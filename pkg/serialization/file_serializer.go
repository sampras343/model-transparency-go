// Copyright 2025 The Sigstore Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package serialization

import (
	"fmt"
	"io/fs"
	"path/filepath"
	"runtime"
	"sync"

	fileio "github.com/sigstore/model-signing/pkg/hashing/engines/io"
	"github.com/sigstore/model-signing/pkg/manifest"
)

// FileSerializer serializes ML models by hashing individual files.
// It walks the model directory tree and computes a digest for each file,
// producing manifest items at the file level. File hashing is performed
// in parallel using a configurable worker pool.
type FileSerializer struct {
	hasherFactory   fileio.FileHasherFactory
	maxWorkers      int
	allowSymlinks   bool
	baseIgnorePaths []string
	hashType        string
}

// NewFileSerializer creates a new file-level serializer.
//
// Parameters:
//   - hasherFactory: factory function that creates file hashers for computing digests
//   - maxWorkers: maximum number of parallel workers for hashing; if <=0, uses runtime.NumCPU()
//   - allowSymlinks: whether to follow symbolic links during traversal
//   - baseIgnorePaths: paths to always ignore and record in serialization metadata
//
// Returns a configured FileSerializer or an error if the hasherFactory is nil
// or cannot create a mock hasher to determine the hash type.
func NewFileSerializer(
	hasherFactory fileio.FileHasherFactory,
	maxWorkers int,
	allowSymlinks bool,
	baseIgnorePaths []string,
) (*FileSerializer, error) {
	if hasherFactory == nil {
		return nil, fmt.Errorf("hasherFactory must not be nil")
	}

	mockHasher, err := hasherFactory(".")
	if err != nil {
		return nil, fmt.Errorf("create mock file hasher: %w", err)
	}

	hashType := mockHasher.DigestName()
	baseCopy := make([]string, len(baseIgnorePaths))
	copy(baseCopy, baseIgnorePaths)

	return &FileSerializer{
		hasherFactory:   hasherFactory,
		maxWorkers:      maxWorkers,
		allowSymlinks:   allowSymlinks,
		baseIgnorePaths: baseCopy,
		hashType:        hashType,
	}, nil

}

// SetAllowSymlinks updates whether symbolic links are followed during serialization.
//
// When set to true, symlinks are resolved and their targets are processed.
// When false, symlinks cause an error during path validation.
func (s *FileSerializer) SetAllowSymlinks(allow bool) {
	s.allowSymlinks = allow
}

// Serialize walks the model directory and produces a file-level manifest.
//
// It collects all regular files under modelPath (excluding ignored paths),
// computes their digests in parallel, and constructs a manifest with one
// item per file. File paths in the manifest are relative to modelPath.
//
// Parameters:
//   - modelPath: path to the model (file or directory) to serialize
//   - ignorePaths: additional paths to exclude from serialization
//
// Returns the constructed manifest or an error if validation, collection,
// or hashing fails.
func (s *FileSerializer) Serialize(
	modelPath string,
	ignorePaths []string,
) (manifest.Manifest, error) {
	if err := CheckFileOrDirectory(modelPath, s.allowSymlinks); err != nil {
		return manifest.Manifest{}, err
	}

	// Collect all files to hash
	filePaths, err := s.collectFiles(modelPath, ignorePaths)
	if err != nil {
		return manifest.Manifest{}, err
	}

	// Hash files
	items, err := s.hashFiles(modelPath, filePaths)
	if err != nil {
		return manifest.Manifest{}, err
	}

	// Compute ignore paths to record in the serialization metadata
	finalIgnorePaths := s.buildSerializationIgnorePaths(modelPath, ignorePaths)

	serializationType := manifest.NewFileSerialization(
		s.hashType,
		s.allowSymlinks,
		finalIgnorePaths,
	)

	modelName := deriveModelName(modelPath)

	finalManifest := manifest.NewManifest(modelName, items, serializationType)

	return *finalManifest, nil

}

// collectFiles walks the model path and returns the list of files to hash.
//
// It validates each discovered path and filters out ignored paths, collecting
// only regular files for hashing.
//
// Returns the list of file paths or an error if walking or validation fails.
func (s *FileSerializer) collectFiles(
	modelPath string,
	ignorePaths []string,
) ([]string, error) {
	var files []string

	walkFn := func(path string, dir fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		// Check each discovered path and validate every candidate path
		if err := CheckFileOrDirectory(path, s.allowSymlinks); err != nil {
			return err
		}

		if dir.Type().IsRegular() && !ShouldIgnore(path, ignorePaths) {
			files = append(files, path)
		}
		return nil
	}

	if err := filepath.WalkDir(modelPath, walkFn); err != nil {
		return nil, fmt.Errorf("walk model path %q: %w", modelPath, err)
	}
	return files, nil
}

// hashFiles computes digests for the given file paths using a worker pool.
//
// The worker pool is bounded by maxWorkers (or runtime.NumCPU() if maxWorkers <= 0).
// Each worker independently hashes files from the job queue and sends results
// to a results channel.
//
// Returns manifest items for all successfully hashed files, or the first error
// encountered during hashing.
func (s *FileSerializer) hashFiles(
	modelPath string,
	filePaths []string,
) ([]manifest.ManifestItem, error) {
	if len(filePaths) == 0 {
		return nil, nil
	}

	workerCount := s.maxWorkers
	if workerCount <= 0 {
		workerCount = runtime.NumCPU()
	}

	if workerCount > len(filePaths) {
		workerCount = len(filePaths)
	}

	type result struct {
		item manifest.ManifestItem
		err  error
	}

	jobs := make(chan string)
	results := make(chan result, len(filePaths))

	var wg sync.WaitGroup
	wg.Add(workerCount)

	for i := 0; i < workerCount; i++ {
		go func() {
			defer wg.Done()
			for path := range jobs {
				it, err := s.computeHash(modelPath, path)
				results <- result{item: it, err: err}
			}
		}()
	}

	// Feed jobs
	go func() {
		for _, fp := range filePaths {
			jobs <- fp
		}
		close(jobs)
	}()

	// Wait for workers to finish, then close results so range below terminates
	go func() {
		wg.Wait()
		close(results)
	}()

	items := make([]manifest.ManifestItem, 0, len(filePaths))
	var firstErr error

	for res := range results {
		if res.err != nil {
			if firstErr == nil {
				firstErr = res.err
			}
			continue
		}
		items = append(items, res.item)
	}

	if firstErr != nil {
		return nil, firstErr
	}

	return items, nil
}

// computeHash computes the digest of a single file and constructs a manifest item.
//
// The file path in the resulting item is relative to modelPath.
//
// Returns a FileManifestItem containing the relative path and digest, or an error
// if hasher creation, digest computation, or path relativization fails.
func (s *FileSerializer) computeHash(
	modelPath, path string,
) (manifest.ManifestItem, error) {
	hasher, err := s.hasherFactory(path)
	if err != nil {
		return nil, fmt.Errorf("create file hasher for %q: %w", path, err)
	}

	digest, err := hasher.Compute()
	if err != nil {
		return nil, fmt.Errorf("compute digest for %q: %w", path, err)
	}

	rel, err := filepath.Rel(modelPath, path)
	if err != nil {
		return nil, fmt.Errorf("compute relative path for %q: %w", path, err)
	}

	item := manifest.NewFileManifestItem(rel, digest)

	return item, nil
}

// buildSerializationIgnorePaths constructs the final list of ignore paths for metadata.
//
// Base ignore paths are recorded as-is. Per-call ignorePaths are converted to paths
// relative to modelPath and appended if they are valid child paths (not parent or
// outside the model directory).
//
// Returns the combined list of ignore paths to record in serialization metadata.
func (s *FileSerializer) buildSerializationIgnorePaths(
	modelPath string,
	ignorePaths []string,
) []string {
	recorded := make([]string, len(s.baseIgnorePaths))
	copy(recorded, s.baseIgnorePaths)

	for _, p := range ignorePaths {
		if p == "" {
			continue
		}
		rel, err := filepath.Rel(modelPath, p)
		if err != nil {
			continue
		}
		if rel == ".." || rel == "." || rel == "" {
			// "." (the root) or immediate parent are not recorded
			// as child-relative ignore paths.
			continue
		}
		if hasParent(rel) {
			// If rel starts with "../", it's outside modelPath.
			continue
		}
		recorded = append(recorded, rel)
	}
	return recorded
}

// hasParent reports whether rel starts with "../" indicating a parent directory reference.
//
// This check uses OS-specific path separators to identify paths that point outside
// the model directory.
//
// Returns true if rel begins with a parent directory reference, false otherwise.
func hasParent(rel string) bool {
	// filepath.Rel uses OS-specific separators, but in practice this
	// check only needs to disqualify paths that start with "../" or its OS-equivalent
	return len(rel) >= 3 && rel[:3] == ".."+string(filepath.Separator)
}

// deriveModelName extracts the model name from the model path.
//
// It uses the base name of the path. If the base name is ".", "..", or empty,
// it attempts to derive the name from the absolute path.
//
// Returns the derived model name.
func deriveModelName(modelPath string) string {
	base := filepath.Base(modelPath)
	if base == "" || base == "." || base == ".." {
		if abs, err := filepath.Abs(modelPath); err == nil {
			base = filepath.Base(abs)
		}
	}
	return base
}
