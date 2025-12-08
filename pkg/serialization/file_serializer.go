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

type FileSerializer struct {
	hasherFactory   fileio.FileHasherFactory
	maxWorkers      int
	allowSymlinks   bool
	baseIgnorePaths []string
	hashType        string
}

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

// SetAllowSymlinks updates whether following symlinks is allowed.
func (s *FileSerializer) SetAllowSymlinks(allow bool) {
	s.allowSymlinks = allow
}

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

// Walks the model path and returns the list of files that should be hashed
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

// Hashes the given file paths using a worker pool limited to max workers
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

// Computes the digest of path and returns the FileManifestItem whose
// name is the path relative to the modelPath
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

// Records ignore paths in the serialization metadata
// base ignore paths are recorded as-is
// per-call ignorePaths are converted to paths relative to modelPath and appended
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


// hasParent reports whether rel starts with "../" (POSIX semantics).
func hasParent(rel string) bool {
	// filepath.Rel uses OS-specific separators, but in practice this
	// check only needs to disqualify paths that start with "../" or its OS-equivalent
	return len(rel) >= 3 && rel[:3] == ".."+string(filepath.Separator)
}

// Obtaining model name from the model path
func deriveModelName(modelPath string) string {
	base := filepath.Base(modelPath)
	if base == "" || base == "." || base == ".." {
		if abs, err := filepath.Abs(modelPath); err == nil {
			base = filepath.Base(abs)
		}
	}
	return base
}