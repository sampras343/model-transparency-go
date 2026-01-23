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
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"

	fileio "github.com/sigstore/model-signing/pkg/hashing/engines/io"
	"github.com/sigstore/model-signing/pkg/manifest"
)

// ShardedFileSerializer serializes ML models at the shard level.
//
// It traverses the model directory, splits each file into fixed-size shards,
// and computes digests for each shard in parallel. The resulting manifest
// contains one item per shard rather than per file, enabling efficient
// handling of large model files.
type ShardedFileSerializer struct {
	hasherFactory   fileio.ShardedFileHasherFactory
	maxWorkers      int
	allowSymlinks   bool
	baseIgnorePaths []string
	shardSize       int64
	hashType        string
}

// NewShardedFileSerializer creates a new shard-level serializer.
//
// Parameters:
//   - hasherFactory: factory function that creates sharded file hashers for computing shard digests
//   - maxWorkers: maximum number of parallel workers for hashing; if <=0, uses runtime.NumCPU()
//   - allowSymlinks: whether to follow symbolic links during traversal
//   - baseIgnorePaths: paths to always ignore and record in serialization metadata
//
// Returns a configured ShardedFileSerializer or an error if the hasherFactory is nil,
// does not return a proper ShardedFileHasher type, or if the shard size is invalid.
func NewShardedFileSerializer(
	hasherFactory fileio.ShardedFileHasherFactory,
	maxWorkers int,
	allowSymlinks bool,
	baseIgnorePaths []string,
) (*ShardedFileSerializer, error) {
	if hasherFactory == nil {
		return nil, fmt.Errorf("hasherFactory must not be nil")
	}

	// Precompute shard size amd inner hash type using a mock hasher

	mockHasher, err := hasherFactory("", 0, 1)
	if err != nil {
		return nil, fmt.Errorf("create mock sharded file hasher: %w", err)
	}

	mock, ok := mockHasher.(*fileio.ShardedFileHasher)
	if !ok {
		return nil, fmt.Errorf("sharded hasher factory must return *io.ShardedFileHasher, got %T", mockHasher)
	}

	shardSize := mock.GetShardSize()
	if shardSize <= 0 {
		return nil, fmt.Errorf("invalid shard size %d from mock hasher", shardSize)
	}

	hashType := mockHasher.DigestName()
	baseCopy := make([]string, len(baseIgnorePaths))
	copy(baseCopy, baseIgnorePaths)
	return &ShardedFileSerializer{
		hasherFactory:   hasherFactory,
		maxWorkers:      maxWorkers,
		allowSymlinks:   allowSymlinks,
		baseIgnorePaths: baseCopy,
		shardSize:       shardSize,
		hashType:        hashType,
	}, nil
}

// SetAllowSymlinks updates whether symbolic links are followed during serialization.
//
// When set to true, symlinks are resolved and their targets are processed.
// When false, symlinks cause an error during path validation.
func (s *ShardedFileSerializer) SetAllowSymlinks(allow bool) {
	s.allowSymlinks = allow
}

// Serialize walks the model directory and produces a shard-level manifest.
//
// It generates shard descriptors for each file (splitting files into fixed-size chunks),
// computes their digests in parallel, and constructs a manifest with one item per shard.
// This approach is particularly efficient for large model files.
//
// Parameters:
//   - modelPath: path to the model (file or directory) to serialize
//   - ignorePaths: additional paths to exclude from serialization
//
// Returns the constructed manifest or an error if validation, collection,
// or hashing fails.
func (s *ShardedFileSerializer) Serialize(
	modelPath string,
	ignorePaths []string,
) (manifest.Manifest, error) {
	if err := CheckFileOrDirectory(modelPath, s.allowSymlinks); err != nil {
		return manifest.Manifest{}, err
	}

	// Discover all shards to hash
	shards, err := s.collectShards(modelPath, ignorePaths)
	if err != nil {
		return manifest.Manifest{}, err
	}

	// Hash shards
	items, err := s.hashShards(modelPath, shards)
	if err != nil {
		return manifest.Manifest{}, err
	}

	// Recreate serialization description for new ignorePaths
	finalIgnorePaths := s.buildSerializationIgnorePaths(modelPath, ignorePaths)

	serializationType := manifest.NewShardSerialization(
		s.hashType,
		s.shardSize,
		s.allowSymlinks,
		finalIgnorePaths,
	)

	modelName := deriveModelName(modelPath)

	m := manifest.NewManifest(modelName, items, serializationType)
	return *m, nil
}

// shardDescriptor describes a single file shard [start, end) for hashing.
type shardDescriptor struct {
	path       string
	start, end int64
}

// collectShards walks modelPath and generates shard descriptors for each file.
//
// For each regular file that is not ignored, it determines the file size and
// splits it into fixed-size shards, creating a descriptor for each shard with
// its start and end byte offsets.
//
// Returns the list of shard descriptors or an error if walking or validation fails.
func (s *ShardedFileSerializer) collectShards(
	modelPath string,
	ignorePaths []string,
) ([]shardDescriptor, error) {
	var shards []shardDescriptor

	//nolint:revive
	walkFn := func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		// Validate according to symlink rules
		if err := CheckFileOrDirectory(path, s.allowSymlinks); err != nil {
			return err
		}

		info, err := os.Stat(path)
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() {
			return nil
		}
		if ShouldIgnore(path, ignorePaths) {
			return nil
		}
		size := info.Size()
		if size <= 0 {
			return nil
		}
		ends := endpoints(s.shardSize, size)
		if len(ends) == 0 {
			return nil
		}

		start := int64(0)
		for _, end := range ends {
			shards = append(shards, shardDescriptor{
				path:  path,
				start: start,
				end:   end,
			})
			start = end
		}
		return nil
	}

	if err := filepath.WalkDir(modelPath, walkFn); err != nil {
		return nil, fmt.Errorf("walk model path %q: %w", modelPath, err)
	}
	return shards, nil
}

// hashShards computes digests for all shard descriptors using a worker pool.
//
// The worker pool is bounded by maxWorkers (or runtime.NumCPU() if maxWorkers <= 0).
// Each worker independently hashes shards from the job queue and sends results
// to a results channel.
//
// Returns manifest items for all successfully hashed shards, or the first error
// encountered during hashing.
func (s *ShardedFileSerializer) hashShards(
	modelPath string,
	shards []shardDescriptor,
) ([]manifest.ManifestItem, error) {
	if len(shards) == 0 {
		return nil, nil
	}
	workerCount := s.maxWorkers
	if workerCount <= 0 {
		workerCount = runtime.NumCPU()
	}
	if workerCount > len(shards) {
		workerCount = len(shards)
	}

	type result struct {
		item manifest.ManifestItem
		err  error
	}

	jobs := make(chan shardDescriptor)
	results := make(chan result, len(shards))

	var wg sync.WaitGroup
	wg.Add(workerCount)

	for i := 0; i < workerCount; i++ {
		go func() {
			defer wg.Done()
			for shard := range jobs {
				it, err := s.computeShard(modelPath, shard.path, shard.start, shard.end)
				results <- result{item: it, err: err}
			}
		}()
	}

	// Feed Jobs
	go func() {
		for _, sh := range shards {
			jobs <- sh
		}
		close(jobs)
	}()

	// Close results after workers finish
	go func() {
		wg.Wait()
		close(results)
	}()

	items := make([]manifest.ManifestItem, 0, len(shards))
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

// computeShard computes the digest of a single file shard and constructs a manifest item.
//
// The file path in the resulting item is relative to modelPath, and the item includes
// the shard's start and end byte offsets within the file.
//
// Parameters:
//   - modelPath: root path of the model for computing relative paths
//   - path: absolute path to the file containing this shard
//   - start: starting byte offset of the shard (inclusive)
//   - end: ending byte offset of the shard (exclusive)
//
// Returns a ShardedFileManifestItem or an error if hasher creation, digest
// computation, or path relativization fails.
func (s *ShardedFileSerializer) computeShard(
	modelPath, path string,
	start, end int64,
) (manifest.ManifestItem, error) {
	hasher, err := s.hasherFactory(path, start, end)
	if err != nil {
		return nil, fmt.Errorf("create sharded file hasher for %q [%d,%d): %w", path, start, end, err)
	}

	digest, err := hasher.Compute()
	if err != nil {
		return nil, fmt.Errorf("compute shard digest for %q [%d,%d): %w", path, start, end, err)
	}

	rel, err := filepath.Rel(modelPath, path)
	if err != nil {
		return nil, fmt.Errorf("compute relative path for %q from %q: %w", path, modelPath, err)
	}

	item := manifest.NewShardedFileManifestItem(rel, start, end, digest)
	return item, nil
}

// endpoints generates shard boundary positions from 0 to end at intervals of step.
//
// The last value is always exactly end, even if end is not a multiple of step.
// This ensures the final shard covers any remaining bytes.
//
// Parameters:
//   - step: size of each shard in bytes
//   - end: total file size in bytes
//
// Returns a slice of endpoint positions, or nil if step or end is non-positive.
// There is always at least one value if both parameters are positive.
func endpoints(step, end int64) []int64 {
	if step <= 0 || end <= 0 {
		return nil
	}
	out := make([]int64, 0, end/step+1)
	for v := step; v < end; v += step {
		out = append(out, v)
	}
	out = append(out, end)
	return out
}

// buildSerializationIgnorePaths constructs the final list of ignore paths for metadata.
//
// Base ignore paths are recorded as-is. Per-call ignorePaths are converted to paths
// relative to modelPath and appended if they are valid child paths (not parent or
// outside the model directory).
//
// Returns the combined list of ignore paths to record in serialization metadata.
func (s *ShardedFileSerializer) buildSerializationIgnorePaths(
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
		if rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			continue
		}
		recorded = append(recorded, rel)
	}
	return recorded
}
