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

// Sharded File Serializer produces a manifest recording every file shard.
// It traverses model directory, splits each file into fixed-size shards and
// computes digests for each shard in parallel.
type ShardedFileSerializer struct {
	hasherFactory   fileio.ShardedFileHasherFactory
	maxWorkers      int
	allowSymlinks   bool
	baseIgnorePaths []string
	shardSize       int64
	hashType        string
}

// NewShardedFileSerializer initializes a serializer that works at shard level.
//
// hasherFactory: builds the hash engine used to hash each file shard
// maxWorkers: maximum number of workers to use in parallel. If <=0 then runtime.NumCPU() is used
// baseIgnorePaths: paths to ignpre, stored in the serialization metadata
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

	shardSize := mock.GetShardSize() //CHECK
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

// SetAllowSymlinks updates whether following symlinks is allowed.
func (s *ShardedFileSerializer) SetAllowSymlinks(allow bool) {
	s.allowSymlinks = allow
}

// Serialize implements serialization.Serializer
// It walks modelPath, generates shard descriptors for each file,
// hashes them and returns a manifest where each item corresponds to a file shard
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

// collectShards walks modelPath and computes shard descriptors for each file
// that is not ignored.
func (s *ShardedFileSerializer) collectShards(
	modelPath string,
	ignorePaths []string,
) ([]shardDescriptor, error) {
	var shards []shardDescriptor

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

// hashShards hashes all shard descriptors using a worker pool bounded by
// maxWorkers or runtime.NumCPU()
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

// The last value is always exactly end, even if end is not a multiple of step.
// There is always at least one value if step > 0 and end > 0.
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

// For call specific ignore paths, covert each to a path relative to modelPath
// If relative path does not start with "../", record it
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
