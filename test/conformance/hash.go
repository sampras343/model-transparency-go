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

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"github.com/sigstore/model-signing/pkg/config"
	"github.com/sigstore/model-signing/pkg/modelartifact"
	"github.com/sigstore/model-signing/pkg/utils"
)

// hashModel runs canonicalization with optional chunk size and worker count overrides.
//
// chunkSize < 0 and maxWorkers <= 1: delegates to modelartifact.Canonicalize.
// chunkSize >= 0: builds a HashingConfig directly to access SetChunkSize.
// maxWorkers > 1: partitions files across goroutines for parallel hashing.
func hashModel(modelPath, hashAlgorithm string, shardSize int64, chunkSize int, maxWorkers int) int {
	if maxWorkers > 1 {
		return hashModelParallel(modelPath, hashAlgorithm, shardSize, chunkSize, maxWorkers)
	}

	if chunkSize >= 0 {
		hc := buildHashingConfigWithChunk(hashAlgorithm, shardSize, chunkSize, nil)
		_, err := hc.Hash(modelPath, nil)
		if err != nil {
			fmt.Fprintf(os.Stderr, "canonicalize error: %v\n", err)
			return 1
		}
		return 0
	}

	_, err := modelartifact.Canonicalize(modelPath, modelartifact.Options{
		HashAlgorithm: hashAlgorithm,
		ShardSize:     shardSize,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "canonicalize error: %v\n", err)
		return 1
	}
	return 0
}

// hashModelParallel hashes a model directory using multiple goroutines.
//
// The Go library's HashingConfig.Hash() is sequential. This function provides
// adapter-level parallelism by partitioning the file list across workers,
// each calling Hash() with its subset. HashingConfig is read-only during
// hashing so a single instance is shared safely across goroutines.
func hashModelParallel(modelPath, hashAlgorithm string, shardSize int64, chunkSize int, maxWorkers int) int {
	absModelPath, err := filepath.Abs(modelPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "canonicalize error: %v\n", err)
		return 1
	}

	files, err := walkFiles(absModelPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "walk error: %v\n", err)
		return 1
	}

	if len(files) == 0 {
		return 0
	}

	hc := buildHashingConfigWithChunk(hashAlgorithm, shardSize, chunkSize, nil)
	partitions := partitionFiles(files, maxWorkers)

	var wg sync.WaitGroup
	errs := make([]error, len(partitions))

	for i, partition := range partitions {
		wg.Add(1)
		go func(idx int, subset []string) {
			defer wg.Done()
			_, errs[idx] = hc.Hash(absModelPath, subset)
		}(i, partition)
	}
	wg.Wait()

	for _, e := range errs {
		if e != nil {
			fmt.Fprintf(os.Stderr, "canonicalize error: %v\n", e)
			return 1
		}
	}
	return 0
}

// walkFiles collects all regular file paths under a directory.
func walkFiles(root string) ([]string, error) {
	var files []string
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() {
			files = append(files, path)
		}
		return nil
	})
	return files, err
}

// partitionFiles distributes files round-robin across n buckets.
func partitionFiles(files []string, n int) [][]string {
	if n > len(files) {
		n = len(files)
	}
	parts := make([][]string, n)
	for i, f := range files {
		parts[i%n] = append(parts[i%n], f)
	}
	return parts
}

// buildHashingConfigWithChunk creates a HashingConfig with explicit chunk size.
// This bypasses modelartifact.Canonicalize to access config.SetChunkSize,
// which is not exposed through modelartifact.Options.
func buildHashingConfigWithChunk(hashAlgorithm string, shardSize int64, chunkSize int, ignorePaths []string) *config.HashingConfig {
	algo := hashAlgorithm
	if algo == "" {
		algo = utils.DefaultHashAlgorithm
	}

	hc := config.NewHashingConfig()
	if shardSize > 0 {
		hc.UseShardSerialization(algo, shardSize, false, ignorePaths)
	} else {
		hc.UseFileSerialization(algo, false, ignorePaths)
	}
	if chunkSize >= 0 {
		hc.SetChunkSize(chunkSize)
	}
	return hc
}
