//
// Copyright 2025 The Sigstore Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package hashing

import (
	"fmt"
	"io"
	"os"
	"strconv"
)

// Generic file hash engine.
// This class is intentionally empty (and abstract, via inheritance) to be used
// only as a type annotation (to signal that API expects a hasher capable of
// hashing files, instead of any `HashEngine` instance).
type FileHasher interface {
	HashEngine
}


// Simple file hash engine that computes the digest iteratively.
// To compute the hash of a file, we read the file exactly once, including for
// very large files that don't fit in memory. Files are read in chunks and each
// chunk is passed to the `update` method of an inner
// `hashing.StreamingHashEngine`, instance. This ensures that the file digest
// will not change even if the chunk size changes. As such, we can dynamically
// determine an optimal value for the chunk argument.

type SimpleFileHasher struct {
	filePath           string
	contentHasher      StreamingHashEngine
	chunkSize          int
	digestNameOverride string
}

func NewSimpleFileHasher(filePath string, contentHasher StreamingHashEngine, chunkSize int, digestNameOverride string) (*SimpleFileHasher, error) {
	if chunkSize < 0 {
		return nil, fmt.Errorf("chunk size must be non-negative, got %d", chunkSize)
	}
	return &SimpleFileHasher{
		filePath:           filePath,
		contentHasher:      contentHasher,
		chunkSize:          chunkSize,
		digestNameOverride: digestNameOverride,
	}, nil
}

func (s *SimpleFileHasher) SetFile(filePath string) {
	// Redefines the file to be hashed in `compute`.
	// SetFile resets the target file that will be hashed by Compute.
	// Args:
	//     file: The new file to be hashed.
	s.filePath = filePath
}

// DigestName mirrors Python's digest_name property with override support.
func (s *SimpleFileHasher) DigestName() string {
	if s.digestNameOverride != "" {
		return s.digestNameOverride
	}
	return s.contentHasher.DigestName()
}

// DigestSize returns the size (in bytes) of the digests produced by the engine.
func (s *SimpleFileHasher) DigestSize() int {
	return s.contentHasher.DigestSize()
}

// Compute streams the file into the inner content hasher and returns the digest.
func (s *SimpleFileHasher) Compute() Digest {
	s.contentHasher.Reset(nil)

	f, err := os.Open(s.filePath)
	if err != nil {
		panic(err)
	}
	defer f.Close()

	if s.chunkSize == 0 {
		data, err := io.ReadAll(f)
		if err != nil {
			panic(err)
		}
		s.contentHasher.Update(data)
	} else {
		buf := make([]byte, s.chunkSize)
		for {
			n, readErr := f.Read(buf)
			if n > 0 {
				s.contentHasher.Update(buf[:n])
			}
			if readErr == io.EOF {
				break
			}
			if readErr != nil {
				panic(readErr)
			}
		}
	}

	contentDigest := s.contentHasher.Compute()
	return Digest{
		Algorithm:   s.DigestName(),
		DigestValue: contentDigest.DigestValue,
	}
}

// ShardedFileHasher hashes a specific [start, end) byte range ("shard") of a file
// by streaming it into an inner StreamingHashEngine.
// File hash engine that hashes a portion (shard) of the file.

// By invoking this engine in parallel across disjoint shards, we can speed up
// hashing a single file. However, the hash output depends on the shard size.

// It is the responsibility of the user to compose the digests of each shard
// into a single digest for the entire file.
type ShardedFileHasher struct {
	filePath           string
	contentHasher      StreamingHashEngine
	start              int64
	end                int64
	chunkSize          int    // bytes; 0 => read the entire shard at once
	shardSize          int64  // must be > 0
	digestNameOverride string // optional
}

func NewShardedFileHasher(
	filePath string,
	contentHasher StreamingHashEngine,
	start, end int64,
	chunkSize int,
	shardSize int64,
	digestNameOverride string,
) (*ShardedFileHasher, error) {
	if shardSize <= 0 {
		return nil, fmt.Errorf("shard size must be strictly positive, got %d", shardSize)
	}
	if chunkSize < 0 {
		return nil, fmt.Errorf("chunk size must be non-negative, got %d", chunkSize)
	}
	h := &ShardedFileHasher{
		filePath:           filePath,
		contentHasher:      contentHasher,
		chunkSize:          chunkSize,
		shardSize:          shardSize,
		digestNameOverride: digestNameOverride,
	}
	if err := h.SetShard(start, end); err != nil {
		return nil, err
	}
	return h, nil
}

// SetFile resets the target file that will be hashed by Compute.
func (s *ShardedFileHasher) SetFile(filePath string) {
	s.filePath = filePath
}

// SetShard redefines the [start, end) byte range to hash.
func (s *ShardedFileHasher) SetShard(start, end int64) error {
	// Redefines the file shard to be hashed in `compute`.

	// Args:
	// 	start: The file offset to start reading from. Must be valid.
	// 	end: The file offset to stop reading at. Must be stricly greater
	// 		than start. The entire shard length must be less than the
	// 		configured `shard_size`.
	if start < 0 {
		return fmt.Errorf("file start offset must be non-negative, got %d", start)
	}
	if end <= start {
		return fmt.Errorf("file end offset must be strictly greater than start, got start=%d, end=%d", start, end)
	}
	readLen := end - start
	if readLen > s.shardSize {
		return fmt.Errorf("must not read more than shard_size=%d, got %d", s.shardSize, readLen)
	}
	s.start = start
	s.end = end
	return nil
}

// DigestName reports the algorithm name, honoring the override.
// Matches Python: "<inner>-sharded-<shardSize>" when not overridden.
func (s *ShardedFileHasher) DigestName() string {
	if s.digestNameOverride != "" {
		return s.digestNameOverride
	}
	return s.contentHasher.DigestName() + "-sharded-" + strconv.FormatInt(s.shardSize, 10)
}

// DigestSize proxies to the inner hasher’s size.
func (s *ShardedFileHasher) DigestSize() int {
	return s.contentHasher.DigestSize()
}

// Compute hashes the specified [start, end) region.
func (s *ShardedFileHasher) Compute() Digest {
	s.contentHasher.Reset(nil)

	f, err := os.Open(s.filePath)
	if err != nil {
		panic(err)
	}
	defer f.Close()

	if _, err := f.Seek(s.start, io.SeekStart); err != nil {
		panic(err)
	}

	toRead := s.end - s.start
	if toRead <= 0 {
		// Guard; should be prevented by SetShard.
		cd := s.contentHasher.Compute()
		return Digest{Algorithm: s.DigestName(), DigestValue: cd.DigestValue}
	}

	if s.chunkSize == 0 || int64(s.chunkSize) >= toRead {
		// Read the whole shard in one shot.
		buf := make([]byte, toRead)
		// Read may return fewer bytes than requested; accept what we get.
		n, readErr := io.ReadFull(f, buf)
		if readErr != nil && readErr != io.ErrUnexpectedEOF {
			if readErr != io.EOF {
				panic(readErr)
			}
		}
		if n > 0 {
			s.contentHasher.Update(buf[:n])
		}
	} else {
		// Stream the shard in chunks.
		buf := make([]byte, s.chunkSize)
		for toRead > 0 {
			want := int64(len(buf))
			if want > toRead {
				want = toRead
			}
			n, readErr := f.Read(buf[:want])
			if n > 0 {
				s.contentHasher.Update(buf[:n])
				toRead -= int64(n)
			}
			if readErr == io.EOF {
				break
			}
			if readErr != nil {
				panic(readErr)
			}
		}
	}

	contentDigest := s.contentHasher.Compute()
	return Digest{
		Algorithm:   s.DigestName(),
		DigestValue: contentDigest.DigestValue,
	}
}

var (
	_ FileHasher = (*SimpleFileHasher)(nil)
	_ HashEngine = (*SimpleFileHasher)(nil)

	_ FileHasher = (*ShardedFileHasher)(nil)
	_ HashEngine = (*ShardedFileHasher)(nil)
)
