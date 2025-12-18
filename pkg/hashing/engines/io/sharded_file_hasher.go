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

package io

import (
	"fmt"
	"io"
	"os"

	"github.com/sigstore/model-signing/pkg/hashing/digests"
	hashengines "github.com/sigstore/model-signing/pkg/hashing/engines"
)

// ShardedFileHasher hashes only a portion (shard) of a file.
//
// It reuses the streaming logic from SimpleFileHasher, but restricts
// reading to a [start, end) interval. This is useful for parallelizing
// hashing of large files into multiple independent shards.
type ShardedFileHasher struct {
	*SimpleFileHasher

	start     int64
	end       int64
	shardSize int64
}

// NewShardedFileHasher constructs a ShardedFileHasher.
//
//   - filePath: file to hash
//   - contentHasher: StreamingHashEngine used for hashing shard contents
//   - start, end: byte offsets [start, end) defining the shard
//   - chunkSize: size of read buffer; 0 = read all in one go
//   - shardSize: configured size of a shard; shard length must be <= shardSize
//   - digestNameOverride: if non-empty, overrides the generated sharded name
func NewShardedFileHasher(
	filePath string,
	contentHasher hashengines.StreamingHashEngine,
	start, end int64,
	chunkSize int,
	shardSize int64,
	digestNameOverride string,
) (*ShardedFileHasher, error) {
	if shardSize <= 0 {
		return nil, fmt.Errorf("shard size must be strictly positive, got %d", shardSize)
	}

	base, err := NewSimpleFileHasher(filePath, contentHasher, chunkSize, digestNameOverride)
	if err != nil {
		return nil, err
	}

	h := &ShardedFileHasher{
		SimpleFileHasher: base,
		shardSize:        shardSize,
	}

	if err := h.SetShard(start, end); err != nil {
		return nil, err
	}

	return h, nil
}

// SetShard redefines the file shard [start, end) that will be hashed.
func (h *ShardedFileHasher) SetShard(start, end int64) error {
	if start < 0 {
		return fmt.Errorf("file start offset must be non-negative, got %d", start)
	}
	if end <= start {
		return fmt.Errorf("file end offset must be strictly greater than start, got start=%d, end=%d", start, end)
	}

	readLength := end - start
	if readLength > h.shardSize {
		return fmt.Errorf(
			"must not read more than shardSize=%d, got %d",
			h.shardSize, readLength,
		)
	}

	h.start = start
	h.end = end
	return nil
}

func (h *ShardedFileHasher) GetShardSize() int64 {
	return h.shardSize
}

// DigestName returns either the override or "<inner>-sharded-<shardSize>".
func (h *ShardedFileHasher) DigestName() string {
	if h.digestNameOverride != "" {
		return h.digestNameOverride
	}
	return fmt.Sprintf("%s-sharded-%d", h.contentHasher.DigestName(), h.shardSize)
}

// Compute hashes only the configured shard [start, end) of the file.
//
// It uses io.NewSectionReader to safely limit reading to the shard
// region and otherwise mirrors the chunked streaming logic.
func (h *ShardedFileHasher) Compute() (digests.Digest, error) {
	h.contentHasher.Reset(nil)

	f, err := os.Open(h.filePath)
	if err != nil {
		return digests.Digest{}, fmt.Errorf("open file %q: %w", h.filePath, err)
	}
	//nolint:errcheck
	defer f.Close()
	length := h.end - h.start
	section := io.NewSectionReader(f, h.start, length)

	if h.chunkSize == 0 || int64(h.chunkSize) >= length {
		data, err := io.ReadAll(section)
		if err != nil {
			return digests.Digest{}, fmt.Errorf("read shard: %w", err)
		}
		h.contentHasher.Update(data)
	} else {
		buf := make([]byte, h.chunkSize)
		for {
			n, err := section.Read(buf)
			if n > 0 {
				h.contentHasher.Update(buf[:n])
			}
			if err != nil {
				if err == io.EOF {
					break
				}
				return digests.Digest{}, fmt.Errorf("read shard: %w", err)
			}
		}
	}

	d, err := h.contentHasher.Compute()
	if err != nil {
		return digests.Digest{}, fmt.Errorf("compute shard digest: %w", err)
	}

	return digests.NewDigest(h.DigestName(), d.Value()), nil
}
