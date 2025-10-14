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

import "fmt"

// NewStreamingHasher returns a StreamingHashEngine for the given algorithm.
// Supported: "sha256", "blake2b" (64-byte).
func NewStreamingHasher(algorithm string) (StreamingHashEngine, error) {
	switch algorithm {
	case "sha256":
		return NewSHA256(), nil
	case "blake2b":
		return NewBLAKE2b(), nil
	default:
		return nil, fmt.Errorf("unsupported hashing algorithm %q", algorithm)
	}
}

// NewSimpleFileHasherFactory builds a FileHasherFactory that creates
// *SimpleFileHasher instances configured with the requested algorithm and chunk size.
func NewSimpleFileHasherFactory(algorithm string, chunkSize int) FileHasherFactory {
	return func(path string) (FileHasher, error) {
		h, err := NewStreamingHasher(algorithm)
		if err != nil {
			return nil, err
		}
		sf, err := NewSimpleFileHasher(path, h, chunkSize, "" /* no override */)
		if err != nil {
			return nil, err
		}
		return sf, nil
	}
}


// NewShardedFileHasherFactory builds a ShardHasherFactory that creates
// *ShardedFileHasher instances with the requested algorithm, chunk and shard size.
//
// NOTE: ShardHasherFactory (defined earlier) takes int start/end; we widen to int64 here.
func NewShardedFileHasherFactory(algorithm string, chunkSize int, shardSize int64) ShardHasherFactory {
	return func(path string, start, end int) (FileHasher, error) {
		h, err := NewStreamingHasher(algorithm)
		if err != nil {
			return nil, err
		}
		sh, err := NewShardedFileHasher(path, h, int64(start), int64(end), chunkSize, shardSize, "" /* no override */)
		if err != nil {
			return nil, err
		}
		return sh, nil
	}
}