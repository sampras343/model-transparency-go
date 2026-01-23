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

// Package hashengines provides interfaces and implementations for cryptographic hashing operations.
//
// The package defines the core HashEngine interface and supporting types for computing
// digests of data. It supports both one-shot hashing and streaming operations where
// data can be fed incrementally.
package hashengines

import (
	"github.com/sigstore/model-signing/pkg/hashing/digests"
)

// HashEngine defines the core interface for computing cryptographic hashes.
//
// Implementations must provide methods to compute digests, report the algorithm name,
// and specify the digest size. The algorithm name must include all parameters that
// affect the hash output (e.g., "sha256-sharded-1024" for sharded hashing).
type HashEngine interface {
	// Compute finalizes the hash computation and returns the resulting digest.
	// Returns an error if the computation fails.
	Compute() (digests.Digest, error)

	// DigestName returns the canonical name of the hash algorithm.
	// Implementations must include all parameters that influence the hash output.
	// For example, if a file is split into shards which are hashed separately
	// and the final digest is computed by aggregating these hashes, the shard
	// size must be included in the output string (e.g., "sha256-sharded-1024").
	// This name is transferred to the algorithm field of the Digest returned by Compute.
	DigestName() string

	// DigestSize returns the size in bytes of digests produced by this engine.
	// The returned value must match the Size() of the Digest returned by Compute.
	DigestSize() int
}

// Streaming defines the interface for incrementally feeding data to a hash engine.
//
// This interface is separate from HashEngine to keep interfaces small and focused,
// allowing implementations that only support one-shot hashing.
type Streaming interface {
	// Update appends additional bytes to the data being hashed.
	// The data parameter contains the bytes to append to the hash state.
	Update(data []byte)

	// Reset clears the hash state and optionally initializes it with new data.
	// The data parameter contains the initial bytes for the new hash computation.
	Reset(data []byte)
}

// StreamingHashEngine combines HashEngine and Streaming for incremental hashing.
//
// This interface composes the smaller HashEngine and Streaming interfaces rather
// than creating a monolithic interface, following the principle of interface
// composition in Go.
type StreamingHashEngine interface {
	HashEngine
	Streaming
}
