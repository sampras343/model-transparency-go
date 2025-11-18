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

package hashengines

import (
	"github.com/sigstore/model-signing/pkg/hashing/digests"
)

// HashEngine is the generic interface for hash engines.
type HashEngine interface {
	// Compute computes the digest of the data passed to the engine.
	Compute() (digests.Digest, error)

	// DigestName returns the canonical name of the algorithm used to compute the hash.
	// Implementations MUST include all parameters that influence the hash output
	// For example, if a file is split into
    // shards which are hashed separately and the final digest value is
 	// computed by aggregating these hashes, then the shard size must be given
    //  in the output string.
	// This name gets transferred to the `algorithm` field of the `Digest`
    // computed by the hashing engine.
	DigestName() string

	// DigestSize returns the size in bytes of digests produced by this engine.
	// It must match the Size() of the Digest returned by Compute.
	DigestSize() int
}


// Streaming defines the contract for streaming data into a hashing engine.
//
// This is separate from HashEngine to keep interfaces small and focused.
type Streaming interface {
	// Appends additional bytes to the data to be hashed.
	Update(data []byte)

	// Resets the data to be hashed to the passed argument.
	Reset(data []byte)
}

// StreamingHashEngine is a HashEngine that also supports streaming updates.
// A `HashEngine` that can stream data to be hashed.
// This composes the smaller interfaces rather than creating a monolithic one,
type StreamingHashEngine interface {
	HashEngine
	Streaming
}