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

import "encoding/hex"

type Digest struct {
	// The algorithm used to compute the digest. This could be a
	// canonical name (e.g. "sha256" for SHA256) or a name that uniquely
	// encodes the algorithm being used for the purposes of this library
	// (e.g., "sha256-sharded-1024" for a digest produced by computing SHA256
	// hashes of shards of 1024 bytes of the object).  This name can be used
	// to autodetect the hashing configuration used during signing so that
	// verification can compute a similar digest.
	Algorithm string

	// DigestValue is the raw digest bytes.
	DigestValue []byte
}

// DigestHex returns the hexadecimal, human-readable digest.
func (d Digest) DigestHex() string {
	return hex.EncodeToString(d.DigestValue)
}

// DigestSize returns the size (in bytes) of the digest value.
func (d Digest) DigestSize() int {
	return len(d.DigestValue)
}

type HashEngine interface {
	// Compute finalizes and returns the digest of the data passed to the engine.
	Compute() Digest

	// The canonical name of the algorithm used to compute the hash.
	// Subclasses MUST use the `digest_name()` method to record all parameters
	// that influence the hash output. For example, if a file is split into
	// shards which are hashed separately and the final digest value is
	// computed by aggregating these hashes, then the shard size must be given
	// in the output string.

	// This name gets transferred to the `algorithm` field of the `Digest`
	// computed by the hashing engine.
	DigestName() string

	// The size, in bytes, of the digests produced by the engine.
	// This must return the same value as calling `digest_size` on the `Digest`
    // object produced by the hashing engine.
	DigestSize() int
}

// A protocol to support streaming data to `HashEngine` objects.
type Streaming interface {
	// Appends additional bytes to the data to be hashed.
	// Args:
	//     data: The new data that should be hashed.
	Update(data []byte)
	// Resets the data to be hashed to the passed argument.
	// Args:
	//     data: Optional, initial data to hash.
	Reset(data []byte)
}

// StreamingHashEngine combines HashEngine and Streaming semantics.
// A `HashEngine` that can stream data to be hashed.
type StreamingHashEngine interface {
	HashEngine
	Streaming
}