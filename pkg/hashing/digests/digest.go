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

// Package digests provides types for representing cryptographic hash digests.
//
// A Digest encapsulates both the algorithm name and the computed hash value,
// providing immutability guarantees through defensive copying and unexported fields.
package digests

import (
	"encoding/hex"
	"fmt"
)

// Digest represents a computed cryptographic hash digest.
//
// Digest is designed to be effectively immutable: its fields are unexported,
// and access is provided via read-only methods. Constructors and accessors
// defensively copy the underlying data to prevent external mutation.
type Digest struct {
	algorithm string // Name of the hash algorithm used
	value     []byte // Raw digest bytes
}

// NewDigest creates a new Digest with the specified algorithm and hash value.
//
// The algorithm parameter specifies the name of the hash algorithm used.
// The value parameter contains the raw digest bytes.
// The value slice is defensively copied to preserve immutability and prevent
// external mutations or data races.
//
// Returns a new Digest instance.
func NewDigest(algorithm string, value []byte) Digest {
	valueCopy := make([]byte, len(value))
	copy(valueCopy, value)

	return Digest{
		algorithm: algorithm,
		value:     valueCopy,
	}
}

// Algorithm returns the name of the hash algorithm used to compute this digest.
//
// The returned name may be a canonical algorithm name (e.g., "sha256") or a name
// that encodes additional parameters (e.g., "sha256-sharded-1024" for SHA-256
// computed on 1024-byte shards). This name can be used to auto-detect the hashing
// configuration during verification to ensure compatible digest computation.
//
// Returns the algorithm name as a string.
func (d Digest) Algorithm() string {
	return d.algorithm
}

// Value returns a copy of the raw digest bytes.
//
// A defensive copy is returned to prevent callers from mutating the internal state,
// preserving the immutability guarantee of Digest.
//
// Returns a byte slice containing the digest value.
func (d Digest) Value() []byte {
	valueCopy := make([]byte, len(d.value))
	copy(valueCopy, d.value)
	return valueCopy
}

// Hex returns the hexadecimal string representation of the digest value.
//
// Returns a lowercase hexadecimal string encoding of the digest bytes.
func (d Digest) Hex() string {
	return hex.EncodeToString(d.value)
}

// Size returns the length in bytes of the digest value.
//
// Returns the size of the digest as an integer.
func (d Digest) Size() int {
	return len(d.value)
}

// String returns a human-readable string representation of the digest.
//
// The format is "algorithm:hexvalue" (e.g., "sha256:abc123...").
//
// Returns a formatted string combining the algorithm name and hex-encoded value.
func (d Digest) String() string {
	return fmt.Sprintf("%s:%s", d.algorithm, d.Hex())
}

// Equal compares this digest with another for equality.
//
// The other parameter is the digest to compare against.
// Two digests are equal if and only if they have the same algorithm name
// and identical digest values.
//
// Returns true if the digests are equal, false otherwise.
func (d Digest) Equal(other Digest) bool {
	if d.algorithm != other.algorithm {
		return false
	}

	if len(d.value) != len(other.value) {
		return false
	}

	for i := range d.value {
		if d.value[i] != other.value[i] {
			return false
		}
	}

	return true
}
