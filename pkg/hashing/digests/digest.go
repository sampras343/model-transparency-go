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

package digests

import (
	"encoding/hex"
)


// Digest represents a computed digest.
// Digest is designed to be effectively immutable: its fields are
// unexported, and access is via read-only methods. Constructors copy
// the underlying data to avoid external mutation.
type Digest struct {
	algorithm string
	value     []byte
}

// NewDigest constructs a new Digest.
//
// The value slice is defensively copied to preserve immutability
// and avoid surprising data races or external mutations.
func NewDigest(algorithm string, value []byte) Digest {
	valueCopy := make([]byte, len(value))
	copy(valueCopy, value)

	return Digest{
		algorithm: algorithm,
		value:     valueCopy,
	}
}


// Algorithm returns the name of the algorithm used to compute the digest,
// The algorithm used to compute the digest. This could be a
// canonical name (e.g. "sha256" for SHA256) or a name that uniquely
// encodes the algorithm being used for the purposes of this library
// (e.g., "sha256-sharded-1024" for a digest produced by computing SHA256
// hashes of shards of 1024 bytes of the object).  This name can be used
// to autodetect the hashing configuration used during signing so that
// verification can compute a similar digest.
func (d Digest) Algorithm() string {
	return d.algorithm
}

// Value returns the raw digest bytes.
// A copy is returned to avoid callers mutating internal state.
func (d Digest) Value() []byte {
	valueCopy := make([]byte, len(d.value))
	copy(valueCopy, d.value)
	return valueCopy
}

// Hex returns the hexadecimal, human-readable representation of the digest value.
func (d Digest) Hex() string {
	return hex.EncodeToString(d.value)
}

// Size returns the size in bytes of the digest value.
func (d Digest) Size() int {
	return len(d.value)
}
