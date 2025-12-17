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

package memory

import (
	"hash"

	"github.com/sigstore/model-signing/pkg/hashing/digests"
	hashengines "github.com/sigstore/model-signing/pkg/hashing/engines"
	"golang.org/x/crypto/blake2b"
)

func init() {
	// Register BLAKE2b hash engine
	hashengines.MustRegister("blake2b", func() (hashengines.StreamingHashEngine, error) {
		return NewBLAKE2(nil)
	})
}

// Ensure BLAKE2 implements StreamingHashEngine at compile time.
var _ hashengines.StreamingHashEngine = (*BLAKE2)(nil)

// BLAKE2 is a StreamingHashEngine that wraps BLAKE2b.
type BLAKE2 struct {
	h hash.Hash
}

// NewBLAKE2 creates a new BLAKE2b engine.
//
// If initialData is non-nil and non-empty, it is hashed immediately.
func NewBLAKE2(initialData []byte) (*BLAKE2, error) {
	h, err := blake2b.New512(nil) // 512-bit BLAKE2b digest
	if err != nil {
		return nil, err
	}

	b := &BLAKE2{h: h}
	if len(initialData) > 0 {
		_, _ = b.h.Write(initialData)
	}
	return b, nil
}

// Update appends additional bytes to the data to be hashed.
func (b *BLAKE2) Update(data []byte) {
	if len(data) == 0 {
		return
	}
	_, _ = b.h.Write(data)
}

// Reset clears the hash state and optionally seeds it with initial data.
func (b *BLAKE2) Reset(data []byte) {
	h, _ := blake2b.New512(nil) // nil key is valid; error can be ignored safely
	b.h = h
	if len(data) > 0 {
		_, _ = b.h.Write(data)
	}
}

// Compute finalizes the hash and returns a digests.Digest.
func (b *BLAKE2) Compute() (digests.Digest, error) {
	sum := b.h.Sum(nil)
	return digests.NewDigest(b.DigestName(), sum), nil
}

// DigestName returns the canonical name of the algorithm.
func (b *BLAKE2) DigestName() string {
	return "blake2b"
}

// DigestSize returns the size, in bytes, of digests produced by this engine.
func (b *BLAKE2) DigestSize() int {
	return blake2b.Size
}
