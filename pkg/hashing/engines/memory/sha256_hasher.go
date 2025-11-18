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
	"crypto/sha256"
	"hash"

	"github.com/sigstore/model-signing/pkg/hashing/digests"
	hashengines "github.com/sigstore/model-signing/pkg/hashing/engines"
)

var _ hashengines.StreamingHashEngine = (*SHA256Engine)(nil)

// SHA256Engine is a StreamingHashEngine that wraps crypto/sha256.
//
// It supports optional initial data and full streaming updates.
type SHA256Engine struct {
	h hash.Hash
}

// NewSHA256Engine constructs a new SHA256 engine.
// If initialData is non-nil, it will be written into the hash immediately.
func NewSHA256Engine(initialData []byte) *SHA256Engine {
	e := &SHA256Engine{h: sha256.New()}
	if len(initialData) > 0 {
		_, _ = e.h.Write(initialData)
	}
	return e
}

// Update appends more bytes into the hash state.
func (e *SHA256Engine) Update(data []byte) {
	if len(data) > 0 {
		_, _ = e.h.Write(data)
	}
}

// Reset clears the hash state and optionally seeds it with new data.
func (e *SHA256Engine) Reset(data []byte) {
	e.h = sha256.New()
	if len(data) > 0 {
		_, _ = e.h.Write(data)
	}
}

// Compute finalizes the hash and returns a Digest value.
func (e *SHA256Engine) Compute() (digests.Digest, error) {
	sum := e.h.Sum(nil)
	return digests.NewDigest(e.DigestName(), sum), nil
}

// DigestName returns the algorithm identifier.
func (e *SHA256Engine) DigestName() string {
	return "sha256"
}

// DigestSize returns the byte length of the produced digest.
func (e *SHA256Engine) DigestSize() int {
	return sha256.Size
}
