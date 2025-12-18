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
)

// Ensure GenericHashEngine implements StreamingHashEngine at compile time.
var _ hashengines.StreamingHashEngine = (*GenericHashEngine)(nil)

// HashFactoryFunc is a function that creates a new hash.Hash instance.
type HashFactoryFunc func() (hash.Hash, error)

// GenericHashEngine is a reusable wrapper around any hash.Hash implementation.
//
// This eliminates code duplication between different hash algorithm implementations
// (SHA256, BLAKE2, etc.) by providing a single generic wrapper.
type GenericHashEngine struct {
	name    string
	size    int
	factory HashFactoryFunc
	h       hash.Hash
}

// NewGenericHashEngine creates a new generic hash engine.
//
// Parameters:
//   - name: The canonical name of the hash algorithm (e.g., "sha256", "blake2b")
//   - size: The size of the digest in bytes
//   - factory: A function that creates new hash.Hash instances
//   - initialData: Optional initial data to hash immediately
func NewGenericHashEngine(name string, size int, factory HashFactoryFunc, initialData []byte) (*GenericHashEngine, error) {
	h, err := factory()
	if err != nil {
		return nil, err
	}

	engine := &GenericHashEngine{
		name:    name,
		size:    size,
		factory: factory,
		h:       h,
	}

	if len(initialData) > 0 {
		// hash.Hash.Write never returns an error per the interface contract,
		// but we call it anyway to satisfy the signature
		_, _ = engine.h.Write(initialData)
	}

	return engine, nil
}

// Update appends additional bytes to the data to be hashed.
func (e *GenericHashEngine) Update(data []byte) {
	if len(data) > 0 {
		// hash.Hash.Write never returns an error per the interface contract
		_, _ = e.h.Write(data)
	}
}

// Reset clears the hash state and optionally seeds it with initial data.
func (e *GenericHashEngine) Reset(data []byte) {
	// Recreate hash instance for clean state
	h, _ := e.factory() // Factory should not error after initial validation
	e.h = h

	if len(data) > 0 {
		_, _ = e.h.Write(data)
	}
}

// Compute finalizes the hash and returns a digests.Digest.
func (e *GenericHashEngine) Compute() (digests.Digest, error) {
	sum := e.h.Sum(nil)
	return digests.NewDigest(e.name, sum), nil
}

// DigestName returns the canonical name of the hash algorithm.
func (e *GenericHashEngine) DigestName() string {
	return e.name
}

// DigestSize returns the size, in bytes, of digests produced by this engine.
func (e *GenericHashEngine) DigestSize() int {
	return e.size
}
