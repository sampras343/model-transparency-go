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

// Package memory provides in-memory hash engine implementations.
//
// This package offers a generic hash engine wrapper that works with any hash.Hash
// implementation from Go's standard library or third-party packages. It eliminates
// code duplication between different hash algorithms by providing a single reusable
// implementation that adapts hash.Hash to the HashEngine interface.
package memory

import (
	"hash"

	"github.com/sigstore/model-signing/pkg/hashing/digests"
	hashengines "github.com/sigstore/model-signing/pkg/hashing/engines"
)

// Ensure GenericHashEngine implements StreamingHashEngine at compile time.
var _ hashengines.StreamingHashEngine = (*GenericHashEngine)(nil)

// HashFactoryFunc is a function type that creates new hash.Hash instances.
//
// This allows GenericHashEngine to work with any hash algorithm by accepting
// a factory function that knows how to construct the specific hash implementation.
// Returns an error if the hash instance cannot be created.
type HashFactoryFunc func() (hash.Hash, error)

// GenericHashEngine is a reusable wrapper around any hash.Hash implementation.
//
// This type eliminates code duplication between different hash algorithm
// implementations (SHA256, BLAKE2, etc.) by providing a single generic adapter
// that bridges hash.Hash to the StreamingHashEngine interface.
type GenericHashEngine struct {
	name    string          // Canonical name of the hash algorithm
	size    int             // Size of the digest in bytes
	factory HashFactoryFunc // Factory function to create new hash instances
	h       hash.Hash       // Underlying hash implementation
}

// NewGenericHashEngine creates a new generic hash engine for any hash algorithm.
//
// The name parameter specifies the canonical name of the hash algorithm (e.g., "sha256").
// The size parameter specifies the expected digest size in bytes.
// The factory parameter is a function that creates new hash.Hash instances.
// The initialData parameter contains optional initial bytes to hash immediately.
//
// Returns an error if the factory fails to create the hash instance.
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
		_, _ = engine.h.Write(initialData)
	}

	return engine, nil
}

// Update appends additional bytes to the data being hashed.
// The data parameter contains the bytes to append to the current hash state.
func (e *GenericHashEngine) Update(data []byte) {
	if len(data) > 0 {
		// hash.Hash.Write never returns an error per the interface contract
		_, _ = e.h.Write(data)
	}
}

// Reset clears the hash state and optionally seeds it with new data.
// The data parameter contains the initial bytes for the new hash computation.
func (e *GenericHashEngine) Reset(data []byte) {
	// Recreate hash instance for clean state
	h, _ := e.factory() // Factory should not error after initial validation
	e.h = h

	if len(data) > 0 {
		_, _ = e.h.Write(data)
	}
}

// Compute finalizes the hash computation and returns the resulting digest.
// Returns a Digest containing the algorithm name and computed hash value.
func (e *GenericHashEngine) Compute() (digests.Digest, error) {
	sum := e.h.Sum(nil)
	return digests.NewDigest(e.name, sum), nil
}

// DigestName returns the canonical name of the hash algorithm.
func (e *GenericHashEngine) DigestName() string {
	return e.name
}

// DigestSize returns the size in bytes of digests produced by this engine.
// The returned value matches the size parameter provided to NewGenericHashEngine.
func (e *GenericHashEngine) DigestSize() int {
	return e.size
}
