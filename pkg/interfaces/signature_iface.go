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

// Package interfaces defines core abstractions for signing and verification operations.
package interfaces

// Signature represents a cryptographic signature over a model.
//
// Implementations wrap different signature formats (e.g., Sigstore bundles).
type Signature interface {
	// Write serializes the signature to the given path.
	// Returns an error if writing fails.
	Write(path string) error
}

// SignatureReader reads signatures from disk.
//
// This is separate from the Signature interface because reading is a factory
// operation (creates new instances), while Write is an instance method.
type SignatureReader interface {
	// Read deserializes a signature from the given path.
	// Returns a concrete implementation of Signature or an error if reading fails.
	Read(path string) (Signature, error)
}
