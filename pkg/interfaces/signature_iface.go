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

// SignatureBundle represents a cryptographic signature bundle over a model.
//
// A signature bundle contains the cryptographic signature along with
// verification material (public keys, certificates, transparency log entries)
// in a DSSE envelope wrapped in a Sigstore bundle format.
//
// Implementations wrap different bundle formats (e.g., Sigstore bundles, certificate bundles).
type SignatureBundle interface {
	// Write serializes the signature bundle to the given path.
	// Returns an error if writing fails.
	Write(path string) error
}

// BundleReader reads signature bundles from disk.
//
// This is separate from the SignatureBundle interface because reading is a factory
// operation (creates new instances), while Write is an instance method.
type BundleReader interface {
	// Read deserializes a signature bundle from the given path.
	// Returns a concrete implementation of SignatureBundle or an error if reading fails.
	Read(path string) (SignatureBundle, error)
}
