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

package interfaces

import (
	"github.com/sigstore/model-signing/pkg/manifest"
)

// SignatureVerifier verifies a cryptographic signature and extracts the manifest.
//
// This is a low-level interface for signature verification only.
// It does not hash files or compare manifests - it only validates
// the cryptographic signature and extracts the embedded manifest.
//
// Each SignatureVerifier implementation is paired with a corresponding Signer
// to ensure compatible signature formats and key materials.
//
// For complete model verification (signature + hashing + comparison),
// use the higher-level config.Config.Verify() method instead.
type SignatureVerifier interface {
	// Verify checks the signature's authenticity and returns the manifest.
	// Returns an error if verification fails.
	Verify(signature Signature) (*manifest.Manifest, error)
}
