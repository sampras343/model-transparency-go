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

import (
	"github.com/sigstore/model-signing/pkg/manifest"
)

// BundleVerifier verifies a cryptographic signature bundle and extracts the manifest.
//
// This is a low-level interface for signature bundle verification only.
// It does not hash files or compare manifests - it only validates
// the cryptographic signature and extracts the embedded manifest.
//
// Each BundleVerifier implementation is paired with a corresponding BundleSigner
// to ensure compatible signature formats and key materials.
//
// For complete model verification (signature + hashing + comparison),
// use the higher-level config.Config.Verify() method instead.
type BundleVerifier interface {
	// Verify checks the signature bundle's authenticity and returns the embedded manifest.
	// Returns the manifest if verification succeeds, or an error if verification fails.
	Verify(bundle SignatureBundle) (*manifest.Manifest, error)
}
