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

// Package verify provides high-level model verification orchestration.
package verify

import (
	"context"

	"github.com/sigstore/model-signing/pkg/oci"
	"github.com/sigstore/model-signing/pkg/utils"
)

// Result represents the outcome of a verification operation.
type Result struct {
	Verified bool   // Verified indicates whether the verification succeeded.
	Message  string // Message contains a human-readable description of the result.
}

// ValidateVerifierPaths checks that the common verification paths are valid.
// Call this at the start of each verifier's New* constructor before
// performing type-specific validation.
func ValidateVerifierPaths(modelPath, signaturePath string, ignorePaths []string) error {
	if err := utils.ValidatePathExists("model path", modelPath); err != nil {
		return err
	}
	if err := utils.ValidateFileExists("signature", signaturePath); err != nil {
		return err
	}
	// Validate ignore paths only for non-OCI manifests.
	// For OCI manifests, ignore paths refer to layer entries, not local files.
	if !oci.IsOCIManifest(modelPath) {
		if err := utils.ValidateMultiple("ignore paths", ignorePaths, utils.PathTypeAny); err != nil {
			return err
		}
	}
	return nil
}

// ModelVerifier performs complete model verification.
//
// Orchestrates the full verification workflow:
// 1. Reads and verifies signature bundle cryptographically
// 2. Hashes model files
// 3. Compares actual vs expected manifests
//
// Unlike interfaces.BundleVerifier which only handles cryptographic verification,
// ModelVerifier handles the complete end-to-end verification process.
// Implementations include KeyVerifier, SigstoreVerifier, and CertificateVerifier.
type ModelVerifier interface {
	// Verify executes the complete verification workflow.
	// Returns a Result indicating success or failure, and an error if verification failed.
	Verify(ctx context.Context) (Result, error)
}
