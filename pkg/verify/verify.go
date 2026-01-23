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

import "context"

// Result represents the outcome of a verification operation.
type Result struct {
	Verified bool   // Verified indicates whether the verification succeeded.
	Message  string // Message contains a human-readable description of the result.
}

// ModelVerifier performs complete model verification.
//
// Orchestrates the full verification workflow:
// 1. Reads and verifies signature cryptographically
// 2. Hashes model files
// 3. Compares actual vs expected manifests
//
// Unlike interfaces.SignatureVerifier which only handles cryptographic verification,
// ModelVerifier handles the complete end-to-end verification process.
// Implementations include KeyVerifier, SigstoreVerifier, and CertificateVerifier.
type ModelVerifier interface {
	// Verify executes the complete verification workflow.
	// Returns a Result indicating success or failure, and an error if verification failed.
	Verify(ctx context.Context) (Result, error)
}
