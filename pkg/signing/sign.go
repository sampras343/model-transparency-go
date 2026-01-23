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

// Package signing provides high-level model signing orchestration.
package signing

import "context"

// Result represents the outcome of a signing operation.
type Result struct {
	Verified bool   // Verified indicates whether the signing operation succeeded.
	Message  string // Message contains a human-readable description of the result.
}

// ModelSigner performs complete model signing.
//
// Orchestrates the full signing workflow including model hashing, manifest creation,
// payload construction, cryptographic signing, and signature file writing.
// Implementations include KeySigner (local key-based) and SigstoreSigner (Sigstore/Fulcio-based).
type ModelSigner interface {
	// Sign executes the complete signing workflow.
	// Returns a Result indicating success or failure, and an error if the operation failed.
	Sign(ctx context.Context) (Result, error)
}
