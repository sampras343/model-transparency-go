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

package verify

import "context"

// Result represents the outcome of a verification operation.
type Result struct {
	Verified bool
	Message  string
}

// ModelVerifier performs complete model verification.
//
// This is a high-level interface that orchestrates the full verification workflow:
// 1. Read and verify signature
// 2. Hash model files
// 3. Compare manifests
//
// Unlike interfaces.SignatureVerifier which only handles cryptographic verification,
// ModelVerifier handles the complete end-to-end verification process.
type ModelVerifier interface {
	Verify(ctx context.Context) (Result, error)
}
