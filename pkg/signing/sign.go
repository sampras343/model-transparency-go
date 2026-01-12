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

package signing

import "context"

// Result represents the outcome of a signing operation.
type Result struct {
	Verified bool
	Message  string
}

// ModelSigner performs complete model signing.
//
// This is a high-level interface that orchestrates the full signing workflow:
// ModelSigner handles the complete end-to-end signing process.
type ModelSigner interface {
	Sign(ctx context.Context) (Result, error)
}
