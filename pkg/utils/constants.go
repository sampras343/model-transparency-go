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

package utils

const (
	// InTotoJSONPayloadType is the MIME type for in-toto JSON payloads in DSSE.
	InTotoJSONPayloadType = "application/vnd.in-toto+json"

	// InTotoStatementType is the statement type URI for in-toto v1 statements.
	InTotoStatementType = "https://in-toto.io/Statement/v1"

	// PredicateType is the predicate type URI for model signing v1.0 format.
	PredicateType = "https://model_signing/signature/v1.0"

	// PredicateTypeCompat is the predicate type URI for model signing v0.1 format (deprecated).
	PredicateTypeCompat = "https://model_signing/Digests/v0.1"

	// IssuerProdURL is the OAuth2 issuer URL for Sigstore production environment.
	IssuerProdURL = "https://oauth2.sigstore.dev/auth"

	// IssuerStagingURL is the OAuth2 issuer URL for Sigstore staging environment.
	IssuerStagingURL = "https://oauth2.sigstage.dev/auth"

	// FulcioProdURL is the Fulcio certificate authority URL for production environment.
	FulcioProdURL = "https://fulcio.sigstore.dev"

	// FulcioStagingURL is the Fulcio certificate authority URL for staging environment.
	FulcioStagingURL = "https://fulcio.sigstage.dev"

	// RekorProdURL is the Rekor transparency log URL for production environment.
	RekorProdURL = "https://rekor.sigstore.dev"

	// RekorStagingURL is the Rekor transparency log URL for staging environment.
	RekorStagingURL = "https://rekor.sigstage.dev"

	// DefaultClientID is the default OAuth2 client ID for Sigstore authentication.
	DefaultClientID = "sigstore"
)
