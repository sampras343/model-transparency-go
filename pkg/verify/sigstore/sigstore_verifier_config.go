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

package sigstore_verifier

import (
	"encoding/base64"
	"fmt"
	"net/url"

	"github.com/sigstore/model-signing/pkg/interfaces"
	"github.com/sigstore/model-signing/pkg/manifest"
	sign "github.com/sigstore/model-signing/pkg/signature"
	"github.com/sigstore/model-signing/pkg/utils"
	"github.com/sigstore/sigstore-go/pkg/root"
	sigstoreverify "github.com/sigstore/sigstore-go/pkg/verify"
)

// Ensure Verifier implements interfaces.SignatureVerifier at compile time.
var _ interfaces.SignatureVerifier = (*Verifier)(nil)

// SigstoreVerifierConfig holds configuration for creating a Sigstore verifier.
//
//nolint:revive
type SigstoreVerifierConfig struct {
	// Identity is the expected identity that signed the model.
	// This is matched against the certificate's subject.
	Identity string

	// OIDCIssuer is the expected OpenID Connect issuer that provided
	// the certificate used for the signature.
	OIDCIssuer string

	// UseStaging uses staging configurations instead of production.
	// Should only be set to true when testing. Default is false.
	UseStaging bool

	// TrustRootPath is a path to a custom trust root JSON file.
	// When provided, verification uses this instead of the default
	// Sigstore trust root.
	TrustRootPath string
}

// Verifier verifies Sigstore signatures on model manifests.
//
// It checks both the cryptographic signature and an identity policy:
// the certificate must belong to the expected identity and be issued
// by the expected OIDC issuer.
type Verifier struct {
	config   SigstoreVerifierConfig
	verifier *sigstoreverify.Verifier
}

// NewVerifier creates a new Sigstore verifier with the given configuration.
func NewVerifier(config SigstoreVerifierConfig) (*Verifier, error) {
	if config.Identity == "" {
		return nil, fmt.Errorf("identity is required")
	}
	if config.OIDCIssuer == "" {
		return nil, fmt.Errorf("OIDC issuer is required")
	}

	// Validate OIDC issuer is a valid URL
	if _, err := url.ParseRequestURI(config.OIDCIssuer); err != nil {
		return nil, fmt.Errorf("invalid OIDC issuer URL %q: %w", config.OIDCIssuer, err)
	}

	// Create trust root
	var trustRoot *root.TrustedRoot
	var err error

	//nolint:gocritic
	if config.UseStaging {
		// TODO: Use staging TUF options when available
		trustRoot, err = root.FetchTrustedRoot()
		if err != nil {
			return nil, fmt.Errorf("failed to fetch staging trust root: %w", err)
		}
	} else if config.TrustRootPath != "" {
		trustRoot, err = root.NewTrustedRootFromPath(config.TrustRootPath)
		if err != nil {
			return nil, fmt.Errorf("failed to load trust root from file: %w", err)
		}
	} else {
		// Use production trust root
		trustRoot, err = root.FetchTrustedRoot()
		if err != nil {
			return nil, fmt.Errorf("failed to fetch production trust root: %w", err)
		}
	}

	// Create verifier options
	// WithTransparencyLog verifies Rekor transparency log entries including SignedEntryTimestamps
	// WithIntegratedTimestamps uses integrated timestamps from the transparency log
	// Both are needed for proper Sigstore verification with short-lived certificates
	verifierOpts := []sigstoreverify.VerifierOption{
		sigstoreverify.WithTransparencyLog(1),
		sigstoreverify.WithIntegratedTimestamps(1),
	}

	// Create the verifier
	verifier, err := sigstoreverify.NewVerifier(trustRoot, verifierOpts...)
	if err != nil {
		return nil, fmt.Errorf("failed to create verifier: %w", err)
	}

	return &Verifier{
		config:   config,
		verifier: verifier,
	}, nil
}

// Verify verifies the signature and returns the manifest.
//
// This performs cryptographic verification of the signature and checks
// the identity policy before extracting and validating the manifest.
func (v *Verifier) Verify(signature interfaces.Signature) (*manifest.Manifest, error) {
	// Cast to Sigstore signature
	sig, ok := signature.(*sign.Signature)
	if !ok {
		return nil, fmt.Errorf("signature is not a Sigstore signature")
	}

	// Create certificate identity for verification
	// Using NewShortCertificateIdentity for simpler initialization
	certIdentity, err := sigstoreverify.NewShortCertificateIdentity(
		v.config.OIDCIssuer, // issuer
		"",                  // issuer regex (empty = exact match)
		v.config.Identity,   // SAN value
		"",                  // SAN regex (empty = exact match)
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create certificate identity: %w", err)
	}

	// Build policy for identity verification
	policy := sigstoreverify.NewPolicy(
		sigstoreverify.WithoutArtifactUnsafe(),
		sigstoreverify.WithCertificateIdentity(certIdentity),
	)

	// Verify the bundle
	verificationResult, err := v.verifier.Verify(sig.Bundle(), policy)
	if err != nil {
		return nil, fmt.Errorf("signature verification failed: %w", err)
	}

	// Extract DSSE envelope from the bundle
	bundle := sig.Bundle()
	envelope, err := bundle.Envelope()
	if err != nil {
		return nil, fmt.Errorf("failed to extract envelope from bundle: %w", err)
	}

	dsseEnvelope := envelope.RawEnvelope()
	if dsseEnvelope == nil {
		return nil, fmt.Errorf("bundle does not contain a DSSE envelope")
	}

	// Verify payload type
	if dsseEnvelope.PayloadType != utils.InTotoJSONPayloadType {
		return nil, fmt.Errorf("expected DSSE payload %s, but got %s",
			utils.InTotoJSONPayloadType, dsseEnvelope.PayloadType)
	}

	// Decode the base64-encoded payload
	payloadBytes, err := base64.StdEncoding.DecodeString(string(dsseEnvelope.Payload))
	if err != nil {
		return nil, fmt.Errorf("failed to decode DSSE payload: %w", err)
	}

	// Extract manifest from payload
	m, err := utils.VerifySignedContent(dsseEnvelope.PayloadType, payloadBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to extract manifest: %w", err)
	}

	// Note: verificationResult contains verified certificate details and timestamps
	// from Sigstore verification. The result is already validated by the Verify() call above.
	// Future enhancement: could log/return certificate details for audit purposes.
	_ = verificationResult

	return m, nil
}
