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

package sigstore

import (
	"fmt"
	"net/url"

	"github.com/sigstore/model-signing/pkg/config"
	"github.com/sigstore/model-signing/pkg/dsse"
	"github.com/sigstore/model-signing/pkg/interfaces"
	"github.com/sigstore/model-signing/pkg/manifest"
	sign "github.com/sigstore/model-signing/pkg/signature"
	"github.com/sigstore/model-signing/pkg/utils"
	sigstoreverify "github.com/sigstore/sigstore-go/pkg/verify"
)

// Ensure SigstoreBundleVerifier implements interfaces.BundleVerifier at compile time.
var _ interfaces.BundleVerifier = (*SigstoreBundleVerifier)(nil)

// SigstoreVerifierConfig holds configuration for creating a Sigstore bundle verifier.
//
//nolint:revive
type SigstoreVerifierConfig struct {
	// Embedded trust root configuration for loading Sigstore trust roots
	config.TrustRootConfig

	// Identity is the expected identity that signed the model.
	// This is matched against the certificate's subject.
	Identity string

	// OIDCIssuer is the expected OpenID Connect issuer that provided
	// the certificate used for the signature.
	OIDCIssuer string
}

// SigstoreBundleVerifier verifies Sigstore signature bundles on model manifests.
//
// It checks both the cryptographic signature and an identity policy:
// the certificate must belong to the expected identity and be issued
// by the expected OIDC issuer.
type SigstoreBundleVerifier struct {
	config   SigstoreVerifierConfig
	verifier *sigstoreverify.Verifier
}

// NewSigstoreBundleVerifier creates a new Sigstore bundle verifier with the given configuration.
func NewSigstoreBundleVerifier(config SigstoreVerifierConfig) (*SigstoreBundleVerifier, error) {
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

	// Load trust root using shared configuration primitive
	trustRoot, err := config.LoadTrustRoot()
	if err != nil {
		return nil, err
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

	return &SigstoreBundleVerifier{
		config:   config,
		verifier: verifier,
	}, nil
}

// Verify verifies the signature bundle and returns the manifest.
//
// This performs cryptographic verification of the signature and checks
// the identity policy before extracting and validating the manifest.
func (v *SigstoreBundleVerifier) Verify(bundle interfaces.SignatureBundle) (*manifest.Manifest, error) {
	// Cast to SigstoreBundle
	sig, ok := bundle.(*sign.SigstoreBundle)
	if !ok {
		return nil, fmt.Errorf("bundle is not a SigstoreBundle")
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

	// Extract DSSE envelope from the bundle using common utilities
	dsseEnvelope, err := dsse.ExtractFromBundle(sig.Bundle())
	if err != nil {
		return nil, err
	}

	// Verify payload type
	if err := dsseEnvelope.ValidatePayloadType(utils.InTotoJSONPayloadType); err != nil {
		return nil, err
	}

	// Decode the base64-encoded payload
	payloadBytes, err := dsseEnvelope.DecodePayload()
	if err != nil {
		return nil, err
	}

	// Extract manifest from payload
	m, err := utils.VerifySignedContent(dsseEnvelope.PayloadType(), payloadBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to extract manifest: %w", err)
	}

	// Note: verificationResult contains verified certificate details and timestamps
	// from Sigstore verification. The result is already validated by the Verify() call above.
	// Future enhancement: could log/return certificate details for audit purposes.
	_ = verificationResult

	return m, nil
}
