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

package key

import (
	"crypto"
	"fmt"
	"os"

	"github.com/sigstore/model-signing/pkg/config"
	"github.com/sigstore/model-signing/pkg/dsse"
	"github.com/sigstore/model-signing/pkg/interfaces"
	"github.com/sigstore/model-signing/pkg/manifest"
	sign "github.com/sigstore/model-signing/pkg/signature"
	"github.com/sigstore/model-signing/pkg/utils"
)

// Ensure Verifier implements interfaces.SignatureVerifier at compile time.
var _ interfaces.SignatureVerifier = (*Verifier)(nil)

// KeyVerifierConfig holds configuration for creating a public key verifier.
//
//nolint:revive
type KeyVerifierConfig struct {
	// Embedded key configuration for loading public keys
	config.KeyConfig
}

// Verifier verifies signatures created with elliptic curve or RSA private keys.
//
// It checks the cryptographic signature using the provided public key
// and extracts the manifest from the signed payload.
type Verifier struct {
	config    KeyVerifierConfig
	publicKey crypto.PublicKey
	keyHash   string
}

// NewVerifier creates a new public key verifier with the given configuration.
func NewVerifier(cfg KeyVerifierConfig) (*Verifier, error) {
	// Load public key using shared configuration primitive
	publicKey, err := cfg.LoadPublicKey()
	if err != nil {
		return nil, err
	}

	// Compute public key hash using shared utility
	keyHash, err := config.ComputePublicKeyHashFromFile(cfg.Path)
	if err != nil {
		return nil, err
	}

	return &Verifier{
		config:    cfg,
		publicKey: publicKey,
		keyHash:   keyHash,
	}, nil
}

// Verify verifies the signature and returns the manifest.
//
// This performs cryptographic verification of the signature using the public key
// before extracting and validating the manifest.
func (v *Verifier) Verify(signature interfaces.Signature) (*manifest.Manifest, error) {
	// Cast to Sigstore signature (same format used for key-based signatures)
	sig, ok := signature.(*sign.Signature)
	if !ok {
		return nil, fmt.Errorf("signature is not in expected format")
	}

	// Extract DSSE envelope from the bundle using common utilities
	dsseEnvelope, err := dsse.ExtractFromBundle(sig.Bundle())
	if err != nil {
		return nil, err
	}

	// Verify exactly one signature
	// Note: May need to change if we start appending signatures with incremental changes in model
	if err := dsseEnvelope.ValidateSignatureCount(); err != nil {
		return nil, err
	}

	// Check public key hint if present
	bundle := sig.Bundle()
	if bundle.VerificationMaterial != nil &&
		bundle.VerificationMaterial.GetPublicKey() != nil &&
		bundle.VerificationMaterial.GetPublicKey().Hint != "" {
		keyHint := bundle.VerificationMaterial.GetPublicKey().Hint
		if keyHint != v.keyHash {
			// This warning should always be shown as it indicates a potential issue
			fmt.Fprintf(os.Stderr, "WARNING: Key mismatch: The public key hash in the signature's "+
				"verification material (%s) does not match the provided public key (%s). "+
				"Proceeding with verification anyway.\n", keyHint, v.keyHash)
		}
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

	// Compute Pre-Authentication Encoding (PAE) for DSSE using shared utility
	pae := utils.ComputePAE(dsseEnvelope.PayloadType(), payloadBytes)

	// Decode the base64-encoded signature
	signatureBytes, err := dsseEnvelope.DecodeSignature()
	if err != nil {
		return nil, err
	}

	// Verify the signature using the public key with shared utility
	if err := utils.VerifySignature(v.publicKey, pae, signatureBytes); err != nil {
		// Try v0.2.0 compatibility mode
		paeCompat := utils.ComputePAECompat(dsseEnvelope.PayloadType(), payloadBytes)
		if compatErr := utils.VerifySignatureCompat(v.publicKey, paeCompat, signatureBytes); compatErr != nil {
			return nil, fmt.Errorf("signature verification failed: %w", err)
		}
	}

	// Extract manifest from payload
	m, err := utils.VerifySignedContent(dsseEnvelope.PayloadType(), payloadBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to extract manifest: %w", err)
	}

	return m, nil
}
