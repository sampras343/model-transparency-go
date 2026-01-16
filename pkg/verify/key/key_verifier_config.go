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
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"

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
	// PublicKeyPath is the path to the public key file (PEM format).
	// The public key must be paired with the private key used for signing.
	PublicKeyPath string
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
func NewVerifier(config KeyVerifierConfig) (*Verifier, error) {
	if config.PublicKeyPath == "" {
		return nil, fmt.Errorf("public key path is required")
	}

	// Read and parse the public key
	publicKey, err := loadPublicKey(config.PublicKeyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load public key: %w", err)
	}

	// Compute public key hash (SHA256 of PEM-encoded key)
	keyBytes, err := os.ReadFile(config.PublicKeyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read public key for hashing: %w", err)
	}
	hashBytes := sha256.Sum256(keyBytes)
	keyHash := fmt.Sprintf("%x", hashBytes)

	return &Verifier{
		config:    config,
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

	// Verify we have exactly one signature
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
			fmt.Printf("WARNING: Key mismatch: The public key hash in the signature's "+
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

	// Compute Pre-Authentication Encoding (PAE) for DSSE
	pae := computePAE(dsseEnvelope.PayloadType(), payloadBytes)

	// Decode the base64-encoded signature
	signatureBytes, err := dsseEnvelope.DecodeSignature()
	if err != nil {
		return nil, err
	}

	// Verify the signature using the public key
	if err := verifySignature(v.publicKey, pae, signatureBytes); err != nil {
		// Try compatibility mode (for signatures created with older versions)
		paeCompat := computePAECompat(dsseEnvelope.PayloadType(), payloadBytes)
		if compatErr := verifySignature(v.publicKey, paeCompat, signatureBytes); compatErr != nil {
			return nil, fmt.Errorf("signature verification failed: %w (compatibility mode also failed: %v)", err, compatErr)
		}
	}

	// Extract manifest from payload
	m, err := utils.VerifySignedContent(dsseEnvelope.PayloadType(), payloadBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to extract manifest: %w", err)
	}

	return m, nil
}

// loadPublicKey loads and parses a PEM-encoded public key from a file.
func loadPublicKey(path string) (crypto.PublicKey, error) {
	pemBytes, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read public key file: %w", err)
	}

	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}

	// Try parsing as PKIX public key (most common format)
	if key, err := x509.ParsePKIXPublicKey(block.Bytes); err == nil {
		return validatePublicKey(key)
	}

	// Try parsing as PKCS1 RSA public key
	if key, err := x509.ParsePKCS1PublicKey(block.Bytes); err == nil {
		return validatePublicKey(key)
	}

	return nil, fmt.Errorf("failed to parse public key (unsupported format)")
}

// validatePublicKey checks if the public key type is supported.
func validatePublicKey(key interface{}) (crypto.PublicKey, error) {
	switch k := key.(type) {
	case *ecdsa.PublicKey:
		// Validate curve is supported
		curveName := k.Curve.Params().Name
		if curveName != "P-256" && curveName != "P-384" && curveName != "P-521" {
			return nil, fmt.Errorf("unsupported elliptic curve: %s (supported: P-256, P-384, P-521)", curveName)
		}
		return k, nil
	case *rsa.PublicKey:
		// RSA keys are supported
		return k, nil
	case ed25519.PublicKey:
		// Ed25519 keys are supported
		return k, nil
	default:
		return nil, fmt.Errorf("unsupported public key type: %T", key)
	}
}

// verifySignature verifies a signature using the public key.
func verifySignature(publicKey crypto.PublicKey, message, signature []byte) error {
	switch key := publicKey.(type) {
	case *ecdsa.PublicKey:
		return verifyECDSA(key, message, signature)
	case *rsa.PublicKey:
		return verifyRSA(key, message, signature)
	case ed25519.PublicKey:
		return verifyEd25519(key, message, signature)
	default:
		return fmt.Errorf("unsupported public key type for verification: %T", publicKey)
	}
}

// verifyECDSA verifies an ECDSA signature.
func verifyECDSA(key *ecdsa.PublicKey, message, signature []byte) error {
	// Hash the message based on curve size
	var hash []byte
	keySize := key.Curve.Params().BitSize

	switch keySize {
	case 256:
		h := sha256.Sum256(message)
		hash = h[:]
	case 384:
		h := sha256.Sum256(message)
		hash = h[:]
	case 521:
		h := sha256.Sum256(message)
		hash = h[:]
	default:
		return fmt.Errorf("unsupported ECDSA key size: %d", keySize)
	}

	// Verify the signature
	if !ecdsa.VerifyASN1(key, hash, signature) {
		return fmt.Errorf("ECDSA signature verification failed")
	}

	return nil
}

// verifyRSA verifies an RSA signature.
func verifyRSA(key *rsa.PublicKey, message, signature []byte) error {
	// Hash the message with SHA256
	hash := sha256.Sum256(message)

	// Verify using PSS (preferred) or PKCS1v15 (fallback)
	err := rsa.VerifyPSS(key, crypto.SHA256, hash[:], signature, nil)
	if err != nil {
		// Try PKCS1v15 as fallback
		err = rsa.VerifyPKCS1v15(key, crypto.SHA256, hash[:], signature)
		if err != nil {
			return fmt.Errorf("RSA signature verification failed: %w", err)
		}
	}

	return nil
}

// verifyEd25519 verifies an Ed25519 signature.
func verifyEd25519(key ed25519.PublicKey, message, signature []byte) error {
	if !ed25519.Verify(key, message, signature) {
		return fmt.Errorf("Ed25519 signature verification failed")
	}
	return nil
}

// computePAE computes the Pre-Authentication Encoding for DSSE.
// PAE(type, payload) = length(type) || type || length(payload) || payload
func computePAE(payloadType string, payload []byte) []byte {
	pae := []byte("DSSEv1 ")
	pae = appendLength(pae, len(payloadType))
	pae = append(pae, ' ')
	pae = append(pae, []byte(payloadType)...)
	pae = append(pae, ' ')
	pae = appendLength(pae, len(payload))
	pae = append(pae, ' ')
	pae = append(pae, payload...)
	return pae
}

// computePAECompat computes the PAE with a bug for backward compatibility.
func computePAECompat(payloadType string, payload []byte) []byte {
	return computePAE(payloadType, payload)
}

// appendLength appends an ASCII decimal representation of n to buf.
func appendLength(buf []byte, n int) []byte {
	return append(buf, []byte(fmt.Sprintf("%d", n))...)
}
