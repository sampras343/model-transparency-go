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

// Keypair adapter for sigstore-go signing.
//
// This file provides the Keypair type which wraps a PKCS#11-based crypto.Signer
// to satisfy sigstore-go's Keypair interface. This enables PKCS#11 keys from HSMs
// to be used directly with sigstore-go's sign.Bundle() API.
package pkcs11

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"fmt"

	protocommon "github.com/sigstore/protobuf-specs/gen/pb-go/common/v1"
	sigstoresign "github.com/sigstore/sigstore-go/pkg/sign"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
	"github.com/sigstore/sigstore/pkg/signature"
)

// Ensure Keypair implements sigstore-go's Keypair interface
var _ sigstoresign.Keypair = (*Keypair)(nil)

// Keypair wraps a PKCS#11 crypto.Signer to implement sigstore-go's Keypair interface.
// This adapter allows PKCS#11 keys to be used with sigstore-go's sign.Bundle() API.
type Keypair struct {
	signer     crypto.Signer
	algDetails signature.AlgorithmDetails
	hint       []byte
}

// NewKeypair creates a new PKCS#11 keypair from a PKCS#11 URI.
// It loads the PKCS#11 module, finds the key, and wraps it in a Keypair adapter.
func NewKeypair(uri string, modulePaths []string) (*Keypair, error) {
	// Parse PKCS#11 URI
	parsedURI, err := ParsePKCS11URI(uri)
	if err != nil {
		return nil, fmt.Errorf("invalid PKCS#11 URI: %w", err)
	}

	// Load PKCS#11 module and find signer
	ctx, err := LoadContext(parsedURI, modulePaths)
	if err != nil {
		return nil, fmt.Errorf("failed to load PKCS#11 module: %w", err)
	}

	signer, err := ctx.FindSigner(parsedURI)
	if err != nil {
		ctx.Close()
		return nil, fmt.Errorf("failed to find signing key: %w", err)
	}

	// Determine algorithm details from public key
	algDetails, err := getAlgorithmDetails(signer.Public())
	if err != nil {
		ctx.Close()
		return nil, fmt.Errorf("failed to determine algorithm: %w", err)
	}

	// Generate key hint (SHA256 of public key in PEM format, hex encoded)
	// This matches Python model_signing implementation (sign_ec_key.py:136-141)
	pubKeyBytes, err := x509.MarshalPKIXPublicKey(signer.Public())
	if err != nil {
		ctx.Close()
		return nil, fmt.Errorf("failed to marshal public key: %w", err)
	}

	// Convert to PEM format to match Python's encoding
	pemBlock := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubKeyBytes,
	})

	// Compute SHA256 hash and encode as lowercase hex (matching Python)
	hashedBytes := sha256.Sum256(pemBlock)
	hint := []byte(fmt.Sprintf("%x", hashedBytes))

	return &Keypair{
		signer:     signer,
		algDetails: algDetails,
		hint:       hint,
	}, nil
}

// GetHashAlgorithm returns the hash algorithm to compute the digest to sign.
func (pk *Keypair) GetHashAlgorithm() protocommon.HashAlgorithm {
	return pk.algDetails.GetProtoHashType()
}

// GetSigningAlgorithm returns the signing algorithm for this keypair.
func (pk *Keypair) GetSigningAlgorithm() protocommon.PublicKeyDetails {
	return pk.algDetails.GetSignatureAlgorithm()
}

// GetHint returns the hint for the public key (SHA256 hash).
func (pk *Keypair) GetHint() []byte {
	return pk.hint
}

// GetKeyAlgorithm returns the key algorithm as a string.
func (pk *Keypair) GetKeyAlgorithm() string {
	switch pk.algDetails.GetKeyType() {
	case signature.ECDSA:
		return "ECDSA"
	case signature.RSA:
		return "RSA"
	case signature.ED25519:
		return "ED25519"
	default:
		return "UNKNOWN"
	}
}

// GetPublicKey returns the public key.
func (pk *Keypair) GetPublicKey() crypto.PublicKey {
	return pk.signer.Public()
}

// GetPublicKeyPem returns the public key in PEM format.
func (pk *Keypair) GetPublicKeyPem() (string, error) {
	pubKeyBytes, err := cryptoutils.MarshalPublicKeyToPEM(pk.signer.Public())
	if err != nil {
		return "", fmt.Errorf("failed to marshal public key to PEM: %w", err)
	}
	return string(pubKeyBytes), nil
}

// SignData signs the provided data and returns the signature and digest.
// This method computes the digest and signs it using the PKCS#11 key.
func (pk *Keypair) SignData(_ context.Context, data []byte) ([]byte, []byte, error) {
	// Compute digest
	hf := pk.algDetails.GetHashType()
	hasher := hf.New()
	hasher.Write(data)
	digest := hasher.Sum(nil)

	// Sign the digest
	// PKCS#11 uses pre-hashed signatures
	sig, err := pk.signer.Sign(rand.Reader, digest, hf)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to sign with PKCS#11 key: %w", err)
	}

	return sig, digest, nil
}

// Close closes the PKCS#11 context. This should be called when done with the keypair.
func (pk *Keypair) Close() error {
	// The context is managed separately - this is a placeholder for future cleanup
	return nil
}

// getAlgorithmDetails determines the algorithm details from a public key.
func getAlgorithmDetails(pubKey crypto.PublicKey) (signature.AlgorithmDetails, error) {
	switch pk := pubKey.(type) {
	case *ecdsa.PublicKey:
		// Determine the curve and corresponding algorithm
		switch pk.Curve.Params().Name {
		case "P-256":
			return signature.GetAlgorithmDetails(protocommon.PublicKeyDetails_PKIX_ECDSA_P256_SHA_256)
		case "P-384":
			return signature.GetAlgorithmDetails(protocommon.PublicKeyDetails_PKIX_ECDSA_P384_SHA_384)
		case "P-521":
			return signature.GetAlgorithmDetails(protocommon.PublicKeyDetails_PKIX_ECDSA_P521_SHA_512)
		default:
			return signature.AlgorithmDetails{}, fmt.Errorf("unsupported ECDSA curve: %s", pk.Curve.Params().Name)
		}
	case *rsa.PublicKey:
		// Use RSA with SHA256 (most common)
		return signature.GetAlgorithmDetails(protocommon.PublicKeyDetails_PKIX_RSA_PKCS1V15_2048_SHA256)
	default:
		return signature.AlgorithmDetails{}, fmt.Errorf("unsupported public key type: %T", pubKey)
	}
}
