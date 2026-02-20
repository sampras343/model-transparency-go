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
	"crypto/rand"
	"fmt"

	"github.com/sigstore/model-signing/pkg/signing"
	protocommon "github.com/sigstore/protobuf-specs/gen/pb-go/common/v1"
	sigstoresign "github.com/sigstore/sigstore-go/pkg/sign"
	"github.com/sigstore/sigstore/pkg/signature"
)

// Ensure Keypair implements sigstore-go's Keypair interface
var _ sigstoresign.Keypair = (*Keypair)(nil)

// Keypair wraps a PKCS#11 crypto.Signer to implement sigstore-go's Keypair interface.
// This adapter allows PKCS#11 keys to be used with sigstore-go's sign.Bundle() API.
type Keypair struct {
	ctx        *Context
	signer     crypto.Signer
	algDetails signature.AlgorithmDetails
	hint       []byte
}

// NewKeypair creates a new PKCS#11 keypair from a PKCS#11 URI.
// It loads the PKCS#11 module, finds the key, and wraps it in a Keypair adapter.
// NOTE: The PKCS#11 context remains open for the lifetime of the Keypair.
// The caller must call Close() when done to release the PKCS#11 session.
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

	// Initialize algorithm details and hint
	algDetails, hint, err := signing.InitializeKeypairData(signer.Public())
	if err != nil {
		ctx.Close()
		return nil, err
	}

	return &Keypair{
		ctx:        ctx,
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
	return signing.KeyTypeToString(pk.algDetails.GetKeyType())
}

// GetPublicKey returns the public key.
func (pk *Keypair) GetPublicKey() crypto.PublicKey {
	return pk.signer.Public()
}

// GetPublicKeyPem returns the public key in PEM format.
func (pk *Keypair) GetPublicKeyPem() (string, error) {
	return signing.GetPublicKeyPEM(pk.signer.Public())
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

// Close closes the underlying PKCS#11 context and releases HSM session resources.
func (pk *Keypair) Close() error {
	if pk.ctx != nil {
		return pk.ctx.Close()
	}
	return nil
}
