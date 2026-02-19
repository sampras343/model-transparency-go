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
	"context"
	"crypto"
	"crypto/rand"

	"github.com/sigstore/model-signing/pkg/signing"
	protocommon "github.com/sigstore/protobuf-specs/gen/pb-go/common/v1"
	sigstoresig "github.com/sigstore/sigstore/pkg/signature"
)

// ModelKeypair implements sigstore-go's sign.Keypair interface by wrapping
// a user-provided private key loaded from a PEM file. This enables key-based
// signing through sigstore-go's sign.Bundle() API.
type ModelKeypair struct {
	privateKey crypto.Signer
	publicKey  crypto.PublicKey
	hint       []byte
	algDetails sigstoresig.AlgorithmDetails
}

// NewModelKeypair loads a private key from a PEM file and returns a Keypair
// that can be passed to sigstore-go's sign.Bundle().
//
// Supports ECDSA (P-256, P-384), RSA, and Ed25519 keys.
// If password is non-empty, the key is assumed to be encrypted.
func NewModelKeypair(keyPath string, password string) (*ModelKeypair, error) {
	// Load private key from PEM file
	signer, err := signing.LoadPrivateKeyFromPEM(keyPath, password)
	if err != nil {
		return nil, err
	}

	pubKey := signer.Public()

	// Initialize algorithm details and hint
	algDetails, hint, err := signing.InitializeKeypairData(pubKey)
	if err != nil {
		return nil, err
	}

	return &ModelKeypair{
		privateKey: signer,
		publicKey:  pubKey,
		hint:       hint,
		algDetails: algDetails,
	}, nil
}

// GetHashAlgorithm returns the hash algorithm to compute the digest to sign.
func (k *ModelKeypair) GetHashAlgorithm() protocommon.HashAlgorithm {
	return k.algDetails.GetProtoHashType()
}

// GetSigningAlgorithm returns the signing algorithm of the key.
func (k *ModelKeypair) GetSigningAlgorithm() protocommon.PublicKeyDetails {
	return k.algDetails.GetSignatureAlgorithm()
}

// GetHint returns the fingerprint of the public key.
func (k *ModelKeypair) GetHint() []byte {
	return k.hint
}

// GetKeyAlgorithm returns the top-level key algorithm name.
func (k *ModelKeypair) GetKeyAlgorithm() string {
	return signing.KeyTypeToString(k.algDetails.GetKeyType())
}

// GetPublicKey returns the public key.
func (k *ModelKeypair) GetPublicKey() crypto.PublicKey {
	return k.publicKey
}

// GetPublicKeyPem returns the public key in PEM format.
func (k *ModelKeypair) GetPublicKeyPem() (string, error) {
	return signing.GetPublicKeyPEM(k.publicKey)
}

// SignData signs the given data using the wrapped private key.
// Returns the signature and the data that was signed (digest for RSA/ECDSA,
// raw data for Ed25519).
func (k *ModelKeypair) SignData(_ context.Context, data []byte) ([]byte, []byte, error) {
	hf := k.algDetails.GetHashType()

	// Compute digest (no-op for pure Ed25519 which doesn't pre-hash)
	dataToSign := signing.ComputeDigest(data, hf)

	sig, err := k.privateKey.Sign(rand.Reader, dataToSign, hf)
	if err != nil {
		return nil, nil, err
	}

	return sig, dataToSign, nil
}
