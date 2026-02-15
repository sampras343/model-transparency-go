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
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"

	protocommon "github.com/sigstore/protobuf-specs/gen/pb-go/common/v1"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
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
	pemBytes, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read key file: %w", err)
	}

	// Use sigstore's cryptoutils for private key parsing (handles PKCS8, EC, RSA, encrypted)
	var passFunc cryptoutils.PassFunc
	if password != "" {
		passFunc = func(_ bool) ([]byte, error) {
			return []byte(password), nil
		}
	}

	privKey, err := cryptoutils.UnmarshalPEMToPrivateKey(pemBytes, passFunc)
	if err != nil {
		return nil, fmt.Errorf("failed to parse private key: %w", err)
	}

	signer, ok := privKey.(crypto.Signer)
	if !ok {
		return nil, fmt.Errorf("private key does not implement crypto.Signer")
	}

	pubKey := signer.Public()

	// Determine the algorithm details from the key type
	algID, err := algorithmFromKey(pubKey)
	if err != nil {
		return nil, err
	}

	algDetails, err := sigstoresig.GetAlgorithmDetails(algID)
	if err != nil {
		return nil, fmt.Errorf("failed to get algorithm details: %w", err)
	}

	// Compute key hint (SHA256 of PEM-encoded public key, hex-encoded).
	// Hashes the full PEM bytes (including BEGIN/END headers) and hex-encodes the result.
	pubKeyPEM, err := cryptoutils.MarshalPublicKeyToPEM(pubKey)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal public key to PEM: %w", err)
	}
	hashedBytes := sha256.Sum256(pubKeyPEM)
	hint := []byte(hex.EncodeToString(hashedBytes[:]))

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
	switch k.algDetails.GetKeyType() {
	case sigstoresig.ECDSA:
		return "ECDSA"
	case sigstoresig.RSA:
		return "RSA"
	case sigstoresig.ED25519:
		return "ED25519"
	default:
		return ""
	}
}

// GetPublicKey returns the public key.
func (k *ModelKeypair) GetPublicKey() crypto.PublicKey {
	return k.publicKey
}

// GetPublicKeyPem returns the public key in PEM format.
func (k *ModelKeypair) GetPublicKeyPem() (string, error) {
	pubKeyPEM, err := cryptoutils.MarshalPublicKeyToPEM(k.publicKey)
	if err != nil {
		return "", err
	}
	return string(pubKeyPEM), nil
}

// SignData signs the given data using the wrapped private key.
// Returns the signature and the data that was signed (digest for RSA/ECDSA,
// raw data for Ed25519).
func (k *ModelKeypair) SignData(_ context.Context, data []byte) ([]byte, []byte, error) {
	hf := k.algDetails.GetHashType()
	dataToSign := data

	// RSA, ECDSA, and Ed25519ph sign a digest; pure Ed25519 hashes during signing
	if hf != crypto.Hash(0) {
		hasher := hf.New()
		hasher.Write(data)
		dataToSign = hasher.Sum(nil)
	}

	sig, err := k.privateKey.Sign(rand.Reader, dataToSign, hf)
	if err != nil {
		return nil, nil, err
	}

	return sig, dataToSign, nil
}

// algorithmFromKey determines the sigstore PublicKeyDetails for a given public key.
func algorithmFromKey(pubKey crypto.PublicKey) (protocommon.PublicKeyDetails, error) {
	switch k := pubKey.(type) {
	case *ecdsa.PublicKey:
		switch k.Curve {
		case elliptic.P256():
			return protocommon.PublicKeyDetails_PKIX_ECDSA_P256_SHA_256, nil
		case elliptic.P384():
			return protocommon.PublicKeyDetails_PKIX_ECDSA_P384_SHA_384, nil
		default:
			return 0, fmt.Errorf("unsupported ECDSA curve: %s", k.Curve.Params().Name)
		}
	case *rsa.PublicKey:
		bitSize := k.N.BitLen()
		switch {
		case bitSize <= 2048:
			return protocommon.PublicKeyDetails_PKIX_RSA_PKCS1V15_2048_SHA256, nil
		case bitSize <= 3072:
			return protocommon.PublicKeyDetails_PKIX_RSA_PKCS1V15_3072_SHA256, nil
		default:
			return protocommon.PublicKeyDetails_PKIX_RSA_PKCS1V15_4096_SHA256, nil
		}
	case ed25519.PublicKey:
		return protocommon.PublicKeyDetails_PKIX_ED25519_PH, nil
	default:
		return 0, fmt.Errorf("unsupported key type: %T", pubKey)
	}
}
