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

// Package signing provides signing utilities and key algorithm detection functions.
package signing

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"

	protocommon "github.com/sigstore/protobuf-specs/gen/pb-go/common/v1"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
	sigstoresig "github.com/sigstore/sigstore/pkg/signature"
)

// GetPublicKeyDetails determines the PublicKeyDetails enum for a given public key.
// This function supports ECDSA (P-256, P-384), RSA (2048, 3072, 4096 bits), and Ed25519 keys.
func GetPublicKeyDetails(pubKey crypto.PublicKey) (protocommon.PublicKeyDetails, error) {
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

// KeyTypeToString converts a signature.PublicKeyType to its string representation.
func KeyTypeToString(keyType sigstoresig.PublicKeyType) string {
	switch keyType {
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

// ComputeKeyHint computes a key hint from a public key.
// The hint is the SHA256 hash of the PEM-encoded public key, hex-encoded.
// This is used by sigstore-go's Keypair interface.
func ComputeKeyHint(pubKey crypto.PublicKey) ([]byte, error) {
	pubKeyPEM, err := cryptoutils.MarshalPublicKeyToPEM(pubKey)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal public key to PEM: %w", err)
	}

	hashedBytes := sha256.Sum256(pubKeyPEM)
	return []byte(hex.EncodeToString(hashedBytes[:])), nil
}

// GetPublicKeyPEM returns the public key in PEM format as a string.
// This is a convenience wrapper around cryptoutils.MarshalPublicKeyToPEM.
func GetPublicKeyPEM(pubKey crypto.PublicKey) (string, error) {
	pubKeyPEM, err := cryptoutils.MarshalPublicKeyToPEM(pubKey)
	if err != nil {
		return "", err
	}
	return string(pubKeyPEM), nil
}

// InitializeKeypairData initializes algorithm details and hint for a public key.
// This is common initialization logic used by both file-based and PKCS#11 keypairs.
// Returns the algorithm details, key hint, and any error encountered.
func InitializeKeypairData(pubKey crypto.PublicKey) (sigstoresig.AlgorithmDetails, []byte, error) {
	// Determine algorithm details from public key
	algID, err := GetPublicKeyDetails(pubKey)
	if err != nil {
		return sigstoresig.AlgorithmDetails{}, nil, err
	}

	algDetails, err := sigstoresig.GetAlgorithmDetails(algID)
	if err != nil {
		return sigstoresig.AlgorithmDetails{}, nil, fmt.Errorf("failed to get algorithm details: %w", err)
	}

	// Compute key hint (SHA256 of PEM-encoded public key, hex-encoded)
	hint, err := ComputeKeyHint(pubKey)
	if err != nil {
		return sigstoresig.AlgorithmDetails{}, nil, err
	}

	return algDetails, hint, nil
}

// LoadPrivateKeyFromPEM loads a private key from a PEM file.
// Returns a crypto.Signer implementation. Supports encrypted keys via password parameter.
func LoadPrivateKeyFromPEM(keyPath string, password string) (crypto.Signer, error) {
	pemBytes, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read key file: %w", err)
	}

	// Create password function if password is provided
	var passFunc cryptoutils.PassFunc
	if password != "" {
		passFunc = func(_ bool) ([]byte, error) {
			return []byte(password), nil
		}
	}

	// Parse private key (handles PKCS8, EC, RSA, encrypted)
	privKey, err := cryptoutils.UnmarshalPEMToPrivateKey(pemBytes, passFunc)
	if err != nil {
		return nil, fmt.Errorf("failed to parse private key: %w", err)
	}

	signer, ok := privKey.(crypto.Signer)
	if !ok {
		return nil, fmt.Errorf("private key does not implement crypto.Signer")
	}

	return signer, nil
}

// ComputeDigest computes a hash digest of the input data using the specified hash function.
// If hashFunc is crypto.Hash(0) (e.g., for pure Ed25519), returns the original data unchanged.
// This is used for signing operations where some algorithms (like Ed25519) don't pre-hash.
func ComputeDigest(data []byte, hashFunc crypto.Hash) []byte {
	if hashFunc == crypto.Hash(0) {
		return data
	}
	hasher := hashFunc.New()
	hasher.Write(data)
	return hasher.Sum(nil)
}
