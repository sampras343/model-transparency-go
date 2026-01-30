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

package crypto

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"fmt"
)

// SignWithKey signs data using the provided private key.
// Supports ECDSA (with ASN.1 encoding), RSA (with PSS padding), and Ed25519 keys.
// Returns the signature bytes or an error if the key type is unsupported or signing fails.
func SignWithKey(privateKey crypto.PrivateKey, data []byte) ([]byte, error) {
	switch key := privateKey.(type) {
	case *ecdsa.PrivateKey:
		return signECDSA(key, data)
	case *rsa.PrivateKey:
		return signRSA(key, data)
	case ed25519.PrivateKey:
		return signEd25519(key, data)
	default:
		return nil, fmt.Errorf("unsupported private key type: %T", privateKey)
	}
}

// signECDSA signs data using an ECDSA private key.
// The hash algorithm is selected based on the key size to match cryptographic best practices:
// - P-256 (secp256r1) uses SHA256
// - P-384 (secp384r1) uses SHA384
// - P-521 (secp521r1) uses SHA512
func signECDSA(key *ecdsa.PrivateKey, data []byte) ([]byte, error) {
	// Select hash algorithm based on curve size
	var hash []byte
	keySize := key.Curve.Params().BitSize

	switch keySize {
	case 256:
		h := sha256.Sum256(data)
		hash = h[:]
	case 384:
		h := sha512.Sum384(data)
		hash = h[:]
	case 521:
		h := sha512.Sum512(data)
		hash = h[:]
	default:
		return nil, fmt.Errorf("unsupported ECDSA curve size: %d bits", keySize)
	}

	// Sign using ECDSA with ASN.1 encoding
	signature, err := ecdsa.SignASN1(rand.Reader, key, hash)
	if err != nil {
		return nil, fmt.Errorf("ECDSA signing failed: %w", err)
	}

	return signature, nil
}

// signRSA signs data using an RSA private key with PSS padding and SHA256 hash.
// Returns the signature bytes or an error if signing fails.
func signRSA(key *rsa.PrivateKey, data []byte) ([]byte, error) {
	// Hash the data with SHA256
	hash := sha256.Sum256(data)

	// Sign using RSA-PSS
	signature, err := rsa.SignPSS(rand.Reader, key, crypto.SHA256, hash[:], nil)
	if err != nil {
		return nil, fmt.Errorf("RSA-PSS signing failed: %w", err)
	}

	return signature, nil
}

// signEd25519 signs data using an Ed25519 private key.
// Returns the signature bytes.
func signEd25519(key ed25519.PrivateKey, data []byte) ([]byte, error) {
	signature := ed25519.Sign(key, data)
	return signature, nil
}
