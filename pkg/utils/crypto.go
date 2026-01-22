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

package utils

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"fmt"
)

// SignWithKey signs data using the private key.
//
// Supports ECDSA (with ASN.1 encoding), RSA (with PSS padding), and Ed25519 keys.
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

// VerifySignature verifies a signature using the public key.
//
// Supports ECDSA, RSA (tries PSS first, falls back to PKCS1v15), and Ed25519 keys.
func VerifySignature(publicKey crypto.PublicKey, message, signature []byte) error {
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

// signECDSA signs data using an ECDSA private key.
func signECDSA(key *ecdsa.PrivateKey, data []byte) ([]byte, error) {
	// Hash the data with SHA256
	hash := sha256.Sum256(data)

	// Sign using ECDSA with ASN.1 encoding
	signature, err := ecdsa.SignASN1(rand.Reader, key, hash[:])
	if err != nil {
		return nil, fmt.Errorf("ECDSA signing failed: %w", err)
	}

	return signature, nil
}

// signRSA signs data using an RSA private key with PSS padding.
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
func signEd25519(key ed25519.PrivateKey, data []byte) ([]byte, error) {
	signature := ed25519.Sign(key, data)
	return signature, nil
}

// verifyECDSA verifies an ECDSA signature.
func verifyECDSA(key *ecdsa.PublicKey, message, signature []byte) error {
	// Hash the message based on curve size
	var hash []byte
	keySize := key.Curve.Params().BitSize

	switch keySize {
	case 256, 384, 521:
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

// ComputePAE computes the Pre-Authentication Encoding for DSSE.
//
// PAE(type, payload) = "DSSEv1" + SP + LEN(type) + SP + type + SP + LEN(payload) + SP + payload
func ComputePAE(payloadType string, payload []byte) []byte {
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

// appendLength appends an ASCII decimal representation of n to buf.
func appendLength(buf []byte, n int) []byte {
	return append(buf, []byte(fmt.Sprintf("%d", n))...)
}
