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
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"fmt"
)

// VerifySignature verifies a signature against the message using the provided public key.
// Supports ECDSA, RSA (tries PSS first, falls back to PKCS1v15), and Ed25519 keys.
// Returns nil if verification succeeds, or an error if the signature is invalid or key type is unsupported.
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

// verifyECDSA verifies an ECDSA signature.
// The hash algorithm is selected based on the key size to match signing:
// - P-256 (secp256r1) uses SHA256
// - P-384 (secp384r1) uses SHA384
// - P-521 (secp521r1) uses SHA512
func verifyECDSA(key *ecdsa.PublicKey, message, signature []byte) error {
	// Select hash algorithm based on curve size
	var hash []byte
	keySize := key.Curve.Params().BitSize

	switch keySize {
	case 256:
		h := sha256.Sum256(message)
		hash = h[:]
	case 384:
		h := sha512.Sum384(message)
		hash = h[:]
	case 521:
		h := sha512.Sum512(message)
		hash = h[:]
	default:
		return fmt.Errorf("unsupported ECDSA key size: %d bits", keySize)
	}

	// Verify the signature
	if !ecdsa.VerifyASN1(key, hash, signature) {
		return fmt.Errorf("ECDSA signature verification failed")
	}

	return nil
}

// verifyRSA verifies an RSA signature using SHA256 hash.
// Attempts PSS verification first, falls back to PKCS1v15 if PSS fails.
// Returns nil if verification succeeds, or an error if both methods fail.
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
// Returns nil if verification succeeds, or an error if the signature is invalid.
func verifyEd25519(key ed25519.PublicKey, message, signature []byte) error {
	if !ed25519.Verify(key, message, signature) {
		return fmt.Errorf("Ed25519 signature verification failed")
	}
	return nil
}

// VerifySignatureCompat verifies a signature using SHA256 hash regardless of key type.
// This exists for backward compatibility with v0.2.0 signatures that incorrectly
// used SHA256 for all ECDSA keys instead of matching the hash to the curve size.
//
// Returns nil if verification succeeds, or an error if the signature is invalid.
func VerifySignatureCompat(publicKey crypto.PublicKey, message, signature []byte) error {
	switch key := publicKey.(type) {
	case *ecdsa.PublicKey:
		// v0.2.0 bug: always use SHA256 regardless of curve size
		hash := sha256.Sum256(message)
		if !ecdsa.VerifyASN1(key, hash[:], signature) {
			return fmt.Errorf("ECDSA signature verification failed (compat mode)")
		}
		return nil
	case *rsa.PublicKey:
		return verifyRSA(key, message, signature)
	case ed25519.PublicKey:
		return verifyEd25519(key, message, signature)
	default:
		return fmt.Errorf("unsupported public key type for compat verification: %T", publicKey)
	}
}
