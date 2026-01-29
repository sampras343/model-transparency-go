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

// ComputePAE computes the Pre-Authentication Encoding for DSSE (Dead Simple Signing Envelope).
// The encoding format is: "DSSEv1" + SP + LEN(type) + SP + type + SP + LEN(payload) + SP + payload
// where SP is a space character and LEN is the ASCII decimal length.
// Returns the PAE as a byte slice.
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
// Returns the extended buffer.
func appendLength(buf []byte, n int) []byte {
	return append(buf, []byte(fmt.Sprintf("%d", n))...)
}

// This exists for backward compatibility with signatures created by model_signing v0.2.0.
func ComputePAECompat(payloadType string, payload []byte) []byte {
	// Emulate Python's bytes repr: b'...' with escape sequences
	payloadRepr := fmt.Sprintf("b'%s'", escapeBytesAsPythonRepr(payload))

	// Build buggy PAE: DSSEV1 (capital V) + payload as string repr
	paeStr := fmt.Sprintf("DSSEV1 %d %s %d %s",
		len(payloadType), payloadType, len(payload), payloadRepr)

	return []byte(paeStr)
}

// escapeBytesAsPythonRepr emulates Python package bytes repr escaping.
// This converts bytes to the same string representation Python would use
// when bytes are converted to string via str() or f-string interpolation.
func escapeBytesAsPythonRepr(data []byte) string {
	result := make([]byte, 0, len(data)*2)
	for _, b := range data {
		switch b {
		case '\'':
			result = append(result, '\\', '\'')
		case '\\':
			result = append(result, '\\', '\\')
		case '\n':
			result = append(result, '\\', 'n')
		case '\r':
			result = append(result, '\\', 'r')
		case '\t':
			result = append(result, '\\', 't')
		default:
			if b >= 32 && b < 127 {
				result = append(result, b)
			} else {
				result = append(result, fmt.Sprintf("\\x%02x", b)...)
			}
		}
	}
	return string(result)
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
