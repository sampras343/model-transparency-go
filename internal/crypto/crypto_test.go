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
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"testing"
)

// TestComputePAE tests the PAE computation function.
func TestComputePAE(t *testing.T) {
	tests := []struct {
		name        string
		payloadType string
		payload     []byte
		expected    []byte
	}{
		{
			name:        "empty payload",
			payloadType: "application/json",
			payload:     []byte{},
			expected:    []byte("DSSEv1 16 application/json 0 "),
		},
		{
			name:        "simple payload",
			payloadType: "application/json",
			payload:     []byte("test"),
			expected:    []byte("DSSEv1 16 application/json 4 test"),
		},
		{
			name:        "in-toto payload type",
			payloadType: "application/vnd.in-toto+json",
			payload:     []byte(`{"test":"data"}`),
			expected:    []byte("DSSEv1 28 application/vnd.in-toto+json 15 {\"test\":\"data\"}"),
		},
		{
			name:        "payload with special characters",
			payloadType: "text/plain",
			payload:     []byte("hello\nworld\t!"),
			expected:    []byte("DSSEv1 10 text/plain 13 hello\nworld\t!"),
		},
		{
			name:        "large payload length",
			payloadType: "test",
			payload:     make([]byte, 1000),
			expected:    append([]byte("DSSEv1 4 test 1000 "), make([]byte, 1000)...),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ComputePAE(tt.payloadType, tt.payload)
			if len(result) != len(tt.expected) {
				t.Errorf("ComputePAE() length = %d, want %d", len(result), len(tt.expected))
				return
			}
			for i := range result {
				if result[i] != tt.expected[i] {
					t.Errorf("ComputePAE() at index %d = %v, want %v", i, result[i], tt.expected[i])
					return
				}
			}
		})
	}
}

// TestComputePAECompat tests backward compatibility PAE computation.
func TestComputePAECompat(t *testing.T) {
	tests := []struct {
		name        string
		payloadType string
		payload     []byte
		contains    string
	}{
		{
			name:        "simple payload",
			payloadType: "application/json",
			payload:     []byte("test"),
			contains:    "DSSEV1", // Note capital V
		},
		{
			name:        "payload with newline",
			payloadType: "text/plain",
			payload:     []byte("hello\nworld"),
			contains:    "\\n", // Should be escaped
		},
		{
			name:        "payload with tab",
			payloadType: "text/plain",
			payload:     []byte("hello\tworld"),
			contains:    "\\t", // Should be escaped
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ComputePAECompat(tt.payloadType, tt.payload)
			resultStr := string(result)
			if len(resultStr) == 0 {
				t.Error("ComputePAECompat() returned empty result")
			}
			if tt.contains != "" && !containsSubstring(resultStr, tt.contains) {
				t.Errorf("ComputePAECompat() = %q, want to contain %q", resultStr, tt.contains)
			}
		})
	}
}

// TestEscapeBytesAsPythonRepr tests Python-style byte escaping.
func TestEscapeBytesAsPythonRepr(t *testing.T) {
	tests := []struct {
		name     string
		input    []byte
		expected string
	}{
		{
			name:     "simple ascii",
			input:    []byte("hello"),
			expected: "hello",
		},
		{
			name:     "newline",
			input:    []byte("hello\nworld"),
			expected: "hello\\nworld",
		},
		{
			name:     "tab",
			input:    []byte("hello\tworld"),
			expected: "hello\\tworld",
		},
		{
			name:     "carriage return",
			input:    []byte("hello\rworld"),
			expected: "hello\\rworld",
		},
		{
			name:     "single quote",
			input:    []byte("it's"),
			expected: "it\\'s",
		},
		{
			name:     "backslash",
			input:    []byte("path\\to\\file"),
			expected: "path\\\\to\\\\file",
		},
		{
			name:     "non-printable byte",
			input:    []byte{0x00, 0x01, 0x02},
			expected: "\\x00\\x01\\x02",
		},
		{
			name:     "mixed content",
			input:    []byte("hello\x00world"),
			expected: "hello\\x00world",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := escapeBytesAsPythonRepr(tt.input)
			if result != tt.expected {
				t.Errorf("escapeBytesAsPythonRepr() = %q, want %q", result, tt.expected)
			}
		})
	}
}

// TestSignWithKey_ECDSA tests ECDSA signing with different curve sizes.
func TestSignWithKey_ECDSA(t *testing.T) {
	curves := []struct {
		name  string
		curve elliptic.Curve
	}{
		{"P-256", elliptic.P256()},
		{"P-384", elliptic.P384()},
		{"P-521", elliptic.P521()},
	}

	data := []byte("test data to sign")

	for _, tc := range curves {
		t.Run(tc.name, func(t *testing.T) {
			privateKey, err := ecdsa.GenerateKey(tc.curve, rand.Reader)
			if err != nil {
				t.Fatalf("Failed to generate %s key: %v", tc.name, err)
			}

			signature, err := SignWithKey(privateKey, data)
			if err != nil {
				t.Fatalf("SignWithKey() error = %v", err)
			}

			if len(signature) == 0 {
				t.Error("SignWithKey() returned empty signature")
			}

			// Verify the signature
			err = VerifySignature(&privateKey.PublicKey, data, signature)
			if err != nil {
				t.Errorf("VerifySignature() failed to verify: %v", err)
			}
		})
	}
}

// TestSignWithKey_RSA tests RSA signing.
func TestSignWithKey_RSA(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key: %v", err)
	}

	data := []byte("test data to sign")

	signature, err := SignWithKey(privateKey, data)
	if err != nil {
		t.Fatalf("SignWithKey() error = %v", err)
	}

	if len(signature) == 0 {
		t.Error("SignWithKey() returned empty signature")
	}

	// Verify the signature
	err = VerifySignature(&privateKey.PublicKey, data, signature)
	if err != nil {
		t.Errorf("VerifySignature() failed to verify: %v", err)
	}
}

// TestSignWithKey_Ed25519 tests Ed25519 signing.
func TestSignWithKey_Ed25519(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate Ed25519 key: %v", err)
	}

	data := []byte("test data to sign")

	signature, err := SignWithKey(privateKey, data)
	if err != nil {
		t.Fatalf("SignWithKey() error = %v", err)
	}

	if len(signature) == 0 {
		t.Error("SignWithKey() returned empty signature")
	}

	// Verify the signature
	err = VerifySignature(publicKey, data, signature)
	if err != nil {
		t.Errorf("VerifySignature() failed to verify: %v", err)
	}
}

// TestSignWithKey_UnsupportedKey tests that unsupported key types return an error.
func TestSignWithKey_UnsupportedKey(t *testing.T) {
	_, err := SignWithKey("not a key", []byte("data"))
	if err == nil {
		t.Error("SignWithKey() expected error for unsupported key type")
	}
}

// TestVerifySignature_ECDSA tests ECDSA signature verification.
func TestVerifySignature_ECDSA(t *testing.T) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate ECDSA key: %v", err)
	}

	data := []byte("test data")
	signature, err := SignWithKey(privateKey, data)
	if err != nil {
		t.Fatalf("SignWithKey() error = %v", err)
	}

	// Valid signature
	err = VerifySignature(&privateKey.PublicKey, data, signature)
	if err != nil {
		t.Errorf("VerifySignature() error = %v", err)
	}

	// Invalid signature (wrong data)
	err = VerifySignature(&privateKey.PublicKey, []byte("wrong data"), signature)
	if err == nil {
		t.Error("VerifySignature() expected error for wrong data")
	}

	// Invalid signature (corrupted)
	corruptedSig := make([]byte, len(signature))
	copy(corruptedSig, signature)
	corruptedSig[0] ^= 0xff
	err = VerifySignature(&privateKey.PublicKey, data, corruptedSig)
	if err == nil {
		t.Error("VerifySignature() expected error for corrupted signature")
	}
}

// TestVerifySignature_RSA tests RSA signature verification.
func TestVerifySignature_RSA(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key: %v", err)
	}

	data := []byte("test data")
	signature, err := SignWithKey(privateKey, data)
	if err != nil {
		t.Fatalf("SignWithKey() error = %v", err)
	}

	// Valid signature
	err = VerifySignature(&privateKey.PublicKey, data, signature)
	if err != nil {
		t.Errorf("VerifySignature() error = %v", err)
	}

	// Invalid signature (wrong data)
	err = VerifySignature(&privateKey.PublicKey, []byte("wrong data"), signature)
	if err == nil {
		t.Error("VerifySignature() expected error for wrong data")
	}
}

// TestVerifySignature_Ed25519 tests Ed25519 signature verification.
func TestVerifySignature_Ed25519(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate Ed25519 key: %v", err)
	}

	data := []byte("test data")
	signature, err := SignWithKey(privateKey, data)
	if err != nil {
		t.Fatalf("SignWithKey() error = %v", err)
	}

	// Valid signature
	err = VerifySignature(publicKey, data, signature)
	if err != nil {
		t.Errorf("VerifySignature() error = %v", err)
	}

	// Invalid signature (wrong data)
	err = VerifySignature(publicKey, []byte("wrong data"), signature)
	if err == nil {
		t.Error("VerifySignature() expected error for wrong data")
	}
}

// TestVerifySignature_UnsupportedKey tests that unsupported key types return an error.
func TestVerifySignature_UnsupportedKey(t *testing.T) {
	err := VerifySignature("not a key", []byte("data"), []byte("signature"))
	if err == nil {
		t.Error("VerifySignature() expected error for unsupported key type")
	}
}

// TestVerifySignatureCompat_ECDSA tests backward compatible ECDSA verification.
func TestVerifySignatureCompat_ECDSA(t *testing.T) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate ECDSA key: %v", err)
	}

	// For compat mode, we need to create a signature using SHA256 directly
	// (this is what v0.2.0 did incorrectly for all curves)
	data := []byte("test data")

	// Sign with normal method
	signature, err := SignWithKey(privateKey, data)
	if err != nil {
		t.Fatalf("SignWithKey() error = %v", err)
	}

	// VerifySignatureCompat should also work with normal signatures for P-256
	// since both methods use SHA256 for P-256
	err = VerifySignatureCompat(&privateKey.PublicKey, data, signature)
	if err != nil {
		t.Errorf("VerifySignatureCompat() error = %v", err)
	}
}

// TestVerifySignatureCompat_UnsupportedKey tests that unsupported key types return an error.
func TestVerifySignatureCompat_UnsupportedKey(t *testing.T) {
	err := VerifySignatureCompat("not a key", []byte("data"), []byte("signature"))
	if err == nil {
		t.Error("VerifySignatureCompat() expected error for unsupported key type")
	}
}

// TestSignAndVerifyRoundTrip tests the full sign and verify cycle.
func TestSignAndVerifyRoundTrip(t *testing.T) {
	testCases := []struct {
		name       string
		generateFn func() (interface{}, interface{}, error)
	}{
		{
			name: "ECDSA P-256",
			generateFn: func() (interface{}, interface{}, error) {
				key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
				if err != nil {
					return nil, nil, err
				}
				return key, &key.PublicKey, nil
			},
		},
		{
			name: "ECDSA P-384",
			generateFn: func() (interface{}, interface{}, error) {
				key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
				if err != nil {
					return nil, nil, err
				}
				return key, &key.PublicKey, nil
			},
		},
		{
			name: "RSA 2048",
			generateFn: func() (interface{}, interface{}, error) {
				key, err := rsa.GenerateKey(rand.Reader, 2048)
				if err != nil {
					return nil, nil, err
				}
				return key, &key.PublicKey, nil
			},
		},
		{
			name: "Ed25519",
			generateFn: func() (interface{}, interface{}, error) {
				pub, priv, err := ed25519.GenerateKey(rand.Reader)
				return priv, pub, err
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			privateKey, publicKey, err := tc.generateFn()
			if err != nil {
				t.Fatalf("Failed to generate key: %v", err)
			}

			data := []byte("test message for signing")

			// Sign
			signature, err := SignWithKey(privateKey, data)
			if err != nil {
				t.Fatalf("SignWithKey() error = %v", err)
			}

			// Verify
			err = VerifySignature(publicKey, data, signature)
			if err != nil {
				t.Errorf("VerifySignature() error = %v", err)
			}
		})
	}
}

// Helper function for string containment check.
func containsSubstring(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(substr) == 0 ||
		(len(s) > 0 && containsSubstringHelper(s, substr)))
}

func containsSubstringHelper(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
