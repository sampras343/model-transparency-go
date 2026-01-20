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
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"testing"
)

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
			result := computePAE(tt.payloadType, tt.payload)
			if len(result) != len(tt.expected) {
				t.Errorf("computePAE() length = %d, want %d", len(result), len(tt.expected))
				return
			}
			for i := range result {
				if result[i] != tt.expected[i] {
					t.Errorf("computePAE() at index %d = %v, want %v", i, result[i], tt.expected[i])
					t.Errorf("Full result: %q", string(result))
					t.Errorf("Full expected: %q", string(tt.expected))
					return
				}
			}
		})
	}
}

func TestAppendLength(t *testing.T) {
	tests := []struct {
		name     string
		buf      []byte
		n        int
		expected []byte
	}{
		{
			name:     "zero",
			buf:      []byte{},
			n:        0,
			expected: []byte("0"),
		},
		{
			name:     "single digit",
			buf:      []byte{},
			n:        5,
			expected: []byte("5"),
		},
		{
			name:     "double digit",
			buf:      []byte{},
			n:        42,
			expected: []byte("42"),
		},
		{
			name:     "large number",
			buf:      []byte{},
			n:        12345,
			expected: []byte("12345"),
		},
		{
			name:     "append to existing buffer",
			buf:      []byte("prefix "),
			n:        100,
			expected: []byte("prefix 100"),
		},
		{
			name:     "very large number",
			buf:      []byte{},
			n:        1000000,
			expected: []byte("1000000"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := appendLength(tt.buf, tt.n)
			if string(result) != string(tt.expected) {
				t.Errorf("appendLength() = %q, want %q", string(result), string(tt.expected))
			}
		})
	}
}

func TestExtractPublicKey_ECDSA(t *testing.T) {
	// Generate ECDSA test key
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate ECDSA key: %v", err)
	}

	publicKey, err := extractPublicKey(privateKey)
	if err != nil {
		t.Fatalf("extractPublicKey() error = %v", err)
	}

	// Verify it's the correct public key
	ecdsaPubKey, ok := publicKey.(*ecdsa.PublicKey)
	if !ok {
		t.Fatalf("Expected *ecdsa.PublicKey, got %T", publicKey)
	}

	if !ecdsaPubKey.Equal(&privateKey.PublicKey) {
		t.Error("Extracted public key does not match private key's public key")
	}
}

func TestExtractPublicKey_RSA(t *testing.T) {
	// Generate RSA test key (using small key size for speed)
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key: %v", err)
	}

	publicKey, err := extractPublicKey(privateKey)
	if err != nil {
		t.Fatalf("extractPublicKey() error = %v", err)
	}

	// Verify it's the correct public key
	rsaPubKey, ok := publicKey.(*rsa.PublicKey)
	if !ok {
		t.Fatalf("Expected *rsa.PublicKey, got %T", publicKey)
	}

	if !rsaPubKey.Equal(&privateKey.PublicKey) {
		t.Error("Extracted public key does not match private key's public key")
	}
}

func TestExtractPublicKey_Ed25519(t *testing.T) {
	// Generate Ed25519 test key
	publicKeyGen, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate Ed25519 key: %v", err)
	}

	publicKey, err := extractPublicKey(privateKey)
	if err != nil {
		t.Fatalf("extractPublicKey() error = %v", err)
	}

	// Verify it's the correct public key
	ed25519PubKey, ok := publicKey.(ed25519.PublicKey)
	if !ok {
		t.Fatalf("Expected ed25519.PublicKey, got %T", publicKey)
	}

	if !ed25519PubKey.Equal(publicKeyGen) {
		t.Error("Extracted public key does not match generated public key")
	}
}

func TestExtractPublicKey_UnsupportedType(t *testing.T) {
	// Test with unsupported type (e.g., string)
	_, err := extractPublicKey("not a key")
	if err == nil {
		t.Error("Expected error for unsupported key type, got nil")
	}
}

func TestComputePublicKeyHash_ECDSA(t *testing.T) {
	// Generate ECDSA test key
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate ECDSA key: %v", err)
	}

	hash, err := computePublicKeyHash(&privateKey.PublicKey)
	if err != nil {
		t.Fatalf("computePublicKeyHash() error = %v", err)
	}

	// Verify hash is a hex string of correct length (SHA256 = 64 hex chars)
	if len(hash) != 64 {
		t.Errorf("Expected hash length 64, got %d", len(hash))
	}

	// Verify hash is consistent (calling again should give same result)
	hash2, err := computePublicKeyHash(&privateKey.PublicKey)
	if err != nil {
		t.Fatalf("computePublicKeyHash() second call error = %v", err)
	}

	if hash != hash2 {
		t.Error("computePublicKeyHash() is not deterministic")
	}
}

func TestComputePublicKeyHash_RSA(t *testing.T) {
	// Generate RSA test key (small for speed)
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key: %v", err)
	}

	hash, err := computePublicKeyHash(&privateKey.PublicKey)
	if err != nil {
		t.Fatalf("computePublicKeyHash() error = %v", err)
	}

	// Verify hash is a hex string of correct length (SHA256 = 64 hex chars)
	if len(hash) != 64 {
		t.Errorf("Expected hash length 64, got %d", len(hash))
	}

	// Verify all characters are valid hex
	for _, c := range hash {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) { //nolint:staticcheck
			t.Errorf("Invalid hex character in hash: %c", c)
		}
	}
}

func TestComputePublicKeyHash_Ed25519(t *testing.T) {
	// Generate Ed25519 test key
	publicKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate Ed25519 key: %v", err)
	}

	hash, err := computePublicKeyHash(publicKey)
	if err != nil {
		t.Fatalf("computePublicKeyHash() error = %v", err)
	}

	// Verify hash is a hex string of correct length (SHA256 = 64 hex chars)
	if len(hash) != 64 {
		t.Errorf("Expected hash length 64, got %d", len(hash))
	}
}

func TestSignWithKey_ECDSA(t *testing.T) {
	// Generate ECDSA test key
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate ECDSA key: %v", err)
	}

	data := []byte("test data to sign")

	signature, err := signWithKey(privateKey, data)
	if err != nil {
		t.Fatalf("signWithKey() error = %v", err)
	}

	if len(signature) == 0 {
		t.Error("Expected non-empty signature")
	}

	// Signatures should be different each time (due to randomness)
	signature2, err := signWithKey(privateKey, data)
	if err != nil {
		t.Fatalf("signWithKey() second call error = %v", err)
	}

	// ECDSA signatures have randomness, so they should differ
	// (This is expected behavior)
	if len(signature2) == 0 {
		t.Error("Expected non-empty second signature")
	}
}

func TestSignWithKey_RSA(t *testing.T) {
	// Generate RSA test key (small for speed)
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key: %v", err)
	}

	data := []byte("test data to sign")

	signature, err := signWithKey(privateKey, data)
	if err != nil {
		t.Fatalf("signWithKey() error = %v", err)
	}

	if len(signature) == 0 {
		t.Error("Expected non-empty signature")
	}

	// RSA-PSS signatures also have randomness
	if len(signature) != 256 { // 2048-bit key = 256 bytes
		t.Errorf("Expected signature length 256, got %d", len(signature))
	}
}

func TestSignWithKey_Ed25519(t *testing.T) {
	// Generate Ed25519 test key
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate Ed25519 key: %v", err)
	}

	data := []byte("test data to sign")

	signature, err := signWithKey(privateKey, data)
	if err != nil {
		t.Fatalf("signWithKey() error = %v", err)
	}

	if len(signature) != ed25519.SignatureSize {
		t.Errorf("Expected signature length %d, got %d", ed25519.SignatureSize, len(signature))
	}

	// Ed25519 signatures are deterministic for the same key and data
	signature2, err := signWithKey(privateKey, data)
	if err != nil {
		t.Fatalf("signWithKey() second call error = %v", err)
	}

	// Ed25519 signatures should be identical for same input
	if string(signature) != string(signature2) {
		t.Error("Ed25519 signatures should be deterministic")
	}
}

func TestSignWithKey_UnsupportedType(t *testing.T) {
	// Test with unsupported type
	_, err := signWithKey("not a key", []byte("data"))
	if err == nil {
		t.Error("Expected error for unsupported key type, got nil")
	}
}

func TestNewLocalKeySigner_EmptyPrivateKeyPath(t *testing.T) {
	config := KeySignerConfig{
		PrivateKeyPath: "",
		Password:       "",
	}

	_, err := NewLocalKeySigner(config)
	if err == nil {
		t.Error("Expected error for empty private key path, got nil")
	}
}

func TestCreateVerificationMaterial(t *testing.T) {
	// Create a signer with minimal setup
	signer := &LocalKeySigner{
		keyHash: "abcd1234567890",
	}

	vm := signer.createVerificationMaterial()

	if vm == nil {
		t.Fatal("Expected non-nil verification material")
	}

	// Check that it has public key content
	if vm.GetPublicKey() == nil {
		t.Error("Expected public key in verification material")
	}

	if vm.GetPublicKey().Hint != signer.keyHash {
		t.Errorf("Expected hint %q, got %q", signer.keyHash, vm.GetPublicKey().Hint)
	}
}

func TestSignECDSA(t *testing.T) {
	// Generate ECDSA test key
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate ECDSA key: %v", err)
	}

	data := []byte("test data")

	signature, err := signECDSA(privateKey, data)
	if err != nil {
		t.Fatalf("signECDSA() error = %v", err)
	}

	if len(signature) == 0 {
		t.Error("Expected non-empty signature")
	}
}

func TestSignRSA(t *testing.T) {
	// Generate RSA test key
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key: %v", err)
	}

	data := []byte("test data")

	signature, err := signRSA(privateKey, data)
	if err != nil {
		t.Fatalf("signRSA() error = %v", err)
	}

	if len(signature) == 0 {
		t.Error("Expected non-empty signature")
	}
}

func TestSignEd25519(t *testing.T) {
	// Generate Ed25519 test key
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate Ed25519 key: %v", err)
	}

	data := []byte("test data")

	signature, err := signEd25519(privateKey, data)
	if err != nil {
		t.Fatalf("signEd25519() error = %v", err)
	}

	if len(signature) != ed25519.SignatureSize {
		t.Errorf("Expected signature length %d, got %d", ed25519.SignatureSize, len(signature))
	}
}
