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
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/sigstore/model-signing/pkg/config"
	"github.com/sigstore/model-signing/pkg/utils"
)

func TestNewVerifier_EmptyPublicKeyPath(t *testing.T) {
	cfg := KeyVerifierConfig{
		KeyConfig: config.KeyConfig{Path: "",},
	}

	_, err := NewVerifier(cfg)
	if err == nil {
		t.Error("Expected error for empty public key path, got nil")
	}
}

func TestNewVerifier_NonexistentPublicKey(t *testing.T) {
	cfg := KeyVerifierConfig{
		KeyConfig: config.KeyConfig{Path: "/nonexistent/key.pub",},
	}

	_, err := NewVerifier(cfg)
	if err == nil {
		t.Error("Expected error for nonexistent public key, got nil")
	}
}

func TestNewVerifier_InvalidPEMFormat(t *testing.T) {
	tmpDir := t.TempDir()
	keyFile := filepath.Join(tmpDir, "key.pub")

	// Write invalid PEM content
	if err := os.WriteFile(keyFile, []byte("not a valid PEM file"), 0644); err != nil {
		t.Fatalf("Failed to create key file: %v", err)
	}

	cfg := KeyVerifierConfig{
		KeyConfig: config.KeyConfig{Path: keyFile,},
	}

	_, err := NewVerifier(cfg)
	if err == nil {
		t.Error("Expected error for invalid PEM format, got nil")
	}
}

func TestNewVerifier_ValidECDSAKey(t *testing.T) {
	tmpDir := t.TempDir()
	keyFile := filepath.Join(tmpDir, "key.pub")

	// Generate ECDSA key
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate ECDSA key: %v", err)
	}

	// Encode public key in PEM format
	pubKeyBytes, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		t.Fatalf("Failed to marshal public key: %v", err)
	}

	pemBlock := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubKeyBytes,
	}

	if err := os.WriteFile(keyFile, pem.EncodeToMemory(pemBlock), 0644); err != nil {
		t.Fatalf("Failed to write key file: %v", err)
	}

	cfg := KeyVerifierConfig{
		KeyConfig: config.KeyConfig{Path: keyFile,},
	}

	verifier, err := NewVerifier(cfg)
	if err != nil {
		t.Fatalf("Expected no error for valid ECDSA key, got: %v", err)
	}

	if verifier == nil {
		t.Fatal("Expected non-nil verifier")
	}

	// Verify the public key is stored
	if _, ok := verifier.publicKey.(*ecdsa.PublicKey); !ok {
		t.Error("Expected ECDSA public key")
	}

	// Verify key hash is computed
	if verifier.keyHash == "" {
		t.Error("Expected non-empty key hash")
	}
}

func TestNewVerifier_ValidRSAKey(t *testing.T) {
	tmpDir := t.TempDir()
	keyFile := filepath.Join(tmpDir, "key.pub")

	// Generate RSA key
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key: %v", err)
	}

	// Encode public key in PEM format
	pubKeyBytes, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		t.Fatalf("Failed to marshal public key: %v", err)
	}

	pemBlock := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubKeyBytes,
	}

	if err := os.WriteFile(keyFile, pem.EncodeToMemory(pemBlock), 0644); err != nil {
		t.Fatalf("Failed to write key file: %v", err)
	}

	cfg := KeyVerifierConfig{
		KeyConfig: config.KeyConfig{Path: keyFile,},
	}

	verifier, err := NewVerifier(cfg)
	if err != nil {
		t.Fatalf("Expected no error for valid RSA key, got: %v", err)
	}

	if verifier == nil {
		t.Fatal("Expected non-nil verifier")
	}

	// Verify the public key is stored
	if _, ok := verifier.publicKey.(*rsa.PublicKey); !ok {
		t.Error("Expected RSA public key")
	}
}

func TestNewVerifier_ValidEd25519Key(t *testing.T) {
	tmpDir := t.TempDir()
	keyFile := filepath.Join(tmpDir, "key.pub")

	// Generate Ed25519 key
	publicKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate Ed25519 key: %v", err)
	}

	// Encode public key in PEM format
	pubKeyBytes, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		t.Fatalf("Failed to marshal public key: %v", err)
	}

	pemBlock := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubKeyBytes,
	}

	if err := os.WriteFile(keyFile, pem.EncodeToMemory(pemBlock), 0644); err != nil {
		t.Fatalf("Failed to write key file: %v", err)
	}

	cfg := KeyVerifierConfig{
		KeyConfig: config.KeyConfig{Path: keyFile,},
	}

	verifier, err := NewVerifier(cfg)
	if err != nil {
		t.Fatalf("Expected no error for valid Ed25519 key, got: %v", err)
	}

	if verifier == nil {
		t.Fatal("Expected non-nil verifier")
	}

	// Verify the public key is stored
	if _, ok := verifier.publicKey.(ed25519.PublicKey); !ok {
		t.Error("Expected Ed25519 public key")
	}
}

func TestNewVerifier_RSAPKCS1Format(t *testing.T) {
	tmpDir := t.TempDir()
	keyFile := filepath.Join(tmpDir, "key.pub")

	// Generate RSA key
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key: %v", err)
	}

	// Encode public key in PKCS1 format
	pubKeyBytes := x509.MarshalPKCS1PublicKey(&privateKey.PublicKey)

	pemBlock := &pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: pubKeyBytes,
	}

	if err := os.WriteFile(keyFile, pem.EncodeToMemory(pemBlock), 0644); err != nil {
		t.Fatalf("Failed to write key file: %v", err)
	}

	cfg := KeyVerifierConfig{
		KeyConfig: config.KeyConfig{Path: keyFile,},
	}

	verifier, err := NewVerifier(cfg)
	if err != nil {
		t.Fatalf("Expected no error for PKCS1 RSA key, got: %v", err)
	}

	if verifier == nil {
		t.Fatal("Expected non-nil verifier")
	}

	// Verify the public key is stored
	if _, ok := verifier.publicKey.(*rsa.PublicKey); !ok {
		t.Error("Expected RSA public key")
	}
}

func TestValidatePublicKey_UnsupportedECDSACurve(t *testing.T) {
	// P-224 is not supported
	privateKey, err := ecdsa.GenerateKey(elliptic.P224(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate ECDSA key: %v", err)
	}

	_, err = validatePublicKeyTest(&privateKey.PublicKey)
	if err == nil {
		t.Error("Expected error for unsupported curve P-224, got nil")
	}
}

func TestValidatePublicKey_SupportedCurves(t *testing.T) {
	curves := []struct {
		name  string
		curve elliptic.Curve
	}{
		{"P-256", elliptic.P256()},
		{"P-384", elliptic.P384()},
		{"P-521", elliptic.P521()},
	}

	for _, tc := range curves {
		t.Run(tc.name, func(t *testing.T) {
			privateKey, err := ecdsa.GenerateKey(tc.curve, rand.Reader)
			if err != nil {
				t.Fatalf("Failed to generate ECDSA key: %v", err)
			}

			pubKey, err := validatePublicKeyTest(&privateKey.PublicKey)
			if err != nil {
				t.Errorf("Expected no error for curve %s, got: %v", tc.name, err)
			}

			if pubKey == nil {
				t.Errorf("Expected non-nil public key for curve %s", tc.name)
			}
		})
	}
}

func TestComputePAE_Verifier(t *testing.T) {
	tests := []struct {
		name        string
		payloadType string
		payload     []byte
		expected    []byte
	}{
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
			name:        "empty payload",
			payloadType: "text/plain",
			payload:     []byte(""),
			expected:    []byte("DSSEv1 10 text/plain 0 "),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := utils.ComputePAE(tt.payloadType, tt.payload)

			if len(result) != len(tt.expected) {
				t.Errorf("utils.ComputePAE() length = %d, want %d", len(result), len(tt.expected))
				t.Errorf("Full result: %q", string(result))
				t.Errorf("Full expected: %q", string(tt.expected))
				return
			}

			for i := range result {
				if result[i] != tt.expected[i] {
					t.Errorf("utils.ComputePAE() at index %d = %d, want %d", i, result[i], tt.expected[i])
					t.Errorf("Full result: %q", string(result))
					t.Errorf("Full expected: %q", string(tt.expected))
					return
				}
			}
		})
	}
}

func TestAppendLength_Verifier(t *testing.T) {
	tests := []struct {
		name     string
		initial  []byte
		length   int
		expected []byte
	}{
		{
			name:     "single digit",
			initial:  []byte("prefix "),
			length:   5,
			expected: []byte("prefix 5"),
		},
		{
			name:     "multiple digits",
			initial:  []byte("test "),
			length:   123,
			expected: []byte("test 123"),
		},
		{
			name:     "zero length",
			initial:  []byte("data "),
			length:   0,
			expected: []byte("data 0"),
		},
		{
			name:     "empty initial",
			initial:  []byte(""),
			length:   42,
			expected: []byte("42"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := appendLengthTest(tt.initial, tt.length)

			if string(result) != string(tt.expected) {
				t.Errorf("appendLengthTest() = %q, want %q", string(result), string(tt.expected))
			}
		})
	}
}

func TestLoadPublicKey_InvalidPEM(t *testing.T) {
	tmpDir := t.TempDir()
	keyFile := filepath.Join(tmpDir, "key.pub")

	// Write invalid PEM content
	if err := os.WriteFile(keyFile, []byte("not a PEM file"), 0644); err != nil {
		t.Fatalf("Failed to create key file: %v", err)
	}

	_, err := loadPublicKeyTest(keyFile)
	if err == nil {
		t.Error("Expected error for invalid PEM, got nil")
	}
}

func TestLoadPublicKey_UnsupportedFormat(t *testing.T) {
	tmpDir := t.TempDir()
	keyFile := filepath.Join(tmpDir, "key.pub")

	// Create a PEM with invalid content
	pemBlock := &pem.Block{
		Type:  "UNSUPPORTED KEY",
		Bytes: []byte("invalid key data"),
	}

	if err := os.WriteFile(keyFile, pem.EncodeToMemory(pemBlock), 0644); err != nil {
		t.Fatalf("Failed to write key file: %v", err)
	}

	_, err := loadPublicKeyTest(keyFile)
	if err == nil {
		t.Error("Expected error for unsupported format, got nil")
	}
}

// Test helper functions

func appendLengthTest(buf []byte, n int) []byte {
	return append(buf, []byte(fmt.Sprintf("%d", n))...)
}

func validatePublicKeyTest(key interface{}) (crypto.PublicKey, error) {
	switch k := key.(type) {
	case *ecdsa.PublicKey:
		// Validate curve is supported
		curveName := k.Curve.Params().Name
		if curveName != "P-256" && curveName != "P-384" && curveName != "P-521" {
			return nil, fmt.Errorf("unsupported elliptic curve: %s (supported: P-256, P-384, P-521)", curveName)
		}
		return k, nil
	case *rsa.PublicKey:
		// RSA keys are supported
		return k, nil
	case ed25519.PublicKey:
		// Ed25519 keys are supported
		return k, nil
	default:
		return nil, fmt.Errorf("unsupported public key type: %T", key)
	}
}

func loadPublicKeyTest(path string) (crypto.PublicKey, error) {
	pemBytes, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read public key file: %w", err)
	}

	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}

	// Try parsing as PKIX public key (most common format)
	if key, err := x509.ParsePKIXPublicKey(block.Bytes); err == nil {
		return validatePublicKeyTest(key)
	}

	// Try parsing as PKCS1 RSA public key
	if key, err := x509.ParsePKCS1PublicKey(block.Bytes); err == nil {
		return validatePublicKeyTest(key)
	}

	return nil, fmt.Errorf("failed to parse public key (unsupported format)")
}
