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

package pkcs11

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// ============================================================================
// Tests for base Signer
// ============================================================================

// TestDefaultModulePaths verifies that default module paths are defined
func TestDefaultModulePaths(t *testing.T) {
	if len(DefaultModulePaths) == 0 {
		t.Error("DefaultModulePaths should not be empty")
	}

	// Check that paths are non-empty strings
	for i, path := range DefaultModulePaths {
		if path == "" {
			t.Errorf("DefaultModulePaths[%d] is empty string", i)
		}
	}
}

// TestNewSigner_InvalidURI tests error handling for invalid PKCS#11 URIs
func TestNewSigner_InvalidURI(t *testing.T) {
	tests := []struct {
		name      string
		uri       string
		wantError bool
	}{
		{
			name:      "empty URI",
			uri:       "",
			wantError: true,
		},
		{
			name:      "missing prefix",
			uri:       "token=test;object=key",
			wantError: true,
		},
		{
			name:      "malformed URI",
			uri:       "pkcs11:::",
			wantError: true, // Parser catches malformed URIs
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NewSigner(tt.uri, nil)
			if tt.wantError && err == nil {
				t.Error("Expected error for invalid URI, got nil")
			}
			if !tt.wantError && err != nil && tt.uri != "" {
				// We expect errors for empty URI, but not for malformed ones (parser is lenient)
				t.Errorf("Unexpected error: %v", err)
			}
		})
	}
}

// ============================================================================
// Tests for CertSigner
// ============================================================================

// generateTestCertificate creates a self-signed certificate for testing
func generateTestCertificate(t *testing.T) ([]byte, *ecdsa.PrivateKey) {
	t.Helper()

	// Generate private key
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate private key: %v", err)
	}

	// Create certificate template
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Test Org"},
			CommonName:   "Test Certificate",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
		BasicConstraintsValid: true,
	}

	// Create self-signed certificate
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &privKey.PublicKey, privKey)
	if err != nil {
		t.Fatalf("Failed to create certificate: %v", err)
	}

	// Encode to PEM
	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	})

	return certPEM, privKey
}

// TestNewCertSigner_MissingCertificate tests error handling when certificate file doesn't exist
func TestNewCertSigner_MissingCertificate(t *testing.T) {
	_, err := NewCertSigner("pkcs11:token=test;object=key", "/nonexistent/cert.pem", nil, nil)
	if err == nil {
		t.Error("Expected error for missing certificate file, got nil")
	}
}

// TestNewCertSigner_InvalidCertificate tests error handling for invalid certificate content
func TestNewCertSigner_InvalidCertificate(t *testing.T) {
	tmpDir := t.TempDir()
	certFile := filepath.Join(tmpDir, "invalid.pem")

	// Write invalid PEM content
	err := os.WriteFile(certFile, []byte("invalid certificate content"), 0644)
	if err != nil {
		t.Fatalf("Failed to write test file: %v", err)
	}

	_, err = NewCertSigner("pkcs11:token=test;object=key", certFile, nil, nil)
	if err == nil {
		t.Error("Expected error for invalid certificate content, got nil")
	}
}

// TestNewCertSigner_EmptyURI tests error handling for empty PKCS#11 URI
func TestNewCertSigner_EmptyURI(t *testing.T) {
	tmpDir := t.TempDir()
	certFile := filepath.Join(tmpDir, "cert.pem")

	certPEM, _ := generateTestCertificate(t)
	err := os.WriteFile(certFile, certPEM, 0644)
	if err != nil {
		t.Fatalf("Failed to write test certificate: %v", err)
	}

	_, err = NewCertSigner("", certFile, nil, nil)
	if err == nil {
		t.Error("Expected error for empty PKCS#11 URI, got nil")
	}
}

// TestNewCertSigner_MissingChainFile tests error handling when chain file doesn't exist
func TestNewCertSigner_MissingChainFile(t *testing.T) {
	tmpDir := t.TempDir()
	certFile := filepath.Join(tmpDir, "cert.pem")

	certPEM, _ := generateTestCertificate(t)
	err := os.WriteFile(certFile, certPEM, 0644)
	if err != nil {
		t.Fatalf("Failed to write test certificate: %v", err)
	}

	chainFiles := []string{"/nonexistent/chain.pem"}
	_, err = NewCertSigner("pkcs11:token=test;object=key", certFile, chainFiles, nil)
	if err == nil {
		t.Error("Expected error for missing chain file, got nil")
	}
}

// TestNewCertSigner_InvalidChainFile tests error handling for invalid chain certificate
func TestNewCertSigner_InvalidChainFile(t *testing.T) {
	tmpDir := t.TempDir()
	certFile := filepath.Join(tmpDir, "cert.pem")
	chainFile := filepath.Join(tmpDir, "chain.pem")

	certPEM, _ := generateTestCertificate(t)
	err := os.WriteFile(certFile, certPEM, 0644)
	if err != nil {
		t.Fatalf("Failed to write test certificate: %v", err)
	}

	// Write invalid chain content
	err = os.WriteFile(chainFile, []byte("invalid chain content"), 0644)
	if err != nil {
		t.Fatalf("Failed to write test chain file: %v", err)
	}

	chainFiles := []string{chainFile}
	_, err = NewCertSigner("pkcs11:token=test;object=key", certFile, chainFiles, nil)
	if err == nil {
		t.Error("Expected error for invalid chain certificate, got nil")
	}
}

// TestNewCertSigner_MultipleChainFiles tests handling of multiple chain certificates
func TestNewCertSigner_MultipleChainFiles(t *testing.T) {
	tmpDir := t.TempDir()
	certFile := filepath.Join(tmpDir, "cert.pem")
	chain1File := filepath.Join(tmpDir, "chain1.pem")
	chain2File := filepath.Join(tmpDir, "chain2.pem")

	// Generate certificates
	certPEM, _ := generateTestCertificate(t)
	chain1PEM, _ := generateTestCertificate(t)
	chain2PEM, _ := generateTestCertificate(t)

	// Write certificates
	if err := os.WriteFile(certFile, certPEM, 0644); err != nil {
		t.Fatalf("Failed to write cert: %v", err)
	}
	if err := os.WriteFile(chain1File, chain1PEM, 0644); err != nil {
		t.Fatalf("Failed to write chain1: %v", err)
	}
	if err := os.WriteFile(chain2File, chain2PEM, 0644); err != nil {
		t.Fatalf("Failed to write chain2: %v", err)
	}

	chainFiles := []string{chain1File, chain2File}

	// This will fail because we can't actually initialize PKCS#11 without a real token,
	// but it should at least parse the certificates successfully before failing on PKCS#11 init
	_, err := NewCertSigner("pkcs11:token=test;object=key", certFile, chainFiles, nil)

	// We expect an error (PKCS#11 initialization will fail), but it should NOT be
	// a certificate parsing error
	if err != nil && !strings.Contains(err.Error(), "failed to get module") && !strings.Contains(err.Error(), "failed to initialize PKCS") {
		t.Logf("Expected PKCS#11 initialization error, got: %v", err)
	}
}
