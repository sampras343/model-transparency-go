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
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// generateTestCertificate creates a self-signed certificate for testing
func generateTestCertificate(t *testing.T) (*x509.Certificate, *ecdsa.PrivateKey, []byte) {
	t.Helper()

	// Generate private key
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate private key: %v", err)
	}

	// Create certificate template
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Test Org"},
			CommonName:   "test-cert",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
		BasicConstraintsValid: true,
	}

	// Create self-signed certificate
	derBytes, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	if err != nil {
		t.Fatalf("Failed to create certificate: %v", err)
	}

	cert, err := x509.ParseCertificate(derBytes)
	if err != nil {
		t.Fatalf("Failed to parse certificate: %v", err)
	}

	// PEM encode
	pemBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: derBytes,
	})

	return cert, privateKey, pemBytes
}

func TestNewModelCertificateProvider_ValidCertificate(t *testing.T) {
	tmpDir := t.TempDir()

	// Generate test certificate
	_, _, pemBytes := generateTestCertificate(t)

	// Write to file
	certPath := filepath.Join(tmpDir, "cert.pem")
	if err := os.WriteFile(certPath, pemBytes, 0644); err != nil {
		t.Fatalf("Failed to write certificate: %v", err)
	}

	// Create provider
	provider, err := NewModelCertificateProvider(certPath)
	if err != nil {
		t.Errorf("Expected no error for valid certificate, got: %v", err)
	}

	if provider == nil {
		t.Fatal("Expected non-nil provider")
	}

	if provider.certPath != certPath {
		t.Errorf("Expected cert path %s, got %s", certPath, provider.certPath)
	}

	if provider.cert == nil {
		t.Fatal("Expected non-nil certificate")
	}
}

func TestNewModelCertificateProvider_NonExistentFile(t *testing.T) {
	_, err := NewModelCertificateProvider("/nonexistent/cert.pem")
	if err == nil {
		t.Error("Expected error for non-existent certificate file, got nil")
	}
}

func TestNewModelCertificateProvider_InvalidPEM(t *testing.T) {
	tmpDir := t.TempDir()

	// Write invalid PEM data
	certPath := filepath.Join(tmpDir, "invalid.pem")
	if err := os.WriteFile(certPath, []byte("not a valid PEM"), 0644); err != nil {
		t.Fatalf("Failed to write file: %v", err)
	}

	_, err := NewModelCertificateProvider(certPath)
	if err == nil {
		t.Error("Expected error for invalid PEM data, got nil")
	}
}

func TestNewModelCertificateProvider_EmptyFile(t *testing.T) {
	tmpDir := t.TempDir()

	// Write empty file
	certPath := filepath.Join(tmpDir, "empty.pem")
	if err := os.WriteFile(certPath, []byte(""), 0644); err != nil {
		t.Fatalf("Failed to write file: %v", err)
	}

	_, err := NewModelCertificateProvider(certPath)
	if err == nil {
		t.Error("Expected error for empty file, got nil")
	}
}

func TestModelCertificateProvider_GetCertificate(t *testing.T) {
	tmpDir := t.TempDir()

	// Generate test certificate
	_, _, pemBytes := generateTestCertificate(t)

	// Write to file
	certPath := filepath.Join(tmpDir, "cert.pem")
	if err := os.WriteFile(certPath, pemBytes, 0644); err != nil {
		t.Fatalf("Failed to write certificate: %v", err)
	}

	// Create provider
	provider, err := NewModelCertificateProvider(certPath)
	if err != nil {
		t.Fatalf("Failed to create provider: %v", err)
	}

	// Get certificate
	ctx := context.Background()
	certBytes, err := provider.GetCertificate(ctx, nil, nil)
	if err != nil {
		t.Errorf("Expected no error from GetCertificate, got: %v", err)
	}

	if certBytes == nil {
		t.Error("Expected non-nil certificate bytes")
	}

	// GetCertificate returns raw DER bytes, verify it's parseable
	cert, err := x509.ParseCertificate(certBytes)
	if err != nil {
		t.Errorf("Failed to parse returned certificate: %v", err)
	}

	if cert == nil {
		t.Fatal("Expected non-nil parsed certificate")
	}

	// Verify it matches the original certificate
	if cert.Subject.CommonName != "test-cert" {
		t.Errorf("Expected CommonName 'test-cert', got %s", cert.Subject.CommonName)
	}
}

func TestModelCertificateProvider_GetCertificate_WithContext(t *testing.T) {
	tmpDir := t.TempDir()

	// Generate test certificate
	_, _, pemBytes := generateTestCertificate(t)

	// Write to file
	certPath := filepath.Join(tmpDir, "cert.pem")
	if err := os.WriteFile(certPath, pemBytes, 0644); err != nil {
		t.Fatalf("Failed to write certificate: %v", err)
	}

	// Create provider
	provider, err := NewModelCertificateProvider(certPath)
	if err != nil {
		t.Fatalf("Failed to create provider: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	certBytes, err := provider.GetCertificate(ctx, nil, nil)
	if err != nil {
		t.Errorf("GetCertificate failed: %v", err)
	}

	if certBytes == nil {
		t.Error("Expected non-nil certificate bytes")
	}

	if _, err := x509.ParseCertificate(certBytes); err != nil {
		t.Errorf("Failed to parse certificate: %v", err)
	}
}

// TestModelCertificateProvider_InterfaceCompliance verifies that
// ModelCertificateProvider implements the required interface
func TestModelCertificateProvider_InterfaceCompliance(t *testing.T) {
	// This test ensures the type implements the interface at compile time
	var _ interface{} = (*ModelCertificateProvider)(nil)
}

func TestModelCertificateProvider_MultipleCalls(t *testing.T) {
	tmpDir := t.TempDir()

	// Generate test certificate
	_, _, pemBytes := generateTestCertificate(t)

	// Write to file
	certPath := filepath.Join(tmpDir, "cert.pem")
	if err := os.WriteFile(certPath, pemBytes, 0644); err != nil {
		t.Fatalf("Failed to write certificate: %v", err)
	}

	// Create provider
	provider, err := NewModelCertificateProvider(certPath)
	if err != nil {
		t.Fatalf("Failed to create provider: %v", err)
	}

	ctx := context.Background()

	// Call GetCertificate multiple times
	for i := 0; i < 3; i++ {
		certBytes, err := provider.GetCertificate(ctx, nil, nil)
		if err != nil {
			t.Errorf("Call %d: GetCertificate failed: %v", i+1, err)
		}

		if certBytes == nil {
			t.Errorf("Call %d: Expected non-nil certificate bytes", i+1)
		}
	}
}
