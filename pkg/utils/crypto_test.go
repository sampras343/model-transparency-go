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
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"strings"
	"testing"
	"time"
)

func TestCheckSupportedECKey(t *testing.T) {
	tests := []struct {
		name      string
		curve     elliptic.Curve
		wantError bool
	}{
		{
			name:      "P-256 supported",
			curve:     elliptic.P256(),
			wantError: false,
		},
		{
			name:      "P-384 supported",
			curve:     elliptic.P384(),
			wantError: false,
		},
		{
			name:      "P-521 supported",
			curve:     elliptic.P521(),
			wantError: false,
		},
		{
			name:      "P-224 unsupported",
			curve:     elliptic.P224(),
			wantError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Generate a key for the given curve
			privKey, err := ecdsa.GenerateKey(tt.curve, rand.Reader)
			if err != nil {
				t.Fatalf("failed to generate key: %v", err)
			}

			err = CheckSupportedECKey(&privKey.PublicKey)
			if tt.wantError && err == nil {
				t.Error("expected error but got none")
			}
			if !tt.wantError && err != nil {
				t.Errorf("unexpected error: %v", err)
			}
		})
	}
}

func TestGetHashAlgorithm(t *testing.T) {
	tests := []struct {
		name     string
		curve    elliptic.Curve
		wantHash crypto.Hash
	}{
		{
			name:     "P-256 uses SHA256",
			curve:    elliptic.P256(),
			wantHash: crypto.SHA256,
		},
		{
			name:     "P-384 uses SHA384",
			curve:    elliptic.P384(),
			wantHash: crypto.SHA384,
		},
		{
			name:     "P-521 uses SHA512",
			curve:    elliptic.P521(),
			wantHash: crypto.SHA512,
		},
		{
			name:     "P-224 defaults to SHA256",
			curve:    elliptic.P224(),
			wantHash: crypto.SHA256,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Generate a key for the given curve
			privKey, err := ecdsa.GenerateKey(tt.curve, rand.Reader)
			if err != nil {
				t.Fatalf("failed to generate key: %v", err)
			}

			hash := GetHashAlgorithm(&privKey.PublicKey)
			if hash != tt.wantHash {
				t.Errorf("got hash %v, want %v", hash, tt.wantHash)
			}
		})
	}
}

func TestParsePEMCertificate(t *testing.T) {
	// Generate test certificates
	cert1Data := generateTestCertificate(t, "Test Cert 1")
	cert2Data := generateTestCertificate(t, "Test Cert 2")

	tests := []struct {
		name      string
		data      []byte
		wantError bool
		errorMsg  string
	}{
		{
			name:      "valid single certificate",
			data:      cert1Data,
			wantError: false,
		},
		{
			name:      "multiple certificates returns first",
			data:      append(cert1Data, cert2Data...),
			wantError: false,
		},
		{
			name:      "empty data",
			data:      []byte{},
			wantError: true,
			errorMsg:  "no valid certificates found",
		},
		{
			name:      "invalid PEM data",
			data:      []byte("not a certificate"),
			wantError: true,
			errorMsg:  "no valid certificates found",
		},
		{
			name: "non-certificate PEM block",
			data: []byte(`-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg
-----END PRIVATE KEY-----`),
			wantError: true,
			errorMsg:  "no valid certificates found",
		},
		{
			name: "malformed certificate PEM",
			data: []byte(`-----BEGIN CERTIFICATE-----
aW52YWxpZCBkYXRh
-----END CERTIFICATE-----`),
			wantError: true,
			errorMsg:  "failed to parse certificate",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cert, err := ParsePEMCertificate(tt.data)

			if tt.wantError {
				if err == nil {
					t.Error("expected error but got none")
				} else if tt.errorMsg != "" && !strings.Contains(err.Error(), tt.errorMsg) {
					t.Errorf("expected error containing %q, got %q", tt.errorMsg, err.Error())
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
				if cert == nil {
					t.Error("expected certificate but got nil")
				}
			}
		})
	}
}

func TestParsePEMCertificates(t *testing.T) {
	// Generate test certificates
	cert1Data := generateTestCertificate(t, "Test Cert 1")
	cert2Data := generateTestCertificate(t, "Test Cert 2")

	tests := []struct {
		name      string
		data      []byte
		wantCount int
		wantError bool
		errorMsg  string
	}{
		{
			name:      "single certificate",
			data:      cert1Data,
			wantCount: 1,
			wantError: false,
		},
		{
			name:      "multiple certificates",
			data:      append(cert1Data, cert2Data...),
			wantCount: 2,
			wantError: false,
		},
		{
			name:      "empty data",
			data:      []byte{},
			wantError: true,
			errorMsg:  "no valid certificates found",
		},
		{
			name:      "invalid PEM data",
			data:      []byte("not a certificate"),
			wantError: true,
			errorMsg:  "no valid certificates found",
		},
		{
			name: "mixed PEM blocks",
			data: append(cert1Data, []byte(`-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg
-----END PRIVATE KEY-----
`)...),
			wantCount: 1, // Only the certificate should be parsed
			wantError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			certs, err := ParsePEMCertificates(tt.data)

			if tt.wantError {
				if err == nil {
					t.Error("expected error but got none")
				} else if tt.errorMsg != "" && !strings.Contains(err.Error(), tt.errorMsg) {
					t.Errorf("expected error containing %q, got %q", tt.errorMsg, err.Error())
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
				if len(certs) != tt.wantCount {
					t.Errorf("got %d certificates, want %d", len(certs), tt.wantCount)
				}
			}
		})
	}
}

func TestParsePEMCertificate_ReturnsFirstCert(t *testing.T) {
	// Generate two distinct certificates
	cert1Data := generateTestCertificate(t, "First Cert")
	cert2Data := generateTestCertificate(t, "Second Cert")

	// Combine them
	combined := append(cert1Data, cert2Data...)

	// Parse with ParsePEMCertificate
	cert, err := ParsePEMCertificate(combined)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify it's the first certificate
	if !strings.Contains(cert.Subject.CommonName, "First Cert") {
		t.Errorf("expected first certificate, got subject: %s", cert.Subject.CommonName)
	}
}

// generateTestCertificate creates a self-signed certificate for testing
func generateTestCertificate(t *testing.T, commonName string) []byte {
	t.Helper()

	// Generate a key
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	// Create certificate template
	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		t.Fatalf("failed to generate serial number: %v", err)
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:   commonName,
			Organization: []string{"Test Organization"},
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
		BasicConstraintsValid: true,
	}

	// Create self-signed certificate
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &privKey.PublicKey, privKey)
	if err != nil {
		t.Fatalf("failed to create certificate: %v", err)
	}

	// Encode to PEM
	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	})

	return certPEM
}
