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

package certificate

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

	"github.com/sigstore/model-signing/pkg/logging"
)

// TestNewCertificateVerifier tests the creation of a certificate verifier.
func TestNewCertificateVerifier(t *testing.T) {
	tests := []struct {
		name    string
		opts    CertificateVerifierOptions
		wantErr bool
	}{
		{
			name: "missing model path",
			opts: CertificateVerifierOptions{
				ModelPath:     "",
				SignaturePath: "/tmp/signature.sig",
			},
			wantErr: true,
		},
		{
			name: "missing signature path",
			opts: CertificateVerifierOptions{
				ModelPath:     "/tmp/model",
				SignaturePath: "",
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NewCertificateVerifier(tt.opts)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewCertificateVerifier() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// TestCertificateVerifier_Verify tests the Verify method.
// Note: Full integration tests require actual certificates and signatures.
func TestCertificateVerifier_Verify(t *testing.T) {
	// This is a placeholder for integration tests
	// Actual tests would require setting up test certificates and signatures
	t.Skip("Integration test - requires test certificates and signatures")

	verifier := &CertificateVerifier{
		opts: CertificateVerifierOptions{
			ModelPath:        "/path/to/test/model",
			SignaturePath:    "/path/to/test/signature.sig",
			CertificateChain: []string{"/path/to/test/cert.pem"},
			LogFingerprints:  false,
		},
		logger: logging.NewLogger(false),
	}

	_, err := verifier.Verify(context.Background())
	if err != nil {
		t.Errorf("Verify() error = %v", err)
	}
}

func TestChainVerificationUsesNotBeforeWithoutTSA(t *testing.T) {
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test CA"},
		NotBefore:             time.Now().Add(-2 * 365 * 24 * time.Hour),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}

	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	// Expired leaf: validity ended 1 hour ago
	leafTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "Expired Leaf"},
		NotBefore:    time.Now().Add(-48 * time.Hour),
		NotAfter:     time.Now().Add(-1 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, caTemplate, &leafKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	leafCert, _ := x509.ParseCertificate(leafDER)

	// Write CA cert to temp file
	tmpDir := t.TempDir()
	caPath := filepath.Join(tmpDir, "ca.pem")
	caFile, _ := os.Create(caPath)
	_ = pem.Encode(caFile, &pem.Block{Type: "CERTIFICATE", Bytes: caDER})
	caFile.Close()

	cv := &CertificateVerifier{
		opts: CertificateVerifierOptions{
			CertificateChain: []string{caPath},
		},
		logger: logging.NewLogger(false),
	}

	rootPool, intermediatePool, err := cv.buildCertificatePools()
	if err != nil {
		t.Fatalf("buildCertificatePools failed: %v", err)
	}

	// Without TSA, verification uses NotBefore — expired certs still pass
	// (matches Python reference implementation behavior)
	_, err = leafCert.Verify(x509.VerifyOptions{
		Roots:         rootPool,
		Intermediates: intermediatePool,
		CurrentTime:   leafCert.NotBefore,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	})
	if err != nil {
		t.Fatalf("expected chain verification at NotBefore to pass, got: %v", err)
	}

	// With time.Now(), the same expired cert would fail
	_, err = leafCert.Verify(x509.VerifyOptions{
		Roots:         rootPool,
		Intermediates: intermediatePool,
		CurrentTime:   time.Now(),
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	})
	if err == nil {
		t.Fatal("expected chain verification at time.Now() to fail for expired cert, got nil")
	}
}

func TestParseTSAGenTime(t *testing.T) {
	// A valid timestamp should be parseable
	_, ok := parseTSAGenTime([]byte{})
	if ok {
		t.Fatal("expected parseTSAGenTime to return false for empty input")
	}

	_, ok = parseTSAGenTime([]byte{0x30, 0x03, 0x02, 0x01, 0x00})
	if ok {
		t.Fatal("expected parseTSAGenTime to return false for invalid ASN.1")
	}
}
