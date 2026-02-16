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

// Certificate provider adapter for PKCS#11 certificate-based signing.
//
// This file provides ModelCertificateProvider which implements sigstore-go's
// CertificateProvider interface, enabling certificate-based signing where the
// private key resides in an HSM but the certificate is loaded from a file.
package pkcs11

import (
	"context"
	"crypto/x509"
	"fmt"
	"os"

	sigstoresign "github.com/sigstore/sigstore-go/pkg/sign"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
)

// Ensure ModelCertificateProvider implements sigstore-go's CertificateProvider interface
var _ sigstoresign.CertificateProvider = (*ModelCertificateProvider)(nil)

// ModelCertificateProvider implements sigstore-go's CertificateProvider interface
// for PKCS#11 certificate-based signing. It provides the signing certificate
// from a PEM file.
type ModelCertificateProvider struct {
	certPath string
	cert     *x509.Certificate
}

// NewModelCertificateProvider creates a new certificate provider from a certificate file path.
// It loads and parses the certificate immediately to validate it.
func NewModelCertificateProvider(certPath string) (*ModelCertificateProvider, error) {
	// Load certificate file
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read signing certificate: %w", err)
	}

	// Parse certificate
	certs, err := cryptoutils.UnmarshalCertificatesFromPEM(certPEM)
	if err != nil || len(certs) == 0 {
		return nil, fmt.Errorf("failed to parse signing certificate: %w", err)
	}

	return &ModelCertificateProvider{
		certPath: certPath,
		cert:     certs[0], // Use the first certificate
	}, nil
}

// GetCertificate returns the DER-encoded certificate.
// This method is called by sigstore-go's sign.Bundle() to get the certificate
// for embedding in the bundle's verification material.
func (mcp *ModelCertificateProvider) GetCertificate(_ context.Context, _ sigstoresign.Keypair, _ *sigstoresign.CertificateProviderOptions) ([]byte, error) {
	return mcp.cert.Raw, nil
}
