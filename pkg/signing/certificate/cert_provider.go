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
	"crypto/x509"
	"fmt"
	"os"

	"github.com/sigstore/sigstore-go/pkg/sign"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
)

// ModelCertificateProvider implements sigstore-go's sign.CertificateProvider
// interface by returning a pre-existing signing certificate (not from Fulcio).
// This enables certificate-based signing through sigstore-go's sign.Bundle() API.
type ModelCertificateProvider struct {
	// signingCertDER is the DER-encoded signing certificate.
	signingCertDER []byte
}

// NewModelCertificateProvider loads a signing certificate from a PEM file
// and validates that it matches the provided keypair's public key.
func NewModelCertificateProvider(certPath string, keypair sign.Keypair) (*ModelCertificateProvider, error) {
	cert, err := loadCertificateFromFile(certPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load signing certificate: %w", err)
	}

	// Validate that the certificate's public key matches the keypair
	if err := cryptoutils.EqualKeys(keypair.GetPublicKey(), cert.PublicKey); err != nil {
		return nil, fmt.Errorf("signing certificate does not match private key: %w", err)
	}

	return &ModelCertificateProvider{
		signingCertDER: cert.Raw,
	}, nil
}

// GetCertificate returns the DER-encoded signing certificate.
// This satisfies the sigstore-go sign.CertificateProvider interface.
func (p *ModelCertificateProvider) GetCertificate(_ context.Context, _ sign.Keypair, _ *sign.CertificateProviderOptions) ([]byte, error) {
	return p.signingCertDER, nil
}

// loadCertificateFromFile loads a single X509 certificate from a PEM file.
func loadCertificateFromFile(path string) (*x509.Certificate, error) {
	if path == "" {
		return nil, fmt.Errorf("certificate path is required")
	}

	pemBytes, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read certificate file %s: %w", path, err)
	}

	certs, err := cryptoutils.UnmarshalCertificatesFromPEM(pemBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate from %s: %w", path, err)
	}

	if len(certs) == 0 {
		return nil, fmt.Errorf("no certificates found in %s", path)
	}

	return certs[0], nil
}
