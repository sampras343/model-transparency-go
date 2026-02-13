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
	"crypto/x509"
	"encoding/pem"
	"fmt"
)

// CheckSupportedECKey checks if the elliptic curve key is supported.
// Returns an error if the curve is not one of P-256, P-384, or P-521.
func CheckSupportedECKey(key *ecdsa.PublicKey) error {
	switch key.Curve {
	case elliptic.P256(), elliptic.P384(), elliptic.P521():
		return nil
	default:
		return fmt.Errorf("unsupported key for curve '%s'", key.Curve.Params().Name)
	}
}

// GetHashAlgorithm returns the appropriate hash algorithm for the given ECDSA key.
// The hash algorithm is matched to the curve: SHA256 for P-256, SHA384 for P-384,
// SHA512 for P-521. Defaults to SHA256 for unknown curves.
func GetHashAlgorithm(key *ecdsa.PublicKey) crypto.Hash {
	switch key.Curve {
	case elliptic.P256():
		return crypto.SHA256
	case elliptic.P384():
		return crypto.SHA384
	case elliptic.P521():
		return crypto.SHA512
	default:
		return crypto.SHA256
	}
}

// ParsePEMCertificate parses a single PEM-encoded X.509 certificate.
// Returns the parsed certificate or an error if parsing fails.
func ParsePEMCertificate(data []byte) (*x509.Certificate, error) {
	certs, err := ParsePEMCertificates(data)
	if err != nil {
		return nil, err
	}
	if len(certs) == 0 {
		return nil, fmt.Errorf("no certificates found in PEM data")
	}
	return certs[0], nil
}

// ParsePEMCertificates parses one or more PEM-encoded X.509 certificates.
// Returns a slice of parsed certificates or an error if parsing fails.
func ParsePEMCertificates(data []byte) ([]*x509.Certificate, error) {
	var certs []*x509.Certificate

	for len(data) > 0 {
		var block *pem.Block
		block, data = pem.Decode(data)
		if block == nil {
			break
		}

		if block.Type != "CERTIFICATE" {
			continue
		}

		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse certificate: %w", err)
		}

		certs = append(certs, cert)
	}

	if len(certs) == 0 {
		return nil, fmt.Errorf("no valid certificates found")
	}

	return certs, nil
}
