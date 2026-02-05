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
	"crypto/x509"
	"fmt"
	"os"

	"github.com/sigstore/model-signing/pkg/interfaces"
	"github.com/sigstore/model-signing/pkg/utils"
	bundle "github.com/sigstore/protobuf-specs/gen/pb-go/bundle/v1"
	common "github.com/sigstore/protobuf-specs/gen/pb-go/common/v1"
)

// CertSigner implements signing using PKCS#11 with certificates.
type CertSigner struct {
	*Signer
	signingCertificate *x509.Certificate
	trustChain         []*x509.Certificate
}

// NewCertSigner creates a new PKCS#11 certificate signer.
func NewCertSigner(
	pkcs11URI string,
	signingCertificatePath string,
	certificateChainPaths []string,
	modulePaths []string,
) (*CertSigner, error) {
	// Create base signer
	baseSigner, err := NewSigner(pkcs11URI, modulePaths)
	if err != nil {
		return nil, err
	}

	// Load signing certificate
	certData, err := os.ReadFile(signingCertificatePath)
	if err != nil {
		baseSigner.Close()
		return nil, fmt.Errorf("failed to read signing certificate: %w", err)
	}

	signingCert, err := utils.ParsePEMCertificate(certData)
	if err != nil {
		baseSigner.Close()
		return nil, fmt.Errorf("failed to parse signing certificate: %w", err)
	}

	// Verify that the certificate's public key matches the private key
	certPubKey, ok := signingCert.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		baseSigner.Close()
		return nil, fmt.Errorf("certificate public key is not an ECDSA key")
	}

	if !certPubKey.Equal(baseSigner.publicKey) {
		baseSigner.Close()
		return nil, fmt.Errorf("the public key from the certificate does not match the public key paired with the private key")
	}

	// Load trust chain certificates
	var trustChain []*x509.Certificate
	for _, certPath := range certificateChainPaths {
		certData, err := os.ReadFile(certPath)
		if err != nil {
			baseSigner.Close()
			return nil, fmt.Errorf("failed to read certificate chain file %s: %w", certPath, err)
		}

		certs, err := utils.ParsePEMCertificates(certData)
		if err != nil {
			baseSigner.Close()
			return nil, fmt.Errorf("failed to parse certificate chain file %s: %w", certPath, err)
		}

		trustChain = append(trustChain, certs...)
	}

	return &CertSigner{
		Signer:             baseSigner,
		signingCertificate: signingCert,
		trustChain:         trustChain,
	}, nil
}

// Sign signs the payload and returns a signature bundle with certificate chain.
func (s *CertSigner) Sign(payload *interfaces.Payload) (interfaces.SignatureBundle, error) {
	return s.signPayload(payload, s.getVerificationMaterial())
}

// getVerificationMaterial returns the verification material with certificate chain.
func (s *CertSigner) getVerificationMaterial() *bundle.VerificationMaterial {
	// Build certificate chain
	chain := []*common.X509Certificate{
		{
			RawBytes: s.signingCertificate.Raw,
		},
	}

	for _, cert := range s.trustChain {
		chain = append(chain, &common.X509Certificate{
			RawBytes: cert.Raw,
		})
	}

	return &bundle.VerificationMaterial{
		Content: &bundle.VerificationMaterial_X509CertificateChain{
			X509CertificateChain: &common.X509CertificateChain{
				Certificates: chain,
			},
		},
	}
}
