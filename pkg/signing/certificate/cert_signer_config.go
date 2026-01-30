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
	"crypto"
	"crypto/x509"
	"fmt"
	"os"

	internalcrypto "github.com/sigstore/model-signing/internal/crypto"
	"github.com/sigstore/model-signing/pkg/config"
	"github.com/sigstore/model-signing/pkg/dsse"
	"github.com/sigstore/model-signing/pkg/interfaces"
	"github.com/sigstore/model-signing/pkg/utils"
	protobundle "github.com/sigstore/protobuf-specs/gen/pb-go/bundle/v1"
	protocommon "github.com/sigstore/protobuf-specs/gen/pb-go/common/v1"
	"google.golang.org/protobuf/encoding/protojson"
)

// Ensure CertificateBundleSigner implements interfaces.BundleSigner at compile time.
var _ interfaces.BundleSigner = (*CertificateBundleSigner)(nil)

// Ensure CertificateBundle implements interfaces.SignatureBundle at compile time.
var _ interfaces.SignatureBundle = (*CertificateBundle)(nil)

// CertificateBundle wraps a protobuf bundle for certificate-based signatures.
//
// This type bypasses sigstore-go's bundle validation which rejects v0.3 bundles
// with X509 certificate chains. It serializes the protobuf bundle directly.
// nolint:revive
type CertificateBundle struct {
	bundle *protobundle.Bundle
}

// NewCertificateBundle creates a new CertificateBundle from a protobuf bundle.
func NewCertificateBundle(bundle *protobundle.Bundle) *CertificateBundle {
	return &CertificateBundle{bundle: bundle}
}

// Write serializes the signature bundle to a file at the given path.
//
// The bundle is written in standard Sigstore JSON format with world-readable
// permissions (0644) as signature bundles are public artifacts.
func (s *CertificateBundle) Write(path string) error {
	// Marshal bundle to JSON using protojson for proper formatting
	jsonBytes, err := protojson.Marshal(s.bundle)
	if err != nil {
		return fmt.Errorf("failed to marshal bundle to JSON: %w", err)
	}

	// Write to file with appropriate permissions
	// Signature files should be world-readable (0644) as they are public artifacts
	//nolint:gosec // G306: Signature files are public, 0644 is intentional
	if err := os.WriteFile(path, jsonBytes, 0644); err != nil {
		return fmt.Errorf("failed to write signature file: %w", err)
	}

	return nil
}

// CertificateSignerConfig holds configuration for creating a certificate-based bundle signer.
//
//nolint:revive
type CertificateSignerConfig struct {
	// KeyConfig provides private key loading functionality.
	config.KeyConfig

	// SigningCertificatePath is the path to the PEM-encoded signing certificate.
	SigningCertificatePath string

	// CertificateChainPaths are paths to other certificates used to establish chain of trust.
	CertificateChainPaths []string
}

// CertificateBundleSigner signs model manifests using a private key and certificate.
// Implements the interfaces.BundleSigner interface.
// nolint:revive
type CertificateBundleSigner struct {
	config             CertificateSignerConfig
	privateKey         crypto.PrivateKey
	signingCertificate *x509.Certificate
	trustChain         []*x509.Certificate
}

// NewCertificateBundleSigner creates a new certificate-based bundle signer with the given configuration.
// Loads and validates the private key, signing certificate, and certificate chain.
// Validates that the signing certificate's public key matches the private key.
// Returns an error if key/certificate loading or validation fails.
func NewCertificateBundleSigner(cfg CertificateSignerConfig) (*CertificateBundleSigner, error) {
	// Load private key using shared configuration primitive
	privateKey, err := cfg.LoadPrivateKey()
	if err != nil {
		return nil, err
	}

	// Extract public key from private key
	publicKeyFromKey, err := config.ExtractPublicKey(privateKey)
	if err != nil {
		return nil, err
	}

	// Load signing certificate using shared utility
	signingCert, err := config.LoadCertificate(cfg.SigningCertificatePath)
	if err != nil {
		return nil, fmt.Errorf("failed to load signing certificate: %w", err)
	}

	// Validate that public key from certificate matches public key from private key
	if err := config.ValidatePublicKeysMatch(publicKeyFromKey, signingCert.PublicKey); err != nil {
		return nil, err
	}

	// Load certificate chain using shared utility
	trustChain, err := config.LoadCertificateChain(cfg.CertificateChainPaths)
	if err != nil {
		return nil, fmt.Errorf("failed to load certificate chain: %w", err)
	}

	return &CertificateBundleSigner{
		config:             cfg,
		privateKey:         privateKey,
		signingCertificate: signingCert,
		trustChain:         trustChain,
	}, nil
}

// Sign signs a payload and returns a signature bundle.
//
// Creates a DSSE envelope with the signed payload and wraps it
// in a Sigstore bundle format with X509 certificate chain verification material.
// Returns an error if serialization, signing, or bundle creation fails.
func (s *CertificateBundleSigner) Sign(payload *interfaces.Payload) (interfaces.SignatureBundle, error) {
	// Convert payload to JSON
	payloadJSON, err := payload.ToJSON()
	if err != nil {
		return nil, fmt.Errorf("failed to convert payload to JSON: %w", err)
	}

	// Compute PAE (Pre-Authentication Encoding) for DSSE using shared utility
	pae := internalcrypto.ComputePAE(utils.InTotoJSONPayloadType, payloadJSON)

	// Sign the PAE using shared utility
	signatureBytes, err := internalcrypto.SignWithKey(s.privateKey, pae)
	if err != nil {
		return nil, fmt.Errorf("failed to sign payload: %w", err)
	}

	// Create DSSE envelope using the shared dsse package
	envelope := dsse.CreateEnvelope(utils.InTotoJSONPayloadType, payloadJSON, signatureBytes)

	// Convert envelope to protobuf format
	protoEnvelope, err := envelope.ToProtobuf()
	if err != nil {
		return nil, fmt.Errorf("failed to convert envelope to protobuf: %w", err)
	}

	// Create Sigstore bundle with verification material
	// Note: We use protobuf bundle directly instead of sigstore-go's bundle.NewBundle()
	// because sigstore-go validates that v0.3 bundles cannot have X509 certificate chains.
	protoBundle := &protobundle.Bundle{
		MediaType:            utils.BundleMediaType,
		VerificationMaterial: s.createVerificationMaterial(),
		Content: &protobundle.Bundle_DsseEnvelope{
			DsseEnvelope: protoEnvelope,
		},
	}

	return NewCertificateBundle(protoBundle), nil
}

// createVerificationMaterial creates the verification material for the bundle.
//
// Includes the X509 certificate chain with the signing certificate followed
// by the trust chain certificates.
func (s *CertificateBundleSigner) createVerificationMaterial() *protobundle.VerificationMaterial {
	// Build the certificate chain: signing certificate first, then trust chain
	certificates := make([]*protocommon.X509Certificate, 0, 1+len(s.trustChain))

	// Add signing certificate
	certificates = append(certificates, &protocommon.X509Certificate{
		RawBytes: s.signingCertificate.Raw,
	})

	// Add trust chain certificates
	for _, cert := range s.trustChain {
		certificates = append(certificates, &protocommon.X509Certificate{
			RawBytes: cert.Raw,
		})
	}

	return &protobundle.VerificationMaterial{
		Content: &protobundle.VerificationMaterial_X509CertificateChain{
			X509CertificateChain: &protocommon.X509CertificateChain{
				Certificates: certificates,
			},
		},
	}
}
