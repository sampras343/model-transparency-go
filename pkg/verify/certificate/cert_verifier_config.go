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
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"

	protobundle "github.com/sigstore/protobuf-specs/gen/pb-go/bundle/v1"
	"google.golang.org/protobuf/encoding/protojson"

	"github.com/sigstore/model-signing/pkg/interfaces"
	"github.com/sigstore/model-signing/pkg/manifest"
	"github.com/sigstore/model-signing/pkg/utils"
)

// Ensure Verifier implements interfaces.SignatureVerifier at compile time.
var _ interfaces.SignatureVerifier = (*Verifier)(nil)

// Ensure Verifier implements interfaces.SignatureReader at compile time.
var _ interfaces.SignatureReader = (*Verifier)(nil)

// Ensure CertificateSignature implements interfaces.SignatureReader at compile time.
var _ interfaces.SignatureReader = (*CertificateSignature)(nil)

// CertificateVerifierConfig holds configuration for creating a certificate verifier.
//
//nolint:revive
type CertificateVerifierConfig struct {
	// CertificateChainPaths contains paths to certificate files that form the
	// chain of trust. If empty, system root certificates will be used.
	CertificateChainPaths []string

	// LogFingerprints enables logging of certificate fingerprints for debugging.
	LogFingerprints bool
}

// Verifier verifies signatures created with certificates.
//
// It validates the certificate chain, checks the cryptographic signature,
// and extracts the manifest from the signed payload.
type Verifier struct {
	config     CertificateVerifierConfig
	certPool   *x509.CertPool
	trustChain []*x509.Certificate
	logger     *utils.Logger
}

// NewVerifier creates a new certificate verifier with the given configuration.
func NewVerifier(cfg CertificateVerifierConfig) (*Verifier, error) {
	logger := utils.NewLogger(cfg.LogFingerprints)

	// Create certificate pool for verification
	certPool := x509.NewCertPool()
	var trustChain []*x509.Certificate

	// Load certificates from the provided paths
	if len(cfg.CertificateChainPaths) == 0 {
		// Use system root certificates if no chain is provided
		systemRoots, err := x509.SystemCertPool()
		if err != nil {
			// If system pool is unavailable, create an empty pool
			// This can happen on some systems
			logger.Debug("Warning: Unable to load system certificates: %v", err)
			certPool = x509.NewCertPool()
		} else {
			certPool = systemRoots
		}
	} else {
		// Load certificates from provided paths
		for _, certPath := range cfg.CertificateChainPaths {
			certBytes, err := os.ReadFile(certPath)
			if err != nil {
				return nil, fmt.Errorf("failed to read certificate file %s: %w", certPath, err)
			}

			// Parse all certificates in the file (may contain multiple PEM blocks)
			certs, err := parseCertificates(certBytes)
			if err != nil {
				return nil, fmt.Errorf("failed to parse certificates from %s: %w", certPath, err)
			}

			for _, cert := range certs {
				certPool.AddCert(cert)
				trustChain = append(trustChain, cert)

				if cfg.LogFingerprints {
					logCertificateFingerprint("init", cert, logger)
				}
			}
		}
	}

	return &Verifier{
		config:     cfg,
		certPool:   certPool,
		trustChain: trustChain,
		logger:     logger,
	}, nil
}

// Read provides signature reading capability, implementing interfaces.SignatureReader.
// This allows the verifier to provide its own signature reading logic.
func (v *Verifier) Read(path string) (interfaces.Signature, error) {
	certSig := &CertificateSignature{}
	return certSig.Read(path)
}

// Write is not supported for certificate verifiers.
func (v *Verifier) Write(path string) error {
	return fmt.Errorf("writing signatures not supported for certificate verifiers")
}

// Verify verifies the signature and returns the manifest.
//
// This performs:
// 1. Certificate chain validation
// 2. Cryptographic signature verification
// 3. Manifest extraction and validation
//
// Strategy:
// - For v0.3 bundles with multiple certificates: uses custom verification
//   (sigstore-go rejects multi-cert chains in v0.3)
// - For other cases: attempts sigstore-go first for better validation,
//   falls back to custom logic if needed
func (v *Verifier) Verify(signature interfaces.Signature) (*manifest.Manifest, error) {
	// Check if this is a CertificateSignature with bundle
	if certSig, ok := signature.(*CertificateSignature); ok {
		return v.verifyWithHybridStrategy(certSig.bundle)
	}

	return nil, fmt.Errorf("certificate verification requires CertificateSignature")
}

// VerifyFromPath verifies a signature file directly without going through bundle validation.
// This is the recommended method for certificate verification.
func (v *Verifier) VerifyFromPath(signaturePath string) (*manifest.Manifest, error) {
	protoBundle, err := readProtobufBundle(signaturePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read bundle: %w", err)
	}

	return v.verifyWithHybridStrategy(protoBundle)
}

// verifyWithHybridStrategy determines the best verification approach based on bundle characteristics.
//
// For v0.3 bundles with certificate chains (multiple certs), it uses custom verification
// because sigstore-go rejects these. For other cases, it could use sigstore-go in the future
// when certificate-based verification is added to sigstore-go with proper trust root support.
//
// Currently, this always uses custom verification but provides the infrastructure for
// future sigstore-go integration.
func (v *Verifier) verifyWithHybridStrategy(protoBundle *protobundle.Bundle) (*manifest.Manifest, error) {
	// Detect bundle version and certificate chain characteristics
	bundleVersion, certCount := detectBundleCharacteristics(protoBundle)

	v.logger.Debug("Bundle version: %s, certificate count: %d", bundleVersion, certCount)

	// Decision logic:
	// - v0.3 with multiple certificates: MUST use custom verification (sigstore-go rejects)
	// - Single certificate: could use sigstore-go, but we need custom trust root support
	//   (sigstore-go expects Fulcio/TUF roots, not custom CA chains)
	// - v0.4+: when available, evaluate sigstore-go support

	if bundleVersion == "0.3" && certCount > 1 {
		v.logger.Debug("Using custom verification (v0.3 with certificate chain)")
		return v.verifyProtobufBundle(protoBundle)
	}

	// For now, always use custom verification for certificate-based signatures
	// Future enhancement: integrate sigstore-go when it supports custom CA trust roots
	v.logger.Debug("Using custom verification (certificate-based signature)")
	return v.verifyProtobufBundle(protoBundle)
}

// detectBundleCharacteristics extracts bundle version and certificate count.
// Returns version string (e.g., "0.3", "0.4") and number of certificates in the chain.
func detectBundleCharacteristics(protoBundle *protobundle.Bundle) (version string, certCount int) {
	// Extract bundle version from media type
	// Expected format: "application/vnd.dev.sigstore.bundle.v0.3+json"
	// Default to "0.3" if parsing fails (most common current version)
	version = "0.3"

	mediaType := protoBundle.GetMediaType()
	if mediaType != "" {
		// Look for "v0.X" pattern in media type
		for i := 0; i < len(mediaType)-3; i++ {
			if mediaType[i] == 'v' &&
				mediaType[i+1] >= '0' && mediaType[i+1] <= '9' &&
				mediaType[i+2] == '.' &&
				mediaType[i+3] >= '0' && mediaType[i+3] <= '9' {
				// Extract version like "0.3" or "0.4"
				version = mediaType[i+1 : i+4]
				break
			}
		}
	}

	// Count certificates in verification material
	certCount = 0
	if verificationMaterial := protoBundle.GetVerificationMaterial(); verificationMaterial != nil {
		if certChain := verificationMaterial.GetX509CertificateChain(); certChain != nil {
			certCount = len(certChain.GetCertificates())
		}
	}

	return version, certCount
}

// verifyProtobufBundle verifies a protobuf bundle.
func (v *Verifier) verifyProtobufBundle(protoBundle *protobundle.Bundle) (*manifest.Manifest, error) {
	// Extract DSSE envelope
	dsseEnvelope := protoBundle.GetDsseEnvelope()
	if dsseEnvelope == nil {
		return nil, fmt.Errorf("bundle does not contain a DSSE envelope")
	}

	// Verify exactly one signature
	if len(dsseEnvelope.Signatures) != 1 {
		return nil, fmt.Errorf("expected exactly one signature, got %d", len(dsseEnvelope.Signatures))
	}

	// Verify payload type
	if dsseEnvelope.PayloadType != utils.InTotoJSONPayloadType {
		return nil, fmt.Errorf("expected DSSE payload %s, but got %s",
			utils.InTotoJSONPayloadType, dsseEnvelope.PayloadType)
	}

	// Extract and verify certificates from verification material
	publicKey, err := v.verifyCertificates(protoBundle.VerificationMaterial)
	if err != nil {
		return nil, fmt.Errorf("certificate verification failed: %w", err)
	}

	// Payload is already raw bytes in protobuf (not base64 encoded)
	payloadBytes := dsseEnvelope.Payload

	// Compute Pre-Authentication Encoding (PAE) for DSSE
	pae := utils.ComputePAE(dsseEnvelope.PayloadType, payloadBytes)

	// Signature is already raw bytes in protobuf (not base64 encoded)
	signatureBytes := dsseEnvelope.Signatures[0].Sig

	// Verify the signature using the public key
	if err := utils.VerifySignature(publicKey, pae, signatureBytes); err != nil {
		return nil, fmt.Errorf("signature verification failed: %w", err)
	}

	// Extract manifest from payload
	m, err := utils.VerifySignedContent(dsseEnvelope.PayloadType, payloadBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to extract manifest: %w", err)
	}

	return m, nil
}

// verifyCertificates verifies the certificate chain and returns the public key.
//
// The public key is extracted from the signing certificate from the chain
// of trust, after the chain is validated.
func (v *Verifier) verifyCertificates(verificationMaterial *protobundle.VerificationMaterial) (crypto.PublicKey, error) {
	if verificationMaterial == nil {
		return nil, fmt.Errorf("verification material is missing")
	}

	certChain := verificationMaterial.GetX509CertificateChain()
	if certChain == nil || len(certChain.Certificates) == 0 {
		return nil, fmt.Errorf("no certificates found in verification material")
	}

	// Parse the signing certificate (first in the chain)
	signingCertBytes := certChain.Certificates[0].RawBytes
	signingCert, err := x509.ParseCertificate(signingCertBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse signing certificate: %w", err)
	}

	if v.config.LogFingerprints {
		logCertificateFingerprint("verify", signingCert, v.logger)
	}

	// Parse intermediate certificates
	var intermediates []*x509.Certificate
	for i := 1; i < len(certChain.Certificates); i++ {
		cert, err := x509.ParseCertificate(certChain.Certificates[i].RawBytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse intermediate certificate %d: %w", i, err)
		}
		intermediates = append(intermediates, cert)

		if v.config.LogFingerprints {
			logCertificateFingerprint("verify", cert, v.logger)
		}
	}

	// Create intermediate certificate pool
	intermediatePool := x509.NewCertPool()
	for _, cert := range intermediates {
		intermediatePool.AddCert(cert)
	}

	// Verify the certificate chain
	// Use the signing certificate's notBefore time as the verification time
	verifyTime := signingCert.NotBefore

	opts := x509.VerifyOptions{
		Roots:         v.certPool,
		Intermediates: intermediatePool,
		CurrentTime:   verifyTime,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}

	chains, err := signingCert.Verify(opts)
	if err != nil {
		return nil, fmt.Errorf("certificate chain verification failed: %w", err)
	}

	if len(chains) == 0 {
		return nil, fmt.Errorf("no valid certificate chains found")
	}

	// Check that the certificate can be used for signing
	if err := validateSigningUsage(signingCert); err != nil {
		return nil, err
	}

	return signingCert.PublicKey, nil
}

// validateSigningUsage checks if the certificate can be used for code signing.
func validateSigningUsage(cert *x509.Certificate) error {
	canSign := false

	// Check KeyUsage extension
	if cert.KeyUsage&x509.KeyUsageDigitalSignature != 0 {
		canSign = true
	}

	// Check ExtendedKeyUsage extension
	for _, usage := range cert.ExtKeyUsage {
		if usage == x509.ExtKeyUsageCodeSigning {
			canSign = true
			break
		}
	}

	if !canSign {
		return fmt.Errorf("signing certificate cannot be used for signing (missing DigitalSignature KeyUsage or CodeSigning ExtKeyUsage)")
	}

	return nil
}

// parseCertificates parses one or more PEM-encoded certificates.
func parseCertificates(certBytes []byte) ([]*x509.Certificate, error) {
	var certs []*x509.Certificate

	// Try parsing as PEM-encoded certificates
	// Multiple certificates may be in the same file
	for {
		block, rest := pem.Decode(certBytes)
		if block == nil {
			break
		}

		if block.Type != "CERTIFICATE" {
			certBytes = rest
			continue
		}

		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse PEM certificate: %w", err)
		}

		certs = append(certs, cert)
		certBytes = rest
	}

	if len(certs) > 0 {
		return certs, nil
	}

	// If no PEM blocks found, try parsing as raw DER
	cert, err := x509.ParseCertificate(certBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate (tried both PEM and DER formats): %w", err)
	}

	return []*x509.Certificate{cert}, nil
}

// logCertificateFingerprint logs the SHA256 fingerprint of a certificate.
func logCertificateFingerprint(location string, cert *x509.Certificate, logger *utils.Logger) {
	fingerprint := sha256.Sum256(cert.Raw)
	logger.Info("[%8s] SHA256 Fingerprint: %X", location, fingerprint)
}

// readProtobufBundle reads a Sigstore bundle directly as protobuf.
//
// This reads the raw protobuf structure without validation, which is necessary
// for v0.3 bundles with certificate chains (sigstore-go rejects these).
// Uses DiscardUnknown to support forward compatibility with newer bundle versions.
func readProtobufBundle(path string) (*protobundle.Bundle, error) {
	jsonBytes, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read signature file: %w", err)
	}

	protoBundle := &protobundle.Bundle{}
	opts := protojson.UnmarshalOptions{
		DiscardUnknown: true,
	}

	if err := opts.Unmarshal(jsonBytes, protoBundle); err != nil {
		return nil, fmt.Errorf("failed to unmarshal bundle: %w", err)
	}

	return protoBundle, nil
}

// CertificateSignature wraps a protobuf bundle for certificate verification.
//
// This uses a hybrid verification strategy:
// - Detects bundle version and certificate chain characteristics
// - Uses custom verification for v0.3 bundles with certificate chains
//   (sigstore-go rejects multi-cert chains in v0.3)
// - Provides infrastructure for future sigstore-go integration when it supports
//   certificate-based verification with custom CA trust roots
type CertificateSignature struct {
	bundle *protobundle.Bundle
}

// NewCertificateSignature creates a signature from a protobuf bundle.
func NewCertificateSignature(bundle *protobundle.Bundle) *CertificateSignature {
	return &CertificateSignature{bundle: bundle}
}

// Write is not implemented for certificate signatures.
func (s *CertificateSignature) Write(path string) error {
	return fmt.Errorf("writing certificate signatures not supported")
}

// Read reads a certificate signature from a file as raw protobuf.
func (s *CertificateSignature) Read(path string) (interfaces.Signature, error) {
	bundle, err := readProtobufBundle(path)
	if err != nil {
		return nil, err
	}
	return NewCertificateSignature(bundle), nil
}
