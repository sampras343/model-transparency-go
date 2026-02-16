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

// Package certificate provides certificate-based verification implementations.
package certificate

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/sigstore/model-signing/pkg/logging"
	"github.com/sigstore/model-signing/pkg/modelartifact"
	"github.com/sigstore/model-signing/pkg/utils"
	"github.com/sigstore/model-signing/pkg/verify"
	"github.com/sigstore/sigstore-go/pkg/bundle"
	sigstoreverify "github.com/sigstore/sigstore-go/pkg/verify"
	sigstoresig "github.com/sigstore/sigstore/pkg/signature"
)

// Ensure CertificateVerifier implements verify.ModelVerifier at compile time.
var _ verify.ModelVerifier = (*CertificateVerifier)(nil)

// CertificateVerifierOptions contains options for high-level certificate-based verification.
//
//nolint:revive
type CertificateVerifierOptions struct {
	ModelPath           string         // ModelPath is the path to the model directory or file to verify.
	SignaturePath       string         // SignaturePath is the path to the signature file.
	IgnorePaths         []string       // IgnorePaths specifies paths to exclude from verification.
	IgnoreGitPaths      bool           // IgnoreGitPaths indicates whether to exclude git-ignored files.
	AllowSymlinks       bool           // AllowSymlinks indicates whether to follow symbolic links.
	IgnoreUnsignedFiles bool           // IgnoreUnsignedFiles allows verification to succeed even if extra files exist.
	Logger              logging.Logger // Logger is used for debug and info output.
	CertificateChain    []string       // CertificateChain is the list of certificate paths for verification.
	LogFingerprints     bool           // LogFingerprints indicates whether to log certificate fingerprints.
}

// CertificateVerifier provides high-level verification with validation.
// Implements the verify.ModelVerifier interface.
//
// Extracts the signing certificate from the bundle, validates the certificate
// chain against user-provided CA certificates, then uses sigstore-go for
// DSSE signature verification via TrustedPublicKeyMaterial.
//
//nolint:revive
type CertificateVerifier struct {
	opts   CertificateVerifierOptions
	logger logging.Logger
}

// NewCertificateVerifier creates a new high-level certificate verifier with validation.
// Validates that required paths exist before returning.
// Returns an error if validation fails.
func NewCertificateVerifier(opts CertificateVerifierOptions) (*CertificateVerifier, error) {
	if err := verify.ValidateVerifierPaths(opts.ModelPath, opts.SignaturePath, opts.IgnorePaths); err != nil {
		return nil, err
	}

	// Validate certificate chains
	if err := utils.ValidateMultiple("certificate chain", opts.CertificateChain, utils.PathTypeFile); err != nil {
		return nil, err
	}

	return &CertificateVerifier{
		opts:   opts,
		logger: logging.EnsureLogger(opts.Logger),
	}, nil
}

// Verify performs the complete verification flow.
//
// Orchestrates:
// 1. Loading the signature bundle from disk
// 2. Extracting and validating the signing certificate from the bundle
// 3. Verifying the certificate chain against user-provided CA certificates
// 4. Verifying the cryptographic signature via sigstore-go
// 5. Extracting the verified payload and comparing with the re-canonicalized model
//
// Returns a Result with success status and message, or an error if verification fails.
func (cv *CertificateVerifier) Verify(_ context.Context) (verify.Result, error) {
	cv.logger.Debugln("Certificate-based verification")
	cv.logger.Debug("  MODEL_PATH:              %s", filepath.Clean(cv.opts.ModelPath))
	cv.logger.Debug("  --signature:             %s", filepath.Clean(cv.opts.SignaturePath))
	cv.logger.Debug("  --ignore-paths:          %v", cv.opts.IgnorePaths)
	cv.logger.Debug("  --ignore-git-paths:      %v", cv.opts.IgnoreGitPaths)
	cv.logger.Debug("  --allow-symlinks:        %v", cv.opts.AllowSymlinks)
	cv.logger.Debug("  --certificate-chain:     %v", cv.opts.CertificateChain)
	cv.logger.Debug("  --log-fingerprints:      %v", cv.opts.LogFingerprints)
	cv.logger.Debug("  --ignore-unsigned-files: %v", cv.opts.IgnoreUnsignedFiles)

	// Step 1: Load bundle and extract any intermediate certs from old bundles
	cv.logger.Debugln("\nStep 1: Loading signature bundle...")

	// Extract intermediate certs from raw bundle JSON before compat transforms
	// discard the x509CertificateChain. Old Python bundles embed the full chain.
	bundleIntermediateCerts, _ := verify.ExtractBundleCertChain(cv.opts.SignaturePath)
	if len(bundleIntermediateCerts) > 0 {
		cv.logger.Warnln("WARNING: Bundle uses X509CertificateChain format (not sigstore-go native). " +
			"Using custom verification path for certificate chain compatibility.")
	}

	bndl, err := verify.LoadBundle(cv.opts.SignaturePath)
	if err != nil {
		return verify.Result{
			Verified: false,
			Message:  fmt.Sprintf("Failed to load bundle: %v", err),
		}, err
	}

	// Step 2: Extract and verify signing certificate
	cv.logger.Debugln("\nStep 2: Verifying certificate chain...")
	signingCert, err := cv.extractAndVerifyCertificate(bndl, bundleIntermediateCerts)
	if err != nil {
		return verify.Result{
			Verified: false,
			Message:  fmt.Sprintf("Certificate verification failed: %v", err),
		}, fmt.Errorf("certificate verification failed: %w", err)
	}

	// Step 3: Verify cryptographic signature
	// Try sigstore-go first (works for key-based bundles). If it fails due to
	// certificate/key type mismatch (bundles with "certificate" verification
	// material), fall back to direct DSSE signature verification.
	cv.logger.Debugln("\nStep 3: Verifying signature...")
	if err := cv.verifySignature(bndl, signingCert); err != nil {
		return verify.Result{
			Verified: false,
			Message:  fmt.Sprintf("Signature verification failed: %v", err),
		}, fmt.Errorf("signature verification failed: %w", err)
	}

	// Step 4: Extract verified payload and compare with model
	if err := verify.ExtractAndCompareModel(bndl, cv.opts.ModelPath, cv.opts.SignaturePath, modelartifact.Options{
		IgnorePaths:    cv.opts.IgnorePaths,
		IgnoreGitPaths: cv.opts.IgnoreGitPaths,
		AllowSymlinks:  cv.opts.AllowSymlinks,
		Logger:         cv.logger,
	}, cv.opts.IgnoreUnsignedFiles, cv.logger); err != nil {
		return verify.Result{
			Verified: false,
			Message:  fmt.Sprintf("Model verification failed: %v", err),
		}, err
	}

	cv.logger.Debugln("  Verification successful")
	return verify.Result{
		Verified: true,
		Message:  "Verification succeeded",
	}, nil
}

// extractAndVerifyCertificate extracts the signing certificate from the bundle's
// verification material and validates it against the user-provided certificate chain.
func (cv *CertificateVerifier) extractAndVerifyCertificate(bndl *bundle.Bundle, bundleIntermediateCerts []*x509.Certificate) (*x509.Certificate, error) {
	// Get the verification content (certificate or public key)
	verificationContent, err := bndl.VerificationContent()
	if err != nil {
		return nil, fmt.Errorf("failed to get verification content: %w", err)
	}

	signingCert := verificationContent.Certificate()
	if signingCert == nil {
		return nil, fmt.Errorf("bundle does not contain a signing certificate")
	}

	if cv.opts.LogFingerprints {
		logCertificateFingerprint("verify", signingCert, cv.logger)
	}

	// Build trust pools from provided certificate chain
	rootPool, intermediatePool, err := cv.buildCertificatePools()
	if err != nil {
		return nil, err
	}

	// Add intermediate certs extracted from old Python bundles' x509CertificateChain.
	// The compat transform converts the chain to a singular certificate, discarding
	// intermediates. We recover them here so the chain can still be validated.
	for _, cert := range bundleIntermediateCerts {
		intermediatePool.AddCert(cert)
	}

	// Verify the certificate chain
	// Use the signing certificate's notBefore time as the verification time
	verifyTime := signingCert.NotBefore

	verifyOpts := x509.VerifyOptions{
		Roots:         rootPool,
		Intermediates: intermediatePool,
		CurrentTime:   verifyTime,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}

	chains, err := signingCert.Verify(verifyOpts)
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

	return signingCert, nil
}

// verifySignature verifies the DSSE signature in the bundle using the signing
// certificate's public key.
//
// Hybrid approach:
//  1. Try sigstore-go's verifier with TrustedPublicKeyMaterial (works when
//     bundle has publicKey verification material)
//  2. If sigstore-go rejects the bundle due to certificate/key type mismatch,
//     fall back to direct DSSE verification using the cert's public key
//  3. On direct DSSE verification failure, try paeCompat for v0.2 signatures
func (cv *CertificateVerifier) verifySignature(bndl *bundle.Bundle, signingCert *x509.Certificate) error {
	// Try sigstore-go verification first
	trustedMaterial, err := verify.CreateTrustedPublicKeyMaterial(signingCert.PublicKey)
	if err != nil {
		return fmt.Errorf("failed to create trusted material: %w", err)
	}

	verifier, err := sigstoreverify.NewVerifier(trustedMaterial,
		sigstoreverify.WithNoObserverTimestamps(),
	)
	if err != nil {
		return fmt.Errorf("failed to create verifier: %w", err)
	}

	policy := sigstoreverify.NewPolicy(
		sigstoreverify.WithoutArtifactUnsafe(),
		sigstoreverify.WithKey(),
	)

	_, err = verifier.Verify(bndl, policy)
	if err == nil {
		return nil
	}

	// If the error is NOT due to certificate/key type mismatch, it's a real
	// verification failure — return it directly.
	if !strings.Contains(err.Error(), "expected key signature") {
		return err
	}

	// Fall back to direct DSSE verification.
	cv.logger.Debugln("  Falling back to direct DSSE verification (certificate bundle)...")
	return verifyDSSEDirect(bndl, signingCert.PublicKey)
}

// verifyDSSEDirect verifies the DSSE envelope signature directly using a
// public key.
//
// It tries current PAE format first with the curve-specific hash, then falls
// back to paeCompat with hardcoded SHA256 for v0.2 signatures.
func verifyDSSEDirect(bndl *bundle.Bundle, pubKey crypto.PublicKey) error {
	dsseEnvelope := bndl.GetDsseEnvelope()
	if dsseEnvelope == nil {
		return fmt.Errorf("bundle does not contain a DSSE envelope")
	}

	if len(dsseEnvelope.Signatures) == 0 {
		return fmt.Errorf("DSSE envelope contains no signatures")
	}

	sigBytes := dsseEnvelope.Signatures[0].Sig

	// Try current PAE format with curve-specific hash
	paeBytes := dssePAE(dsseEnvelope.PayloadType, dsseEnvelope.Payload)
	sigVerifier, err := verify.CreateSignatureVerifier(pubKey)
	if err != nil {
		return fmt.Errorf("failed to create signature verifier: %w", err)
	}

	err = sigVerifier.VerifySignature(bytes.NewReader(sigBytes), bytes.NewReader(paeBytes))
	if err == nil {
		return nil
	}

	// Compatibility with v0.2 signatures (matching Python's pae_compat).
	// v0.2 had two bugs:
	// 1. Used "DSSEV1" (capital V) instead of "DSSEv1"
	// 2. Mixed Python bytes repr with str in f-string interpolation
	// Also, v0.2 hardcoded SHA256 for all curves
	compatPAE := dssePAECompat(dsseEnvelope.PayloadType, dsseEnvelope.Payload)
	compatVerifier, compatErr := createCompatSignatureVerifier(pubKey)
	if compatErr != nil {
		return err // Return original error if we can't create compat verifier
	}

	compatVerifyErr := compatVerifier.VerifySignature(bytes.NewReader(sigBytes), bytes.NewReader(compatPAE))
	if compatVerifyErr == nil {
		return nil
	}

	// Both attempts failed, return the original error
	return err
}

// dssePAE computes the Pre-Authenticated Encoding per DSSE v1.0 spec.
// Format: "DSSEv1" SP LEN(payloadType) SP payloadType SP LEN(payload) SP payload
//
// See https://github.com/secure-systems-lab/dsse/blob/v1.0.0/protocol.md
func dssePAE(payloadType string, payload []byte) []byte {
	prefix := fmt.Sprintf("DSSEv1 %d %s %d ",
		len(payloadType), payloadType, len(payload))
	return append([]byte(prefix), payload...)
}

// dssePAECompat computes the v0.2 buggy PAE encoding.
// Python v0.2 had: f"DSSEV1 {len(pt)} {pt} {len(payload)} {payload}"
// where payload (bytes) was interpolated into an f-string, producing
// its Python repr (b'...'). Also used capital V in "DSSEV1".
//
// Python bytes repr escapes: \n → \\n, \t → \\t, \r → \\r, \\ → \\\\
// and uses b'...' wrapping (single quotes for JSON payloads with no single quotes).
func dssePAECompat(payloadType string, payload []byte) []byte {
	// Replicate Python's bytes repr: b'<escaped_content>'
	payloadRepr := pythonBytesRepr(payload)
	paeStr := fmt.Sprintf("DSSEV1 %d %s %d %s",
		len(payloadType), payloadType, len(payload), payloadRepr)
	return []byte(paeStr)
}

// pythonBytesRepr replicates Python 3's repr() for bytes objects.
// For ASCII-safe JSON payloads, this escapes control characters and wraps
// in b'...' notation, matching what Python's f-string interpolation produces
// when a bytes object is embedded in a format string.
func pythonBytesRepr(data []byte) string {
	var buf bytes.Buffer
	buf.WriteString("b'")
	for _, b := range data {
		switch b {
		case '\\':
			buf.WriteString(`\\`)
		case '\'':
			buf.WriteString(`\'`)
		case '\t':
			buf.WriteString(`\t`)
		case '\n':
			buf.WriteString(`\n`)
		case '\r':
			buf.WriteString(`\r`)
		default:
			if b < 0x20 || b > 0x7e {
				fmt.Fprintf(&buf, `\x%02x`, b)
			} else {
				buf.WriteByte(b)
			}
		}
	}
	buf.WriteByte('\'')
	return buf.String()
}

// createCompatSignatureVerifier creates a verifier with hardcoded SHA256 hash
// for v0.2 compatibility. Python v0.2 used SHA256 for all ECDSA curves
// instead of the curve-specific hash.
func createCompatSignatureVerifier(pubKey crypto.PublicKey) (sigstoresig.Verifier, error) {
	switch k := pubKey.(type) {
	case *ecdsa.PublicKey:
		return sigstoresig.LoadECDSAVerifier(k, crypto.SHA256)
	case *rsa.PublicKey:
		return sigstoresig.LoadRSAPKCS1v15Verifier(k, crypto.SHA256)
	case ed25519.PublicKey:
		return sigstoresig.LoadED25519Verifier(k)
	default:
		return nil, fmt.Errorf("unsupported public key type: %T", pubKey)
	}
}

// buildCertificatePools creates the root and intermediate certificate pools
// from the user-provided certificate chain paths.
func (cv *CertificateVerifier) buildCertificatePools() (*x509.CertPool, *x509.CertPool, error) {
	rootPool := x509.NewCertPool()
	intermediatePool := x509.NewCertPool()

	if len(cv.opts.CertificateChain) == 0 {
		// Use system root certificates if no chain is provided
		systemRoots, err := x509.SystemCertPool()
		if err != nil {
			cv.logger.Debug("Warning: Unable to load system certificates: %v", err)
			return rootPool, intermediatePool, nil
		}
		return systemRoots, intermediatePool, nil
	}

	// Load certificates from provided paths
	for _, certPath := range cv.opts.CertificateChain {
		certBytes, err := os.ReadFile(certPath)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to read certificate file %s: %w", certPath, err)
		}

		certs, err := parseCertificates(certBytes)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to parse certificates from %s: %w", certPath, err)
		}

		for _, cert := range certs {
			if cv.opts.LogFingerprints {
				logCertificateFingerprint("init", cert, cv.logger)
			}

			// Add CA certificates to root pool, others to intermediates
			if cert.IsCA {
				rootPool.AddCert(cert)
			} else {
				intermediatePool.AddCert(cert)
			}
		}
	}

	return rootPool, intermediatePool, nil
}

// validateSigningUsage checks if the certificate can be used for code signing.
func validateSigningUsage(cert *x509.Certificate) error {
	canSign := cert.KeyUsage&x509.KeyUsageDigitalSignature != 0

	if !canSign {
		for _, usage := range cert.ExtKeyUsage {
			if usage == x509.ExtKeyUsageCodeSigning {
				canSign = true
				break
			}
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
func logCertificateFingerprint(location string, cert *x509.Certificate, logger logging.Logger) {
	fingerprint := sha256.Sum256(cert.Raw)
	logger.Info("[%8s] SHA256 Fingerprint: %X", location, fingerprint)
}
