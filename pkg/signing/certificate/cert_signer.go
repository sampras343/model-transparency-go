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

// Package certificate provides local cert-based signing using sigstore-go.
package certificate

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/sigstore/model-signing/pkg/logging"
	"github.com/sigstore/model-signing/pkg/modelartifact"
	"github.com/sigstore/model-signing/pkg/signing"
	signingkey "github.com/sigstore/model-signing/pkg/signing/key"
	"github.com/sigstore/model-signing/pkg/utils"
	sigstoresign "github.com/sigstore/sigstore-go/pkg/sign"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
)

// Ensure CertificateSigner implements signing.ModelSigner at compile time.
var _ signing.ModelSigner = (*CertificateSigner)(nil)

// CertificateSignerOptions configures a CertificateSigner instance.
//
//nolint:revive
type CertificateSignerOptions struct {
	ModelPath              string         // ModelPath is the path to the model directory or file to sign.
	SignaturePath          string         // SignaturePath is where the signature file will be written.
	IgnorePaths            []string       // IgnorePaths specifies paths to exclude from hashing.
	IgnoreGitPaths         bool           // IgnoreGitPaths indicates whether to exclude git-ignored files.
	AllowSymlinks          bool           // AllowSymlinks indicates whether to follow symbolic links.
	Logger                 logging.Logger // Logger is used for debug and info output.
	PrivateKeyPath         string         // PrivateKeyPath is the path to the private key file.
	SigningCertificatePath string         // SigningCertificatePath is the path to the signing certificate PEM file.
	CertificateChain       []string       // CertificateChain is the list of certificate paths (kept for CLI compatibility).
}

// CertificateSigner implements ModelSigner using local cert-based signing.
//
// Uses sigstore-go's sign.Bundle() API with a ModelKeypair adapter for signing
// and a ModelCertificateProvider adapter for providing the signing certificate.
// The signing certificate is embedded in the bundle's verification material.
//
//nolint:revive
type CertificateSigner struct {
	opts   CertificateSignerOptions
	logger logging.Logger
}

// NewCertificateSigner creates a new CertificateSigner with the given options.
// Validates that required paths exist before returning.
// Returns an error if validation fails.
func NewCertificateSigner(opts CertificateSignerOptions) (*CertificateSigner, error) {
	if err := signing.ValidateSignerPaths(opts.ModelPath, opts.IgnorePaths); err != nil {
		return nil, err
	}
	if err := utils.ValidateFileExists("private key", opts.PrivateKeyPath); err != nil {
		return nil, err
	}
	if err := utils.ValidateFileExists("signing certificate", opts.SigningCertificatePath); err != nil {
		return nil, err
	}

	return &CertificateSigner{
		opts:   opts,
		logger: logging.EnsureLogger(opts.Logger),
	}, nil
}

// Sign performs the complete signing flow.
//
// Orchestrates:
// 1. Canonicalizing the model to create a manifest (via modelartifact)
// 2. Marshaling the manifest to an in-toto payload (via modelartifact)
// 3. Signing the payload with the private key and certificate via sigstore-go's sign.Bundle()
// 4. Writing the signature bundle to disk
//
// The bundle includes the signing certificate as verification material, allowing
// verifiers to validate the signature using the certificate chain.
//
// Returns a Result with success status and message, or an error if any step fails.
func (s *CertificateSigner) Sign(ctx context.Context) (signing.Result, error) {
	// Print signing configuration (debug only)
	s.logger.Debugln("Certificate-based Signing")
	s.logger.Debug("  MODEL_PATH:             %s", filepath.Clean(s.opts.ModelPath))
	s.logger.Debug("  --signature:            %s", filepath.Clean(s.opts.SignaturePath))
	s.logger.Debug("  --ignore-paths:         %v", s.opts.IgnorePaths)
	s.logger.Debug("  --ignore-git-paths:     %v", s.opts.IgnoreGitPaths)
	s.logger.Debug("  --private-key:          %v", s.opts.PrivateKeyPath)
	s.logger.Debug("  --allow-symlinks:       %v", s.opts.AllowSymlinks)
	s.logger.Debug("  --signing-certificate:  %v", s.opts.SigningCertificatePath)
	s.logger.Debug("  --certificate-chain:    %v", s.opts.CertificateChain)

	// Steps 1-2: Canonicalize the model and marshal payload
	_, payload, err := signing.PreparePayload(s.opts.ModelPath, s.opts.SignaturePath, modelartifact.Options{
		IgnorePaths:    s.opts.IgnorePaths,
		IgnoreGitPaths: s.opts.IgnoreGitPaths,
		AllowSymlinks:  s.opts.AllowSymlinks,
		Logger:         s.logger,
	}, s.logger)
	if err != nil {
		return signing.Result{
			Verified: false,
			Message:  fmt.Sprintf("Failed to prepare payload: %v", err),
		}, err
	}

	// Step 3: Create keypair, certificate provider, and sign with sigstore-go
	s.logger.Debugln("\nStep 3: Signing with certificate...")
	keypair, err := signingkey.NewModelKeypair(s.opts.PrivateKeyPath, "")
	if err != nil {
		return signing.Result{
			Verified: false,
			Message:  fmt.Sprintf("Failed to load keypair: %v", err),
		}, fmt.Errorf("failed to load keypair: %w", err)
	}

	certProvider, err := NewModelCertificateProvider(s.opts.SigningCertificatePath, keypair)
	if err != nil {
		return signing.Result{
			Verified: false,
			Message:  fmt.Sprintf("Failed to load certificate: %v", err),
		}, fmt.Errorf("failed to load certificate: %w", err)
	}

	content := &sigstoresign.DSSEData{
		Data:        payload,
		PayloadType: utils.InTotoJSONPayloadType,
	}

	bundle, err := sigstoresign.Bundle(content, keypair, sigstoresign.BundleOptions{
		CertificateProvider: certProvider,
		Context:             ctx,
	})
	if err != nil {
		return signing.Result{
			Verified: false,
			Message:  fmt.Sprintf("Failed to sign: %v", err),
		}, fmt.Errorf("failed to create signature bundle: %w", err)
	}
	s.logger.Debugln("  Signing successful")

	// Step 4: Write bundle to disk
	s.logger.Debugln("\nStep 4: Writing signature...")
	if err := signing.WriteBundle(bundle, s.opts.SignaturePath); err != nil {
		return signing.Result{
			Verified: false,
			Message:  fmt.Sprintf("Failed to write signature: %v", err),
		}, err
	}

	// If chain certs are provided, post-process the written bundle JSON to
	// embed the full certificate chain. sigstore-go's sign.Bundle() only
	// embeds the signing cert as a singular "certificate" field (v0.3 format).
	// We convert it to "x509CertificateChain" containing the signing cert
	// followed by the chain certs. The verifier's
	// compat layer converts this back to singular "certificate" for sigstore-go.
	if len(s.opts.CertificateChain) > 0 {
		if err := embedCertChainInBundleFile(s.opts.SignaturePath, s.opts.CertificateChain); err != nil {
			return signing.Result{
				Verified: false,
				Message:  fmt.Sprintf("Failed to embed certificate chain: %v", err),
			}, fmt.Errorf("failed to embed certificate chain: %w", err)
		}
		s.logger.Debug("  Embedded %d chain certificate(s) in bundle", len(s.opts.CertificateChain))
		s.logger.Warnln("WARNING: Bundle uses X509CertificateChain format (not sigstore-go native). " +
			"This format is used for certificate chain compatibility and is handled by " +
			"the custom verification path.")
	}

	s.logger.Debug("  Signature written to: %s", s.opts.SignaturePath)

	return signing.Result{
		Verified: true,
		Message:  fmt.Sprintf("Successfully signed model and saved signature to %s", s.opts.SignaturePath),
	}, nil
}

// embedCertChainInBundleFile post-processes a written bundle JSON file to replace
// the singular "certificate" verification material with "x509CertificateChain"
// containing the signing cert followed by the provided chain certificates.
//
// This is done at the JSON level (rather than protobuf level) because sigstore-go's
// bundle.NewBundle() rejects x509CertificateChain for v0.3 bundles. The verifier's
// compat layer (applyBundleCompat) converts it back to singular "certificate" before
// passing to sigstore-go, and ExtractBundleCertChain extracts the intermediates.
func embedCertChainInBundleFile(bundlePath string, chainPaths []string) error {
	data, err := os.ReadFile(bundlePath)
	if err != nil {
		return fmt.Errorf("failed to read bundle file: %w", err)
	}

	var raw map[string]interface{}
	if err := json.Unmarshal(data, &raw); err != nil {
		return fmt.Errorf("failed to parse bundle JSON: %w", err)
	}

	vm, ok := raw["verificationMaterial"].(map[string]interface{})
	if !ok {
		return fmt.Errorf("bundle has no verificationMaterial")
	}

	// Get the signing certificate from the current "certificate" field
	signingCert, ok := vm["certificate"].(map[string]interface{})
	if !ok {
		return fmt.Errorf("bundle has no certificate field")
	}

	// Build the chain: signing cert first, then chain certs
	chainCerts := []interface{}{signingCert}

	for _, chainPath := range chainPaths {
		pemBytes, err := os.ReadFile(chainPath)
		if err != nil {
			return fmt.Errorf("failed to read chain certificate %s: %w", chainPath, err)
		}

		certs, err := cryptoutils.UnmarshalCertificatesFromPEM(pemBytes)
		if err != nil {
			return fmt.Errorf("failed to parse chain certificate %s: %w", chainPath, err)
		}

		for _, cert := range certs {
			chainCerts = append(chainCerts, map[string]interface{}{
				"rawBytes": base64.StdEncoding.EncodeToString(cert.Raw),
			})
		}
	}

	// Replace "certificate" with "x509CertificateChain"
	delete(vm, "certificate")
	vm["x509CertificateChain"] = map[string]interface{}{
		"certificates": chainCerts,
	}

	out, err := json.MarshalIndent(raw, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal updated bundle: %w", err)
	}

	//nolint:gosec // G306: Signature files are public, 0644 is intentional
	if err := os.WriteFile(bundlePath, out, 0644); err != nil {
		return fmt.Errorf("failed to write updated bundle: %w", err)
	}

	return nil
}
