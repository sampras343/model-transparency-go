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

// Package pkcs11 provides PKCS#11-based signing using sigstore-go with HSM support.
//
// This package enables signing ML models using hardware security modules (HSMs)
// or software tokens like SoftHSM2 via the PKCS#11 standard. It integrates with
// sigstore-go's native signing API through adapter types that wrap PKCS#11 keys
// and certificates.
//
// Key components:
//   - Keypair: Adapter implementing sigstore-go's Keypair interface for PKCS#11 keys
//   - ModelCertificateProvider: Adapter implementing CertificateProvider interface
//   - Context: Manages PKCS#11 module loading and key discovery via crypto11
//   - URI: Parser for RFC 7512 PKCS#11 URIs
//
// Supported key types: ECDSA (P-256, P-384), RSA (2048, 3072, 4096 bits)
package pkcs11

import (
	"context"
	"fmt"
	"path/filepath"

	"github.com/sigstore/model-signing/pkg/logging"
	"github.com/sigstore/model-signing/pkg/modelartifact"
	"github.com/sigstore/model-signing/pkg/signing"
	cert "github.com/sigstore/model-signing/pkg/signing/certificate"
	"github.com/sigstore/model-signing/pkg/utils"
	protobundle "github.com/sigstore/protobuf-specs/gen/pb-go/bundle/v1"
	sigstoresign "github.com/sigstore/sigstore-go/pkg/sign"
)

// Pkcs11SignerOptions configures a Pkcs11Signer instance.
//
//nolint:revive
type Pkcs11SignerOptions struct {
	ModelPath              string         // ModelPath is the path to the model directory or file to sign.
	SignaturePath          string         // SignaturePath is where the signature file will be written.
	IgnorePaths            []string       // IgnorePaths specifies paths to exclude from hashing.
	IgnoreGitPaths         bool           // IgnoreGitPaths indicates whether to exclude git-ignored files.
	AllowSymlinks          bool           // AllowSymlinks indicates whether to follow symbolic links.
	URI                    string         // URI is the PKCS#11 URI identifying the key. [required]
	ModulePaths            []string       // ModulePaths are additional directories to search for PKCS#11 modules.
	SigningCertificatePath string         // SigningCertificatePath is the path to the signing certificate (optional).
	CertificateChain       []string       // CertificateChain are paths to certificate chain files (optional).
	Logger                 logging.Logger // Logger is used for debug and info output.
}

// Pkcs11Signer implements ModelSigner using PKCS#11-based signing.
//
//nolint:revive
type Pkcs11Signer struct {
	opts   Pkcs11SignerOptions
	logger logging.Logger
}

// NewPkcs11Signer creates a new Pkcs11Signer with the given options.
// Validates that required paths exist and PKCS#11 URI format before returning.
// Returns an error if validation fails.
func NewPkcs11Signer(opts Pkcs11SignerOptions) (*Pkcs11Signer, error) {
	if err := signing.ValidateSignerPaths(opts.ModelPath, opts.IgnorePaths); err != nil {
		return nil, err
	}
	if opts.URI == "" {
		return nil, fmt.Errorf("PKCS#11 URI is required")
	}
	// Validate URI format per RFC 7512 before proceeding.
	if _, err := ParsePKCS11URI(opts.URI); err != nil {
		return nil, fmt.Errorf("invalid PKCS#11 URI: %w", err)
	}
	if opts.SigningCertificatePath != "" {
		if err := utils.ValidateFileExists("signing certificate", opts.SigningCertificatePath); err != nil {
			return nil, err
		}
	}
	if err := utils.ValidateMultiple("certificate chain", opts.CertificateChain, utils.PathTypeFile); err != nil {
		return nil, err
	}

	return &Pkcs11Signer{
		opts:   opts,
		logger: logging.EnsureLogger(opts.Logger),
	}, nil
}

// Sign performs the complete signing flow.
//
// Orchestrates:
//  1. Canonicalizing the model to create a manifest (via modelartifact)
//  2. Marshaling the manifest to an in-toto payload (via modelartifact)
//  3. Signing the payload with the PKCS#11 key via sigstore-go's sign.Bundle()
//  4. Writing the signature bundle to disk
//
// The PKCS#11 key is accessed via the URI parameter, which specifies the token,
// key object, and optional PIN. For certificate-based signing, the certificate
// is embedded in the bundle's verification material.
//
// Returns a Result with success status and message, or an error if any step fails.
func (s *Pkcs11Signer) Sign(ctx context.Context) (signing.Result, error) {
	// Print signing configuration (debug only)
	s.logger.Debugln("PKCS#11 Signing")
	s.logger.Debug("  MODEL_PATH:         %s", filepath.Clean(s.opts.ModelPath))
	s.logger.Debug("  --signature:        %s", filepath.Clean(s.opts.SignaturePath))
	s.logger.Debug("  --ignore-paths:     %v", s.opts.IgnorePaths)
	s.logger.Debug("  --ignore-git-paths: %v", s.opts.IgnoreGitPaths)
	s.logger.Debug("  --pkcs11-uri:       %v", SanitizeURI(s.opts.URI))
	s.logger.Debug("  --allow-symlinks:   %v", s.opts.AllowSymlinks)
	if s.opts.SigningCertificatePath != "" {
		s.logger.Debug("  --signing-cert:     %v", s.opts.SigningCertificatePath)
	}

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

	// Step 3: Create keypair, certificate provider (if needed), and sign with sigstore-go
	s.logger.Debugln("\nStep 3: Signing with PKCS#11 key...")
	keypair, err := NewKeypair(s.opts.URI, s.opts.ModulePaths)
	if err != nil {
		return signing.Result{
			Verified: false,
			Message:  fmt.Sprintf("Failed to load PKCS#11 keypair: %v", err),
		}, fmt.Errorf("failed to load PKCS#11 keypair: %w", err)
	}
	defer keypair.Close()

	content := &sigstoresign.DSSEData{
		Data:        payload,
		PayloadType: utils.InTotoJSONPayloadType,
	}

	var bundle *protobundle.Bundle
	if s.opts.SigningCertificatePath != "" {
		certProvider, err := cert.NewModelCertificateProvider(s.opts.SigningCertificatePath, keypair)
		if err != nil {
			return signing.Result{
				Verified: false,
				Message:  fmt.Sprintf("Failed to load certificate: %v", err),
			}, fmt.Errorf("failed to load certificate: %w", err)
		}

		bundle, err = sigstoresign.Bundle(content, keypair, sigstoresign.BundleOptions{
			CertificateProvider: certProvider,
			Context:             ctx,
		})
		if err != nil {
			return signing.Result{
				Verified: false,
				Message:  fmt.Sprintf("Failed to sign: %v", err),
			}, fmt.Errorf("failed to create signature bundle: %w", err)
		}
	} else {
		bundle, err = sigstoresign.Bundle(content, keypair, sigstoresign.BundleOptions{
			Context: ctx,
		})
		if err != nil {
			return signing.Result{
				Verified: false,
				Message:  fmt.Sprintf("Failed to sign: %v", err),
			}, fmt.Errorf("failed to create signature bundle: %w", err)
		}
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

	// Post-processing: If certificate is provided, always embed in x509CertificateChain format
	// for cross-platform compatibility. If chain certs are also provided, include them.
	if s.opts.SigningCertificatePath != "" {
		if err := cert.EmbedCertChainInBundleFile(s.opts.SignaturePath, s.opts.CertificateChain); err != nil {
			return signing.Result{
				Verified: false,
				Message:  fmt.Sprintf("Failed to embed certificate chain: %v", err),
			}, fmt.Errorf("failed to embed certificate chain: %w", err)
		}
		if len(s.opts.CertificateChain) > 0 {
			s.logger.Debug("  Embedded %d chain certificate(s) in bundle", len(s.opts.CertificateChain))
			s.logger.Warnln("WARNING: Bundle uses X509CertificateChain format (not sigstore-go native). " +
				"This format is used for certificate chain compatibility and is handled by " +
				"the custom verification path.")
		} else {
			s.logger.Debug("  Converted to X509CertificateChain format for cross-platform compatibility")
		}
	}

	s.logger.Debug("  Signature written to: %s", s.opts.SignaturePath)

	return signing.Result{
		Verified: true,
		Message:  fmt.Sprintf("Successfully signed model and saved signature to %s", s.opts.SignaturePath),
	}, nil
}
