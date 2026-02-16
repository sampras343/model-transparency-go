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

// Package sigstore provides Sigstore-based verification implementations.
package sigstore

import (
	"context"
	"fmt"
	"net/url"
	"path/filepath"

	"github.com/sigstore/model-signing/pkg/config"
	"github.com/sigstore/model-signing/pkg/logging"
	"github.com/sigstore/model-signing/pkg/modelartifact"
	"github.com/sigstore/model-signing/pkg/utils"
	"github.com/sigstore/model-signing/pkg/verify"
	"github.com/sigstore/sigstore-go/pkg/root"
	sigstoreverify "github.com/sigstore/sigstore-go/pkg/verify"
)

// Ensure SigstoreVerifier implements verify.ModelVerifier at compile time.
var _ verify.ModelVerifier = (*SigstoreVerifier)(nil)

// SigstoreVerifierOptions contains options for high-level Sigstore verification.
//
//nolint:revive
type SigstoreVerifierOptions struct {
	ModelPath           string         // ModelPath is the path to the model directory or file to verify.
	SignaturePath       string         // SignaturePath is the path to the signature file.
	IgnorePaths         []string       // IgnorePaths specifies paths to exclude from verification.
	IgnoreGitPaths      bool           // IgnoreGitPaths indicates whether to exclude git-ignored files.
	AllowSymlinks       bool           // AllowSymlinks indicates whether to follow symbolic links.
	IgnoreUnsignedFiles bool           // IgnoreUnsignedFiles allows verification to succeed even if extra files exist.
	Logger              logging.Logger // Logger is used for debug and info output.
	UseStaging          bool           // UseStaging indicates whether to use Sigstore staging infrastructure.
	Identity            string         // Identity is the expected signer identity (email or URI).
	IdentityProvider    string         // IdentityProvider is the expected OIDC issuer URL.
	TrustConfigPath     string         // TrustConfigPath is an optional path to custom trust root configuration.
}

// SigstoreVerifier provides high-level verification with validation.
// Implements the verify.ModelVerifier interface.
//
// Uses sigstore-go's verify.NewVerifier() with a TUF-based TrustedRoot
// to verify the cryptographic signature and certificate identity, then
// compares the model manifest.
//
//nolint:revive
type SigstoreVerifier struct {
	opts      SigstoreVerifierOptions
	logger    logging.Logger
	trustRoot *root.TrustedRoot
}

// NewSigstoreVerifier creates a new high-level Sigstore verifier with validation.
// Validates that required paths and options are provided, and loads the trust root.
// Returns an error if validation or trust root loading fails.
func NewSigstoreVerifier(opts SigstoreVerifierOptions) (*SigstoreVerifier, error) {
	if err := verify.ValidateVerifierPaths(opts.ModelPath, opts.SignaturePath, opts.IgnorePaths); err != nil {
		return nil, err
	}

	// Validate identity is provided
	if opts.Identity == "" {
		return nil, fmt.Errorf("identity is required")
	}

	// Validate identity provider is a valid URL
	if opts.IdentityProvider == "" {
		return nil, fmt.Errorf("identity provider is required")
	}
	if _, err := url.ParseRequestURI(opts.IdentityProvider); err != nil {
		return nil, fmt.Errorf("invalid identity provider %q: %w", opts.IdentityProvider, err)
	}

	// Validate trust config path if provided
	if err := utils.ValidateOptionalFile("trust config", opts.TrustConfigPath); err != nil {
		return nil, err
	}

	// Load trust root
	trustRootConfig := config.TrustRootConfig{
		UseStaging:    opts.UseStaging,
		TrustRootPath: opts.TrustConfigPath,
	}

	trustRoot, err := trustRootConfig.LoadTrustRoot()
	if err != nil {
		return nil, fmt.Errorf("failed to load trust root: %w", err)
	}

	return &SigstoreVerifier{
		opts:      opts,
		logger:    logging.EnsureLogger(opts.Logger),
		trustRoot: trustRoot,
	}, nil
}

// Verify performs the complete verification flow.
//
// Orchestrates:
// 1. Loading the signature bundle from disk
// 2. Verifying the cryptographic signature and certificate identity via sigstore-go
// 3. Extracting the verified payload and comparing with the re-canonicalized model
//
// Returns a Result with success status and message, or an error if verification fails.
//
//nolint:revive
func (sv *SigstoreVerifier) Verify(_ context.Context) (verify.Result, error) {
	// Print verification info (debug only)
	sv.logger.Debugln("Sigstore verification")
	sv.logger.Debug("  MODEL_PATH:              %s", filepath.Clean(sv.opts.ModelPath))
	sv.logger.Debug("  --signature:             %s", filepath.Clean(sv.opts.SignaturePath))
	sv.logger.Debug("  --ignore-paths:          %v", sv.opts.IgnorePaths)
	sv.logger.Debug("  --ignore-git-paths:      %v", sv.opts.IgnoreGitPaths)
	sv.logger.Debug("  --allow-symlinks:        %v", sv.opts.AllowSymlinks)
	sv.logger.Debug("  --use-staging:           %v", sv.opts.UseStaging)
	sv.logger.Debug("  --identity:              %s", sv.opts.Identity)
	sv.logger.Debug("  --identity-provider:     %s", sv.opts.IdentityProvider)
	sv.logger.Debug("  --ignore-unsigned-files: %v", sv.opts.IgnoreUnsignedFiles)
	sv.logger.Debug("  --trust-config:          %v", sv.opts.TrustConfigPath)

	// Step 1: Load bundle
	sv.logger.Debugln("\nStep 1: Loading signature bundle...")
	bndl, err := verify.LoadBundle(sv.opts.SignaturePath)
	if err != nil {
		return verify.Result{
			Verified: false,
			Message:  fmt.Sprintf("Failed to load bundle: %v", err),
		}, err
	}

	// Step 2: Verify cryptographic signature with sigstore-go
	sv.logger.Debugln("\nStep 2: Verifying Sigstore signature...")

	// Create verifier with transparency log and integrated timestamp verification
	verifier, err := sigstoreverify.NewVerifier(sv.trustRoot,
		sigstoreverify.WithTransparencyLog(1),
		sigstoreverify.WithIntegratedTimestamps(1),
	)
	if err != nil {
		return verify.Result{
			Verified: false,
			Message:  fmt.Sprintf("Failed to create verifier: %v", err),
		}, fmt.Errorf("failed to create verifier: %w", err)
	}

	// Create certificate identity for verification
	certIdentity, err := sigstoreverify.NewShortCertificateIdentity(
		sv.opts.IdentityProvider, // issuer
		"",                       // issuer regex (empty = exact match)
		sv.opts.Identity,         // SAN value
		"",                       // SAN regex (empty = exact match)
	)
	if err != nil {
		return verify.Result{
			Verified: false,
			Message:  fmt.Sprintf("Failed to create certificate identity: %v", err),
		}, fmt.Errorf("failed to create certificate identity: %w", err)
	}

	// Build policy for identity verification
	policy := sigstoreverify.NewPolicy(
		sigstoreverify.WithoutArtifactUnsafe(),
		sigstoreverify.WithCertificateIdentity(certIdentity),
	)

	_, err = verifier.Verify(bndl, policy)
	if err != nil {
		return verify.Result{
			Verified: false,
			Message:  fmt.Sprintf("Signature verification failed: %v", err),
		}, fmt.Errorf("signature verification failed: %w", err)
	}

	// Step 3: Extract verified payload and compare with model
	if err := verify.ExtractAndCompareModel(bndl, sv.opts.ModelPath, sv.opts.SignaturePath, modelartifact.Options{
		IgnorePaths:    sv.opts.IgnorePaths,
		IgnoreGitPaths: sv.opts.IgnoreGitPaths,
		AllowSymlinks:  sv.opts.AllowSymlinks,
		Logger:         sv.logger,
	}, sv.opts.IgnoreUnsignedFiles, sv.logger); err != nil {
		return verify.Result{
			Verified: false,
			Message:  fmt.Sprintf("Model verification failed: %v", err),
		}, err
	}

	sv.logger.Debugln("  Verification successful")
	return verify.Result{
		Verified: true,
		Message:  "Verification succeeded",
	}, nil
}
