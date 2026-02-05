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
	"github.com/sigstore/model-signing/pkg/oci"
	"github.com/sigstore/model-signing/pkg/utils"
	"github.com/sigstore/model-signing/pkg/verify"
)

// Ensure SigstoreVerifier implements verify.ModelVerifier at compile time.
var _ verify.ModelVerifier = (*SigstoreVerifier)(nil)

// SigstoreVerifierOptions contains options for high-level Sigstore verification.
//
//nolint:revive
type SigstoreVerifierOptions struct {
	ModelPath           string        // ModelPath is the path to the model directory or file to verify.
	SignaturePath       string        // SignaturePath is the path to the signature file.
	IgnorePaths         []string      // IgnorePaths specifies paths to exclude from verification.
	IgnoreGitPaths      bool          // IgnoreGitPaths indicates whether to exclude git-ignored files.
	AllowSymlinks       bool          // AllowSymlinks indicates whether to follow symbolic links.
	UseStaging          bool          // UseStaging indicates whether to use Sigstore staging infrastructure.
	Identity            string        // Identity is the expected signer identity (email or URI).
	IdentityProvider    string        // IdentityProvider is the expected OIDC issuer URL.
	TrustConfigPath     string        // TrustConfigPath is an optional path to custom trust root configuration.
	IgnoreUnsignedFiles bool          // IgnoreUnsignedFiles allows verification to succeed even if extra files exist.
	Logger              logging.Logger // Logger is used for debug and info output.
}

// SigstoreVerifier provides high-level verification with validation.
// Implements the verify.ModelVerifier interface.
//
//nolint:revive
type SigstoreVerifier struct {
	opts   SigstoreVerifierOptions
	logger logging.Logger
}

// NewSigstoreVerifier creates a new high-level Sigstore verifier with validation.
// Validates that required paths and options are provided before returning.
// Returns an error if validation fails.
func NewSigstoreVerifier(opts SigstoreVerifierOptions) (*SigstoreVerifier, error) {
	// Validate if required paths exists
	if err := utils.ValidatePathExists("model path", opts.ModelPath); err != nil {
		return nil, err
	}
	if err := utils.ValidateFileExists("signature", opts.SignaturePath); err != nil {
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

	// Validate ignore paths only for non-OCI manifests
	// For OCI manifests, ignore paths refer to layer entries, not local files
	if !oci.IsOCIManifest(opts.ModelPath) {
		if err := utils.ValidateMultiple("ignore paths", opts.IgnorePaths, utils.PathTypeAny); err != nil {
			return nil, err
		}
	}

	// Validate trust config path if provided
	if err := utils.ValidateOptionalFile("trust config", opts.TrustConfigPath); err != nil {
		return nil, err
	}

	return &SigstoreVerifier{
		opts:   opts,
		logger: logging.EnsureLogger(opts.Logger),
	}, nil
}

// Verify performs the complete verification flow.
//
// Verification workflow:
// 1. Detects if the model path is an OCI manifest or a directory
// 2. Creates verifier config
// 3. For OCI manifests: verifies signature and compares with OCI layer digests
// 4. For directories: creates hashing config, hashes files, and compares
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

	// Create Sigstore verifier
	verifierConfig := SigstoreVerifierConfig{
		TrustRootConfig: config.TrustRootConfig{
			UseStaging:    sv.opts.UseStaging,
			TrustRootPath: sv.opts.TrustConfigPath,
		},
		Identity:   sv.opts.Identity,
		OIDCIssuer: sv.opts.IdentityProvider,
	}

	sigstoreVerifier, err := NewSigstoreBundleVerifier(verifierConfig)
	if err != nil {
		return verify.Result{}, fmt.Errorf("failed to create Sigstore verifier: %w", err)
	}

	// Use shared helper for verification
	return verify.VerifyModel(sigstoreVerifier, verify.VerifyOptions{
		ModelPath:           sv.opts.ModelPath,
		SignaturePath:       sv.opts.SignaturePath,
		IgnorePaths:         sv.opts.IgnorePaths,
		IgnoreGitPaths:      sv.opts.IgnoreGitPaths,
		AllowSymlinks:       sv.opts.AllowSymlinks,
		IgnoreUnsignedFiles: sv.opts.IgnoreUnsignedFiles,
	}, sv.logger)
}
