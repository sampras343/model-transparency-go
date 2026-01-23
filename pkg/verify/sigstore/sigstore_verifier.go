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
	Logger              *utils.Logger // Logger is used for debug and info output.
}

// SigstoreVerifier provides high-level verification with validation.
// Implements the verify.ModelVerifier interface.
//
//nolint:revive
type SigstoreVerifier struct {
	opts   SigstoreVerifierOptions
	logger *utils.Logger
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

	// Validate ignore paths using new validation utilities
	if err := utils.ValidateMultiple("ignore paths", opts.IgnorePaths, utils.PathTypeAny); err != nil {
		return nil, err
	}

	// Validate trust config path if provided
	if err := utils.ValidateOptionalFile("trust config", opts.TrustConfigPath); err != nil {
		return nil, err
	}

	// Use provided logger or create a default non-verbose one
	logger := opts.Logger
	if logger == nil {
		logger = utils.NewLogger(false)
	}

	return &SigstoreVerifier{
		opts:   opts,
		logger: logger,
	}, nil
}

// Verify performs the complete verification flow.
//
// Verification workflow:
// 1. Creates verifier config
// 2. Creates hashing config
// 3. Creates verification config
// 4. Executes verification
//
// Returns a Result with success status and message, or an error if verification fails.
//
//nolint:revive
func (sv *SigstoreVerifier) Verify(ctx context.Context) (verify.Result, error) {
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

	// Resolve ignore paths
	ignorePaths := sv.opts.IgnorePaths
	// Add signature path to ignore list
	ignorePaths = append(ignorePaths, sv.opts.SignaturePath)

	// Create Sigstore verifier
	verifierConfig := SigstoreVerifierConfig{
		TrustRootConfig: config.TrustRootConfig{
			UseStaging:    sv.opts.UseStaging,
			TrustRootPath: sv.opts.TrustConfigPath,
		},
		Identity:   sv.opts.Identity,
		OIDCIssuer: sv.opts.IdentityProvider,
	}

	sigstoreVerifier, err := NewVerifier(verifierConfig)
	if err != nil {
		return verify.Result{}, fmt.Errorf("failed to create Sigstore verifier: %w", err)
	}

	// Create hashing config
	// will guess them from the signature's manifest
	hashingConfig := config.NewHashingConfig().
		SetIgnoredPaths(ignorePaths, sv.opts.IgnoreGitPaths).
		SetAllowSymlinks(sv.opts.AllowSymlinks)

	// Create verification config
	verifyConfig := config.NewVerifierConfig().
		SetVerifier(sigstoreVerifier).
		SetHashingConfig(hashingConfig).
		SetIgnoreUnsignedFiles(sv.opts.IgnoreUnsignedFiles)

	// Perform verification
	if err := verifyConfig.Verify(sv.opts.ModelPath, sv.opts.SignaturePath); err != nil {
		return verify.Result{
			Verified: false,
			Message:  err.Error(),
		}, err
	}

	return verify.Result{
		Verified: true,
		Message:  "Verification succeeded",
	}, nil
}
