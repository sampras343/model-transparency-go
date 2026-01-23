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
	"context"
	"fmt"
	"path/filepath"

	"github.com/sigstore/model-signing/pkg/config"
	"github.com/sigstore/model-signing/pkg/utils"
	"github.com/sigstore/model-signing/pkg/verify"
)

// Ensure CertificateVerifier implements verify.ModelVerifier at compile time.
var _ verify.ModelVerifier = (*CertificateVerifier)(nil)

// CertificateVerifierOptions contains options for high-level certificate-based verification.
//
//nolint:revive
type CertificateVerifierOptions struct {
	ModelPath           string
	SignaturePath       string
	IgnorePaths         []string
	IgnoreGitPaths      bool
	AllowSymlinks       bool
	CertificateChain    []string
	IgnoreUnsignedFiles bool
	LogFingerprints     bool
	Logger              *utils.Logger
}

// CertificateVerifier provides high-level verification with validation.
//
//nolint:revive
type CertificateVerifier struct {
	opts   CertificateVerifierOptions
	logger *utils.Logger
}

// NewCertificateVerifier creates a new high-level certificate verifier with validation.
func NewCertificateVerifier(opts CertificateVerifierOptions) (*CertificateVerifier, error) {
	// Validate if required paths exists (model can be a file or folder)
	if err := utils.ValidatePathExists("model path", opts.ModelPath); err != nil {
		return nil, err
	}
	if err := utils.ValidateFileExists("signature", opts.SignaturePath); err != nil {
		return nil, err
	}

	// Validate ignore paths using new validation utilities
	if err := utils.ValidateMultiple("ignore paths", opts.IgnorePaths, utils.PathTypeAny); err != nil {
		return nil, err
	}

	// Validate certificate chains using new validation utilities
	if err := utils.ValidateMultiple("certificate chain", opts.CertificateChain, utils.PathTypeAny); err != nil {
		return nil, err
	}

	// Use provided logger or create a default non-verbose one
	logger := opts.Logger
	if logger == nil {
		logger = utils.NewLogger(false)
	}

	return &CertificateVerifier{
		opts:   opts,
		logger: logger,
	}, nil
}

// Verify performs the complete verification flow.
//
// This orchestrates:
// 1. Creating a certificate-based verifier
// 2. Setting up hashing configuration
// 3. Verifying the signature cryptographically
// 4. Hashing the model files
// 5. Comparing actual vs expected manifests
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

	// Resolve ignore paths
	ignorePaths := cv.opts.IgnorePaths
	// Add signature path to ignore list
	ignorePaths = append(ignorePaths, cv.opts.SignaturePath)

	// Create certificate verifier
	verifierConfig := CertificateVerifierConfig{
		CertificateChainPaths: cv.opts.CertificateChain,
		LogFingerprints:       cv.opts.LogFingerprints,
	}

	certVerifier, err := NewVerifier(verifierConfig)
	if err != nil {
		return verify.Result{}, fmt.Errorf("failed to create certificate verifier: %w", err)
	}

	// Create hashing config
	// will guess them from the signature's manifest
	hashingConfig := config.NewHashingConfig().
		SetIgnoredPaths(ignorePaths, cv.opts.IgnoreGitPaths).
		SetAllowSymlinks(cv.opts.AllowSymlinks)

	// Create verification config
	verifyConfig := config.NewVerifierConfig().
		SetVerifier(certVerifier).
		SetHashingConfig(hashingConfig).
		SetIgnoreUnsignedFiles(cv.opts.IgnoreUnsignedFiles)

	// Perform verification
	if err := verifyConfig.Verify(cv.opts.ModelPath, cv.opts.SignaturePath); err != nil {
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
