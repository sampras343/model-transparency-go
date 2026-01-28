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

// Package key provides local public key-based verification implementations.
package key

import (
	"context"
	"fmt"
	"path/filepath"

	"github.com/sigstore/model-signing/pkg/config"
	"github.com/sigstore/model-signing/pkg/oci"
	"github.com/sigstore/model-signing/pkg/utils"
	"github.com/sigstore/model-signing/pkg/verify"
)

// Ensure KeyVerifier implements verify.ModelVerifier at compile time.
var _ verify.ModelVerifier = (*KeyVerifier)(nil)

// KeyVerifierOptions contains options for high-level key-based verification.
//
//nolint:revive
type KeyVerifierOptions struct {
	ModelPath           string        // ModelPath is the path to the model directory or file to verify.
	SignaturePath       string        // SignaturePath is the path to the signature file.
	IgnorePaths         []string      // IgnorePaths specifies paths to exclude from verification.
	IgnoreGitPaths      bool          // IgnoreGitPaths indicates whether to exclude git-ignored files.
	AllowSymlinks       bool          // AllowSymlinks indicates whether to follow symbolic links.
	PublicKeyPath       string        // PublicKeyPath is the path to the public key file.
	IgnoreUnsignedFiles bool          // IgnoreUnsignedFiles allows verification to succeed even if extra files exist.
	Logger              *utils.Logger // Logger is used for debug and info output.
}

// KeyVerifier provides high-level verification with validation.
// Implements the verify.ModelVerifier interface.
//
//nolint:revive
type KeyVerifier struct {
	opts   KeyVerifierOptions
	logger *utils.Logger
}

// NewKeyVerifier creates a new high-level key verifier with validation.
// Validates that required paths exist before returning.
// Returns an error if validation fails.
func NewKeyVerifier(opts KeyVerifierOptions) (*KeyVerifier, error) {
	// Validate if required paths exists
	if err := utils.ValidatePathExists("model path", opts.ModelPath); err != nil {
		return nil, err
	}
	if err := utils.ValidateFileExists("signature", opts.SignaturePath); err != nil {
		return nil, err
	}
	if err := utils.ValidateFileExists("public key", opts.PublicKeyPath); err != nil {
		return nil, err
	}

	// Validate ignore paths only for non-OCI manifests
	// For OCI manifests, ignore paths refer to layer entries, not local files
	if !oci.IsOCIManifest(opts.ModelPath) {
		if err := utils.ValidateMultiple("ignore paths", opts.IgnorePaths, utils.PathTypeAny); err != nil {
			return nil, err
		}
	}

	// Use provided logger or create a default non-verbose one
	logger := opts.Logger
	if logger == nil {
		logger = utils.NewLogger(false)
	}

	return &KeyVerifier{
		opts:   opts,
		logger: logger,
	}, nil
}

// Verify performs the complete verification flow.
//
// Orchestrates:
// 1. Creates a key-based verifier
// 2. Sets up hashing configuration
// 3. Verifies the signature cryptographically
// 4. Hashes the model files
// 5. Compares actual vs expected manifests
//
// Returns a Result with success status and message, or an error if verification fails.
func (kv *KeyVerifier) Verify(_ context.Context) (verify.Result, error) {
	// Print verification info (debug only)
	kv.logger.Debugln("Key-based verification")
	kv.logger.Debug("  MODEL_PATH:              %s", filepath.Clean(kv.opts.ModelPath))
	kv.logger.Debug("  --signature:             %s", filepath.Clean(kv.opts.SignaturePath))
	kv.logger.Debug("  --ignore-paths:          %v", kv.opts.IgnorePaths)
	kv.logger.Debug("  --ignore-git-paths:      %v", kv.opts.IgnoreGitPaths)
	kv.logger.Debug("  --allow-symlinks:        %v", kv.opts.AllowSymlinks)
	kv.logger.Debug("  --public-key:            %v", filepath.Clean(kv.opts.PublicKeyPath))
	kv.logger.Debug("  --ignore-unsigned-files: %v", kv.opts.IgnoreUnsignedFiles)

	// Create key verifier
	verifierConfig := KeyVerifierConfig{
		KeyConfig: config.KeyConfig{
			Path: kv.opts.PublicKeyPath,
		},
	}

	keyVerifier, err := NewVerifier(verifierConfig)
	if err != nil {
		return verify.Result{}, fmt.Errorf("failed to create key verifier: %w", err)
	}

	// Use shared helper for verification
	return verify.VerifyModel(keyVerifier, verify.VerifyOptions{
		ModelPath:           kv.opts.ModelPath,
		SignaturePath:       kv.opts.SignaturePath,
		IgnorePaths:         kv.opts.IgnorePaths,
		IgnoreGitPaths:      kv.opts.IgnoreGitPaths,
		AllowSymlinks:       kv.opts.AllowSymlinks,
		IgnoreUnsignedFiles: kv.opts.IgnoreUnsignedFiles,
	}, kv.logger)
}
