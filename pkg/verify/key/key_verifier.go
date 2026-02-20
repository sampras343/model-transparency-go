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
	"crypto"
	"fmt"
	"path/filepath"

	"github.com/sigstore/model-signing/pkg/config"
	"github.com/sigstore/model-signing/pkg/logging"
	"github.com/sigstore/model-signing/pkg/modelartifact"
	"github.com/sigstore/model-signing/pkg/utils"
	"github.com/sigstore/model-signing/pkg/verify"
	sigstoreverify "github.com/sigstore/sigstore-go/pkg/verify"
)

// Ensure KeyVerifier implements verify.ModelVerifier at compile time.
var _ verify.ModelVerifier = (*KeyVerifier)(nil)

// KeyVerifierOptions contains options for high-level key-based verification.
//
//nolint:revive
type KeyVerifierOptions struct {
	ModelPath           string         // ModelPath is the path to the model directory or file to verify.
	SignaturePath       string         // SignaturePath is the path to the signature file.
	IgnorePaths         []string       // IgnorePaths specifies paths to exclude from verification.
	IgnoreGitPaths      bool           // IgnoreGitPaths indicates whether to exclude git-ignored files.
	AllowSymlinks       bool           // AllowSymlinks indicates whether to follow symbolic links.
	IgnoreUnsignedFiles bool           // IgnoreUnsignedFiles allows verification to succeed even if extra files exist.
	Logger              logging.Logger // Logger is used for debug and info output.
	PublicKeyPath       string         // PublicKeyPath is the path to the public key file.
}

// KeyVerifier provides high-level verification with validation.
// Implements the verify.ModelVerifier interface.
//
// Uses sigstore-go's verify.NewVerifier() with TrustedPublicKeyMaterial
// to verify the cryptographic signature, then compares the model manifest.
//
//nolint:revive
type KeyVerifier struct {
	opts   KeyVerifierOptions
	logger logging.Logger
}

// NewKeyVerifier creates a new high-level key verifier with validation.
// Validates that required paths exist before returning.
// Returns an error if validation fails.
func NewKeyVerifier(opts KeyVerifierOptions) (*KeyVerifier, error) {
	if err := verify.ValidateVerifierPaths(opts.ModelPath, opts.SignaturePath, opts.IgnorePaths); err != nil {
		return nil, err
	}
	if err := utils.ValidateFileExists("public key", opts.PublicKeyPath); err != nil {
		return nil, err
	}

	return &KeyVerifier{
		opts:   opts,
		logger: logging.EnsureLogger(opts.Logger),
	}, nil
}

// Verify performs the complete verification flow.
//
// Orchestrates:
// 1. Loading the signature bundle from disk
// 2. Loading the public key and creating a sigstore-go TrustedPublicKeyMaterial
// 3. Verifying the cryptographic signature via sigstore-go
// 4. Extracting the verified payload and comparing with the re-canonicalized model
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

	// Step 1: Load bundle
	kv.logger.Debugln("\nStep 1: Loading signature bundle...")
	bndl, err := verify.LoadBundle(kv.opts.SignaturePath)
	if err != nil {
		return verify.Result{
			Verified: false,
			Message:  fmt.Sprintf("Failed to load bundle: %v", err),
		}, err
	}

	// Step 2: Load public key and create trusted material
	kv.logger.Debugln("\nStep 2: Loading public key...")
	publicKey, err := loadPublicKey(kv.opts.PublicKeyPath)
	if err != nil {
		return verify.Result{
			Verified: false,
			Message:  fmt.Sprintf("Failed to load public key: %v", err),
		}, err
	}

	trustedMaterial, err := verify.CreateTrustedPublicKeyMaterial(publicKey)
	if err != nil {
		return verify.Result{
			Verified: false,
			Message:  fmt.Sprintf("Failed to create trusted material: %v", err),
		}, err
	}

	// Step 3: Verify cryptographic signature with sigstore-go
	kv.logger.Debugln("\nStep 3: Verifying signature...")
	verifier, err := sigstoreverify.NewVerifier(trustedMaterial,
		sigstoreverify.WithNoObserverTimestamps(),
	)
	if err != nil {
		return verify.Result{
			Verified: false,
			Message:  fmt.Sprintf("Failed to create verifier: %v", err),
		}, fmt.Errorf("failed to create verifier: %w", err)
	}

	policy := sigstoreverify.NewPolicy(
		sigstoreverify.WithoutArtifactUnsafe(),
		sigstoreverify.WithKey(),
	)

	_, err = verifier.Verify(bndl, policy)
	if err != nil {
		return verify.Result{
			Verified: false,
			Message:  fmt.Sprintf("Signature verification failed: %v", err),
		}, fmt.Errorf("signature verification failed: %w", err)
	}

	// Step 4: Extract verified payload and compare with model
	if err := verify.ExtractAndCompareModel(bndl, kv.opts.ModelPath, kv.opts.SignaturePath, modelartifact.Options{
		IgnorePaths:    kv.opts.IgnorePaths,
		IgnoreGitPaths: kv.opts.IgnoreGitPaths,
		AllowSymlinks:  kv.opts.AllowSymlinks,
		Logger:         kv.logger,
	}, kv.opts.IgnoreUnsignedFiles, kv.logger); err != nil {
		return verify.Result{
			Verified: false,
			Message:  fmt.Sprintf("Model verification failed: %v", err),
		}, err
	}

	kv.logger.Debugln("  Verification successful")
	return verify.Result{
		Verified: true,
		Message:  "Verification succeeded",
	}, nil
}

// loadPublicKey loads a public key from a PEM file using the config package.
func loadPublicKey(path string) (crypto.PublicKey, error) {
	keyConfig := config.KeyConfig{Path: path}
	return keyConfig.LoadPublicKey()
}
