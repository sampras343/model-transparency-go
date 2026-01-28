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

// Package key provides local key-based signing implementations.
package key

import (
	"context"
	"fmt"
	"path/filepath"

	"github.com/sigstore/model-signing/pkg/config"
	"github.com/sigstore/model-signing/pkg/interfaces"
	"github.com/sigstore/model-signing/pkg/manifest"
	"github.com/sigstore/model-signing/pkg/oci"
	"github.com/sigstore/model-signing/pkg/signing"
	"github.com/sigstore/model-signing/pkg/utils"
)

// KeySignerOptions configures a KeySigner instance.
//
//nolint:revive
type KeySignerOptions struct {
	ModelPath      string        // ModelPath is the path to the model directory or file to sign.
	SignaturePath  string        // SignaturePath is where the signature file will be written.
	IgnorePaths    []string      // IgnorePaths specifies paths to exclude from hashing.
	IgnoreGitPaths bool          // IgnoreGitPaths indicates whether to exclude git-ignored files.
	AllowSymlinks  bool          // AllowSymlinks indicates whether to follow symbolic links.
	PrivateKeyPath string        // PrivateKeyPath is the path to the private key file.
	Password       string        // Password is the optional password for the private key.
	Logger         *utils.Logger // Logger is used for debug and info output.
}

// KeySigner implements ModelSigner using local private key-based signing.
//
//nolint:revive
type KeySigner struct {
	opts   KeySignerOptions
	logger *utils.Logger
}

// NewKeySigner creates a new KeySigner with the given options.
// Validates that required paths exist before returning.
// Returns an error if validation fails.
func NewKeySigner(opts KeySignerOptions) (*KeySigner, error) {
	// Validate if required paths exists
	if err := utils.ValidatePathExists("model path", opts.ModelPath); err != nil {
		return nil, err
	}
	if err := utils.ValidateFileExists("private key", opts.PrivateKeyPath); err != nil {
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

	return &KeySigner{
		opts:   opts,
		logger: logger,
	}, nil
}

// Sign performs the complete signing flow.
//
// Orchestrates:
// 1. Hashing the model to create a manifest
// 2. Creating a payload from the manifest
// 3. Signing the payload with the private key
// 4. Writing the signature bundle to disk
//
// Returns a Result with success status and message, or an error if any step fails.
func (ss *KeySigner) Sign(_ context.Context) (signing.Result, error) {
	// Print signing configuration (debug only)
	ss.logger.Debugln("Key-based Signing")
	ss.logger.Debug("  MODEL_PATH:         %s", filepath.Clean(ss.opts.ModelPath))
	ss.logger.Debug("  --signature:        %s", filepath.Clean(ss.opts.SignaturePath))
	ss.logger.Debug("  --ignore-paths:     %v", ss.opts.IgnorePaths)
	ss.logger.Debug("  --ignore-git-paths: %v", ss.opts.IgnoreGitPaths)
	ss.logger.Debug("  --private-key:      %v", ss.opts.PrivateKeyPath)
	ss.logger.Debug("  --allow-symlinks:   %v", ss.opts.AllowSymlinks)
	ss.logger.Debug("  --password:         %v", utils.MaskToken(ss.opts.Password))

	// Resolve ignore paths
	ignorePaths := append([]string{}, ss.opts.IgnorePaths...)
	// Add signature path to ignore list
	ignorePaths = append(ignorePaths, ss.opts.SignaturePath)

	// Step 1: Hash the model to create a manifest
	ss.logger.Debugln("\nStep 1: Hashing model...")

	var modelManifest *manifest.Manifest
	var err error

	// Check if the model path is an OCI manifest
	if oci.IsOCIManifest(ss.opts.ModelPath) {
		ss.logger.Debug("  Detected OCI manifest: %s", ss.opts.ModelPath)

		ociManifest, loadErr := oci.LoadManifest(ss.opts.ModelPath)
		if loadErr != nil {
			return signing.Result{
				Verified: false,
				Message:  fmt.Sprintf("Failed to load OCI manifest: %v", loadErr),
			}, fmt.Errorf("failed to load OCI manifest: %w", loadErr)
		}

		// Validate the OCI manifest
		if validateErr := ociManifest.Validate(); validateErr != nil {
			return signing.Result{
				Verified: false,
				Message:  fmt.Sprintf("Invalid OCI manifest: %v", validateErr),
			}, fmt.Errorf("invalid OCI manifest: %w", validateErr)
		}

		// Create manifest from OCI layers with ignore paths
		modelName := oci.ModelNameFromPath(ss.opts.ModelPath)
		modelManifest, err = oci.CreateManifestFromOCILayersWithIgnore(ociManifest, modelName, true, ignorePaths)
		if err != nil {
			return signing.Result{
				Verified: false,
				Message:  fmt.Sprintf("Failed to create manifest from OCI layers: %v", err),
			}, fmt.Errorf("failed to create manifest from OCI layers: %w", err)
		}
		ss.logger.Debug("  Created manifest from %d OCI layers", len(modelManifest.ResourceDescriptors()))
	} else {
		// Standard model directory hashing
		hashingConfig := config.NewHashingConfig().
			SetIgnoredPaths(ignorePaths, ss.opts.IgnoreGitPaths).
			SetAllowSymlinks(ss.opts.AllowSymlinks)

		modelManifest, err = hashingConfig.Hash(ss.opts.ModelPath, nil)
		if err != nil {
			return signing.Result{
				Verified: false,
				Message:  fmt.Sprintf("Failed to hash model: %v", err),
			}, fmt.Errorf("failed to hash model: %w", err)
		}
		ss.logger.Debug("  Hashed %d files", len(modelManifest.ResourceDescriptors()))
	}

	// Step 2: Create payload from manifest
	ss.logger.Debugln("\nStep 2: Creating signing payload...")
	payload, err := interfaces.NewPayload(modelManifest)
	if err != nil {
		return signing.Result{
			Verified: false,
			Message:  fmt.Sprintf("Failed to create payload: %v", err),
		}, fmt.Errorf("failed to create payload: %w", err)
	}

	// Step 3: Create key signer and sign the payload
	ss.logger.Debugln("\nStep 3: Signing with private key...")
	signerConfig := KeySignerConfig{
		KeyConfig: config.KeyConfig{
			Path:     ss.opts.PrivateKeyPath,
			Password: ss.opts.Password,
		},
	}

	signer, err := NewLocalKeySigner(signerConfig)
	if err != nil {
		return signing.Result{
			Verified: false,
			Message:  fmt.Sprintf("Failed to create signer: %v", err),
		}, fmt.Errorf("failed to create signer: %w", err)
	}

	signature, err := signer.Sign(payload)
	if err != nil {
		return signing.Result{
			Verified: false,
			Message:  fmt.Sprintf("Failed to sign payload: %v", err),
		}, fmt.Errorf("failed to sign payload: %w", err)
	}
	ss.logger.Debugln("  Signing successful")

	// Step 4: Write signature to disk
	ss.logger.Debugln("\nStep 4: Writing signature to disk...")
	if err := signature.Write(ss.opts.SignaturePath); err != nil {
		return signing.Result{
			Verified: false,
			Message:  fmt.Sprintf("Failed to write signature: %v", err),
		}, fmt.Errorf("failed to write signature: %w", err)
	}
	ss.logger.Debug("  Signature written to: %s", ss.opts.SignaturePath)

	return signing.Result{
		Verified: true,
		Message:  fmt.Sprintf("Successfully signed model and saved signature to %s", ss.opts.SignaturePath),
	}, nil
}
