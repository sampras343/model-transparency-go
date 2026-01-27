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

// Package sigstore provides Sigstore/Fulcio-based signing implementations.
package sigstore

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

// SigstoreSignerOptions configures a SigstoreSigner instance.
//
//nolint:revive
type SigstoreSignerOptions struct {
	ModelPath             string        // ModelPath is the path to the model directory or file to sign.
	SignaturePath         string        // SignaturePath is where the signature file will be written.
	IgnorePaths           []string      // IgnorePaths specifies paths to exclude from hashing.
	IgnoreGitPaths        bool          // IgnoreGitPaths indicates whether to exclude git-ignored files.
	AllowSymlinks         bool          // AllowSymlinks indicates whether to follow symbolic links.
	UseStaging            bool          // UseStaging indicates whether to use Sigstore staging infrastructure.
	OAuthForceOob         bool          // OAuthForceOob forces out-of-band OAuth flow.
	UseAmbientCredentials bool          // UseAmbientCredentials uses ambient OIDC credentials instead of interactive OAuth.
	IdentityToken         string        // IdentityToken is a pre-obtained OIDC identity token.
	ClientID              string        // ClientID is the OAuth client ID.
	ClientSecret          string        // ClientSecret is the OAuth client secret.
	TrustConfigPath       string        // TrustConfigPath is an optional path to custom trust root configuration.
	Logger                *utils.Logger // Logger is used for debug and info output.
}

// SigstoreSigner implements ModelSigner using Sigstore/Fulcio signing.
//
//nolint:revive
type SigstoreSigner struct {
	opts   SigstoreSignerOptions
	logger *utils.Logger
}

// NewSigstoreSigner creates a new SigstoreSigner with the given options.
// Validates that required paths exist before returning.
// Returns an error if validation fails.
func NewSigstoreSigner(opts SigstoreSignerOptions) (*SigstoreSigner, error) {
	// Validate if required paths exists
	if err := utils.ValidatePathExists("model path", opts.ModelPath); err != nil {
		return nil, err
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

	// Use provided logger or create a default non-verbose one
	logger := opts.Logger
	if logger == nil {
		logger = utils.NewLogger(false)
	}

	return &SigstoreSigner{
		opts:   opts,
		logger: logger,
	}, nil
}

// Sign performs the complete signing flow.
//
// Orchestrates:
// 1. Hashing the model to create a manifest
// 2. Creating a payload from the manifest
// 3. Signing the payload with Sigstore (obtains ephemeral certificate via OIDC)
// 4. Writing the signature bundle to disk
//
// Returns a Result with success status and message, or an error if any step fails.
func (ss *SigstoreSigner) Sign(_ context.Context) (signing.Result, error) {
	// Print signing configuration (debug only)
	ss.logger.Debugln("Sigstore Signing")
	ss.logger.Debug("  MODEL_PATH:                %s", filepath.Clean(ss.opts.ModelPath))
	ss.logger.Debug("  --signature:               %s", filepath.Clean(ss.opts.SignaturePath))
	ss.logger.Debug("  --ignore-paths:            %v", ss.opts.IgnorePaths)
	ss.logger.Debug("  --ignore-git-paths:        %v", ss.opts.IgnoreGitPaths)
	ss.logger.Debug("  --allow-symlinks:          %v", ss.opts.AllowSymlinks)
	ss.logger.Debug("  --use-staging:             %v", ss.opts.UseStaging)
	ss.logger.Debug("  --oauth-force-oob:         %v", ss.opts.OAuthForceOob)
	ss.logger.Debug("  --use-ambient-credentials: %v", ss.opts.UseAmbientCredentials)
	ss.logger.Debug("  --identity-token:          %v", utils.MaskToken(ss.opts.IdentityToken))
	ss.logger.Debug("  --client-id:               %v", ss.opts.ClientID)
	ss.logger.Debug("  --client-secret:           %v", utils.MaskToken(ss.opts.ClientSecret))
	ss.logger.Debug("  --trust-config:            %v", ss.opts.TrustConfigPath)

	// Resolve ignore paths
	ignorePaths := ss.opts.IgnorePaths
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

	// Step 3: Create Sigstore signer and sign the payload
	ss.logger.Debugln("\nStep 3: Signing with Sigstore...")
	signerConfig := SigstoreSignerConfig{
		TrustRootConfig: config.TrustRootConfig{
			UseStaging:    ss.opts.UseStaging,
			TrustRootPath: ss.opts.TrustConfigPath,
		},
		UseAmbientCredentials: ss.opts.UseAmbientCredentials,
		IdentityToken:         ss.opts.IdentityToken,
		OAuthForceOob:         ss.opts.OAuthForceOob,
		ClientID:              ss.opts.ClientID,
		ClientSecret:          ss.opts.ClientSecret,
	}

	signer, err := NewLocalSigstoreSigner(signerConfig)
	if err != nil {
		return signing.Result{
			Verified: false,
			Message:  fmt.Sprintf("Failed to create signer: %v", err),
		}, fmt.Errorf("failed to create Sigstore signer: %w", err)
	}

	signature, err := signer.Sign(payload)
	if err != nil {
		return signing.Result{
			Verified: false,
			Message:  fmt.Sprintf("Failed to sign: %v", err),
		}, fmt.Errorf("failed to sign payload: %w", err)
	}

	// Step 4: Write signature to file
	ss.logger.Debugln("\nStep 4: Writing signature...")
	if err := signature.Write(ss.opts.SignaturePath); err != nil {
		return signing.Result{
			Verified: false,
			Message:  fmt.Sprintf("Failed to write signature: %v", err),
		}, fmt.Errorf("failed to write signature: %w", err)
	}

	ss.logger.Debug("\nSignature written to: %s", ss.opts.SignaturePath)

	return signing.Result{
		Verified: true,
		Message:  fmt.Sprintf("Successfully signed model and saved signature to %s", ss.opts.SignaturePath),
	}, nil
}
