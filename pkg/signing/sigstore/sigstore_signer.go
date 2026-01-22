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

package sigstore

import (
	"context"
	"fmt"
	"path/filepath"

	"github.com/sigstore/model-signing/pkg/config"
	"github.com/sigstore/model-signing/pkg/interfaces"
	"github.com/sigstore/model-signing/pkg/signing"
	"github.com/sigstore/model-signing/pkg/utils"
)

//nolint:revive
type SigstoreSignerOptions struct {
	ModelPath             string
	SignaturePath         string
	IgnorePaths           []string
	IgnoreGitPaths        bool
	AllowSymlinks         bool
	UseStaging            bool
	OAuthForceOob         bool
	UseAmbientCredentials bool
	IdentityToken         string
	ClientID              string
	ClientSecret          string
	TrustConfigPath       string
	Logger                *utils.Logger
}

//nolint:revive
type SigstoreSigner struct {
	opts   SigstoreSignerOptions
	logger *utils.Logger
}

func NewSigstoreSigner(opts SigstoreSignerOptions) (*SigstoreSigner, error) {
	// Validate if required paths exists
	if err := utils.ValidateFolderExists("model path", opts.ModelPath); err != nil {
		return nil, err
	}
	// Validate ignore paths
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

	return &SigstoreSigner{
		opts:   opts,
		logger: logger,
	}, nil
}

// Sign performs the complete signing flow.
//
// This orchestrates:
// 1. Hashing the model to create a manifest
// 2. Creating a payload from the manifest
// 3. Signing the payload with Sigstore
// 4. Writing the signature bundle to disk
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
	// Add signature path to ignore list so we don't try to hash it
	ignorePaths = append(ignorePaths, ss.opts.SignaturePath)

	// Step 1: Hash the model to create a manifest
	ss.logger.Debugln("\nStep 1: Hashing model...")
	hashingConfig := config.NewHashingConfig().
		SetIgnoredPaths(ignorePaths, ss.opts.IgnoreGitPaths).
		SetAllowSymlinks(ss.opts.AllowSymlinks)

	manifest, err := hashingConfig.Hash(ss.opts.ModelPath, nil)
	if err != nil {
		return signing.Result{
			Verified: false,
			Message:  fmt.Sprintf("Failed to hash model: %v", err),
		}, fmt.Errorf("failed to hash model: %w", err)
	}
	ss.logger.Debug("  Hashed %d files", len(manifest.ResourceDescriptors()))

	// Step 2: Create payload from manifest
	ss.logger.Debugln("\nStep 2: Creating signing payload...")
	payload, err := interfaces.NewPayload(manifest)
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
