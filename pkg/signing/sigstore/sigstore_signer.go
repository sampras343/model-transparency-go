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
}

//nolint:revive
type SigstoreSigner struct {
	opts SigstoreSignerOptions
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
	return &SigstoreSigner{opts: opts}, nil
}

// Sign performs the complete signing flow.
//
// This orchestrates:
// 1. Hashing the model to create a manifest
// 2. Creating a payload from the manifest
// 3. Signing the payload with Sigstore
// 4. Writing the signature bundle to disk
func (ss *SigstoreSigner) Sign(_ context.Context) (signing.Result, error) {
	// Print signing configuration
	fmt.Println("Sigstore Signing")
	fmt.Printf("  MODEL_PATH:                 %s\n", filepath.Clean(ss.opts.ModelPath))
	fmt.Printf("  --signature:                %s\n", filepath.Clean(ss.opts.SignaturePath))
	fmt.Printf("  --ignore-paths:             %v\n", ss.opts.IgnorePaths)
	fmt.Printf("  --ignore-git-paths:         %v\n", ss.opts.IgnoreGitPaths)
	fmt.Printf("  --allow-symlinks:           %v\n", ss.opts.AllowSymlinks)
	fmt.Printf("  --use-staging:              %v\n", ss.opts.UseStaging)
	fmt.Printf("  --oauth-force-oob:          %v\n", ss.opts.OAuthForceOob)
	fmt.Printf("  --use-ambient-credentials:  %v\n", ss.opts.UseAmbientCredentials)
	fmt.Printf("  --identity-token:           %v\n", utils.MaskToken(ss.opts.IdentityToken))
	fmt.Printf("  --client-id:                %v\n", ss.opts.ClientID)
	fmt.Printf("  --client-secret:            %v\n", utils.MaskToken(ss.opts.ClientSecret))
	fmt.Printf("  --trust-config:             %v\n", ss.opts.TrustConfigPath)

	// Resolve ignore paths
	ignorePaths := ss.opts.IgnorePaths
	// Add signature path to ignore list so we don't try to hash it
	ignorePaths = append(ignorePaths, ss.opts.SignaturePath)

	// Step 1: Hash the model to create a manifest
	fmt.Println("\nStep 1: Hashing model...")
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
	fmt.Printf("  Hashed %d files\n", len(manifest.ResourceDescriptors()))

	// Step 2: Create payload from manifest
	fmt.Println("\nStep 2: Creating signing payload...")
	payload, err := interfaces.NewPayload(manifest)
	if err != nil {
		return signing.Result{
			Verified: false,
			Message:  fmt.Sprintf("Failed to create payload: %v", err),
		}, fmt.Errorf("failed to create payload: %w", err)
	}

	// Step 3: Create Sigstore signer and sign the payload
	fmt.Println("\nStep 3: Signing with Sigstore...")
	signerConfig := SigstoreSignerConfig{
		UseAmbientCredentials: ss.opts.UseAmbientCredentials,
		UseStaging:            ss.opts.UseStaging,
		IdentityToken:         ss.opts.IdentityToken,
		OAuthForceOob:         ss.opts.OAuthForceOob,
		ClientID:              ss.opts.ClientID,
		ClientSecret:          ss.opts.ClientSecret,
		TrustRootPath:         ss.opts.TrustConfigPath,
	}

	signer, err := NewLocalSigner(signerConfig)
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
	fmt.Println("\nStep 4: Writing signature...")
	if err := signature.Write(ss.opts.SignaturePath); err != nil {
		return signing.Result{
			Verified: false,
			Message:  fmt.Sprintf("Failed to write signature: %v", err),
		}, fmt.Errorf("failed to write signature: %w", err)
	}

	fmt.Printf("\nSignature written to: %s\n", ss.opts.SignaturePath)

	return signing.Result{
		Verified: true,
		Message:  "Signing succeeded",
	}, nil
}

