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

package key

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
type KeySignerOptions struct {
	ModelPath      string
	SignaturePath  string
	IgnorePaths    []string
	IgnoreGitPaths bool
	AllowSymlinks  bool
	PrivateKeyPath string
	Password       string
}

//nolint:revive
type KeySigner struct {
	opts KeySignerOptions
}

func NewKeySigner(opts KeySignerOptions) (*KeySigner, error) {
	// Validate if required paths exists
	if err := utils.ValidateFolderExists("model path", opts.ModelPath); err != nil {
		return nil, err
	}
	if err := utils.ValidateFileExists("private key", opts.PrivateKeyPath); err != nil {
		return nil, err
	}
	// Validate ignore paths
	if err := utils.ValidateMultiple("ignore paths", opts.IgnorePaths, utils.PathTypeAny); err != nil {
		return nil, err
	}
	return &KeySigner{opts: opts}, nil
}

// Sign performs the complete signing flow.
//
// This orchestrates:
// 1. Hashing the model to create a manifest
// 2. Creating a payload from the manifest
// 3. Signing the payload with Key
// 4. Writing the signature bundle to disk
func (ss *KeySigner) Sign(_ context.Context) (signing.Result, error) {
	// Print signing configuration
	fmt.Println("Sigstore Signing")
	fmt.Printf("  MODEL_PATH:                 %s\n", filepath.Clean(ss.opts.ModelPath))
	fmt.Printf("  --signature:                %s\n", filepath.Clean(ss.opts.SignaturePath))
	fmt.Printf("  --ignore-paths:             %v\n", ss.opts.IgnorePaths)
	fmt.Printf("  --ignore-git-paths:         %v\n", ss.opts.IgnoreGitPaths)
	fmt.Printf("  --private-key:             %v\n", ss.opts.PrivateKeyPath)
	fmt.Printf("  --allow-symlinks:           %v\n", ss.opts.AllowSymlinks)
	fmt.Printf("  --password:           %v\n", utils.MaskToken(ss.opts.Password))

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

	// Step 3: Create key signer and sign the payload
	fmt.Println("\nStep 3: Signing with private key...")
	signerConfig := KeySignerConfig{
		PrivateKeyPath: ss.opts.PrivateKeyPath,
		Password:       ss.opts.Password,
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
	fmt.Println("  Signing successful")

	// Step 4: Write signature to disk
	fmt.Println("\nStep 4: Writing signature to disk...")
	if err := signature.Write(ss.opts.SignaturePath); err != nil {
		return signing.Result{
			Verified: false,
			Message:  fmt.Sprintf("Failed to write signature: %v", err),
		}, fmt.Errorf("failed to write signature: %w", err)
	}
	fmt.Printf("  Signature written to: %s\n", ss.opts.SignaturePath)

	return signing.Result{
		Verified: true,
		Message:  "Signing succeeded",
	}, nil
}
