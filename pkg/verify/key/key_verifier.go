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
	"github.com/sigstore/model-signing/pkg/utils"
	"github.com/sigstore/model-signing/pkg/verify"
)

// Ensure KeyVerifier implements verify.ModelVerifier at compile time.
var _ verify.ModelVerifier = (*KeyVerifier)(nil)

// KeyVerifierOptions contains options for high-level key-based verification.
type KeyVerifierOptions struct {
	ModelPath           string
	SignaturePath       string
	IgnorePaths         []string
	IgnoreGitPaths      bool
	AllowSymlinks       bool
	PublicKeyPath       string
	IgnoreUnsignedFiles bool
}

// KeyVerifier provides high-level verification with validation.
type KeyVerifier struct {
	opts KeyVerifierOptions
}

// NewKeyVerifier creates a new high-level key verifier with validation.
func NewKeyVerifier(opts KeyVerifierOptions) (*KeyVerifier, error) {
	// Validate if required paths exists
	if err := utils.ValidateFolderExists("model path", opts.ModelPath); err != nil {
		return nil, err
	}
	if err := utils.ValidateFileExists("signature", opts.SignaturePath); err != nil {
		return nil, err
	}
	if err := utils.ValidateFileExists("public key", opts.PublicKeyPath); err != nil {
		return nil, err
	}

	// Validate ignore paths using new validation utilities
	if err := utils.ValidateMultiple("ignore paths", opts.IgnorePaths, utils.PathTypeAny); err != nil {
		return nil, err
	}

	return &KeyVerifier{opts: opts}, nil
}

// Verify performs the complete verification flow.
//
// This orchestrates:
// 1. Creating a key-based verifier
// 2. Setting up hashing configuration
// 3. Verifying the signature cryptographically
// 4. Hashing the model files
// 5. Comparing actual vs expected manifests
func (kv *KeyVerifier) Verify(_ context.Context) (verify.Result, error) {
	// Print verification info
	fmt.Println("Key-based verification")
	fmt.Printf("  MODEL_PATH:              %s\n", filepath.Clean(kv.opts.ModelPath))
	fmt.Printf("  --signature:             %s\n", filepath.Clean(kv.opts.SignaturePath))
	fmt.Printf("  --ignore-paths:          %v\n", kv.opts.IgnorePaths)
	fmt.Printf("  --ignore-git-paths:      %v\n", kv.opts.IgnoreGitPaths)
	fmt.Printf("  --allow-symlinks:        %v\n", kv.opts.AllowSymlinks)
	fmt.Printf("  --public-key:            %v\n", filepath.Clean(kv.opts.PublicKeyPath))
	fmt.Printf("  --ignore-unsigned-files: %v\n", kv.opts.IgnoreUnsignedFiles)

	// Resolve ignore paths
	ignorePaths := kv.opts.IgnorePaths
	// Add signature path to ignore list
	ignorePaths = append(ignorePaths, kv.opts.SignaturePath)

	// Create key verifier
	verifierConfig := KeyVerifierConfig{
		PublicKeyPath: kv.opts.PublicKeyPath,
	}

	keyVerifier, err := NewVerifier(verifierConfig)
	if err != nil {
		return verify.Result{}, fmt.Errorf("failed to create key verifier: %w", err)
	}

	// Create hashing config
	// Note: We don't set specific hashing params here because the Config
	// will guess them from the signature's manifest
	hashingConfig := config.NewHashingConfig().
		SetIgnoredPaths(ignorePaths, kv.opts.IgnoreGitPaths).
		SetAllowSymlinks(kv.opts.AllowSymlinks)

	// Create verification config
	verifyConfig := config.NewVerifierConfig().
		SetVerifier(keyVerifier).
		SetHashingConfig(hashingConfig).
		SetIgnoreUnsignedFiles(kv.opts.IgnoreUnsignedFiles)

	// Perform verification
	if err := verifyConfig.Verify(kv.opts.ModelPath, kv.opts.SignaturePath); err != nil {
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
