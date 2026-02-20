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

// Package key provides local key-based signing using sigstore-go.
package key

import (
	"context"
	"fmt"
	"path/filepath"

	"github.com/sigstore/model-signing/pkg/logging"
	"github.com/sigstore/model-signing/pkg/modelartifact"
	"github.com/sigstore/model-signing/pkg/signing"
	"github.com/sigstore/model-signing/pkg/utils"

	sigstoresign "github.com/sigstore/sigstore-go/pkg/sign"
)

// Ensure KeySigner implements signing.ModelSigner at compile time.
var _ signing.ModelSigner = (*KeySigner)(nil)

// KeySignerOptions configures a KeySigner instance.
//
//nolint:revive
type KeySignerOptions struct {
	ModelPath      string         // ModelPath is the path to the model directory or file to sign.
	SignaturePath  string         // SignaturePath is where the signature file will be written.
	IgnorePaths    []string       // IgnorePaths specifies paths to exclude from hashing.
	IgnoreGitPaths bool           // IgnoreGitPaths indicates whether to exclude git-ignored files.
	AllowSymlinks  bool           // AllowSymlinks indicates whether to follow symbolic links.
	Logger         logging.Logger // Logger is used for debug and info output.
	PrivateKeyPath string         // PrivateKeyPath is the path to the private key file.
	Password       string         // Password is the optional password for the private key.
}

// KeySigner implements ModelSigner using local private key-based signing.
//
// Uses sigstore-go's sign.Bundle() API with a ModelKeypair adapter that wraps
// the user-provided private key to satisfy sigstore-go's sign.Keypair interface.
//
//nolint:revive
type KeySigner struct {
	opts   KeySignerOptions
	logger logging.Logger
}

// NewKeySigner creates a new KeySigner with the given options.
// Validates that required paths exist before returning.
// Returns an error if validation fails.
func NewKeySigner(opts KeySignerOptions) (*KeySigner, error) {
	if err := signing.ValidateSignerPaths(opts.ModelPath, opts.IgnorePaths); err != nil {
		return nil, err
	}
	if err := utils.ValidateFileExists("private key", opts.PrivateKeyPath); err != nil {
		return nil, err
	}

	return &KeySigner{
		opts:   opts,
		logger: logging.EnsureLogger(opts.Logger),
	}, nil
}

// Sign performs the complete signing flow.
//
// Orchestrates:
// 1. Canonicalizing the model to create a manifest (via modelartifact)
// 2. Marshaling the manifest to an in-toto payload (via modelartifact)
// 3. Signing the payload with the private key via sigstore-go's sign.Bundle()
// 4. Writing the signature bundle to disk
//
// Returns a Result with success status and message, or an error if any step fails.
func (s *KeySigner) Sign(ctx context.Context) (signing.Result, error) {
	// Print signing configuration (debug only)
	s.logger.Debugln("Key-based Signing")
	s.logger.Debug("  MODEL_PATH:         %s", filepath.Clean(s.opts.ModelPath))
	s.logger.Debug("  --signature:        %s", filepath.Clean(s.opts.SignaturePath))
	s.logger.Debug("  --ignore-paths:     %v", s.opts.IgnorePaths)
	s.logger.Debug("  --ignore-git-paths: %v", s.opts.IgnoreGitPaths)
	s.logger.Debug("  --private-key:      %v", s.opts.PrivateKeyPath)
	s.logger.Debug("  --allow-symlinks:   %v", s.opts.AllowSymlinks)
	s.logger.Debug("  --password:         %v", utils.MaskToken(s.opts.Password))

	// Steps 1-2: Canonicalize the model and marshal payload
	_, payload, err := signing.PreparePayload(s.opts.ModelPath, s.opts.SignaturePath, modelartifact.Options{
		IgnorePaths:    s.opts.IgnorePaths,
		IgnoreGitPaths: s.opts.IgnoreGitPaths,
		AllowSymlinks:  s.opts.AllowSymlinks,
		Logger:         s.logger,
	}, s.logger)
	if err != nil {
		return signing.Result{
			Verified: false,
			Message:  fmt.Sprintf("Failed to prepare payload: %v", err),
		}, err
	}

	// Step 3: Create keypair and sign with sigstore-go
	s.logger.Debugln("\nStep 3: Signing with private key...")
	keypair, err := NewModelKeypair(s.opts.PrivateKeyPath, s.opts.Password)
	if err != nil {
		return signing.Result{
			Verified: false,
			Message:  fmt.Sprintf("Failed to load keypair: %v", err),
		}, fmt.Errorf("failed to load keypair: %w", err)
	}

	content := &sigstoresign.DSSEData{
		Data:        payload,
		PayloadType: utils.InTotoJSONPayloadType,
	}

	bundle, err := sigstoresign.Bundle(content, keypair, sigstoresign.BundleOptions{
		Context: ctx,
	})
	if err != nil {
		return signing.Result{
			Verified: false,
			Message:  fmt.Sprintf("Failed to sign: %v", err),
		}, fmt.Errorf("failed to create signature bundle: %w", err)
	}
	s.logger.Debugln("  Signing successful")

	// Step 4: Write bundle to disk
	s.logger.Debugln("\nStep 4: Writing signature...")
	if err := signing.WriteBundle(bundle, s.opts.SignaturePath); err != nil {
		return signing.Result{
			Verified: false,
			Message:  fmt.Sprintf("Failed to write signature: %v", err),
		}, err
	}
	s.logger.Debug("  Signature written to: %s", s.opts.SignaturePath)

	return signing.Result{
		Verified: true,
		Message:  fmt.Sprintf("Successfully signed model and saved signature to %s", s.opts.SignaturePath),
	}, nil
}
