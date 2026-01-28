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

// Package certificate provides local cert-based signing implementations.
package certificate

import (
	"context"
	"fmt"
	"path/filepath"

	"github.com/sigstore/model-signing/pkg/config"
	"github.com/sigstore/model-signing/pkg/oci"
	"github.com/sigstore/model-signing/pkg/signing"
	"github.com/sigstore/model-signing/pkg/utils"
)

// CertificateSignerOptions configures a CertificateSigner instance.
//
//nolint:revive
type CertificateSignerOptions struct {
	ModelPath              string        // ModelPath is the path to the model directory or file to sign.
	SignaturePath          string        // SignaturePath is where the signature file will be written.
	IgnorePaths            []string      // IgnorePaths specifies paths to exclude from hashing.
	IgnoreGitPaths         bool          // IgnoreGitPaths indicates whether to exclude git-ignored files.
	AllowSymlinks          bool          // AllowSymlinks indicates whether to follow symbolic links.
	PrivateKeyPath         string        // PrivateKeyPath is the path to the private key file.
	CertificateChain       []string      // CertificateChain is the list of certificate paths for signing.
	SigningCertificatePath string        // SigningCertificatePath is the path to the signing certificate, as a PEM-encoded file
	Logger                 *utils.Logger // Logger is used for debug and info output.
}

// CertificateSigner implements ModelSigner using local cert-based signing.
//
//nolint:revive
type CertificateSigner struct {
	opts   CertificateSignerOptions
	logger *utils.Logger
}

// NewCertificateSigner creates a new CertificateSigner with the given options.
// Validates that required paths exist before returning.
// Returns an error if validation fails.
func NewCertificateSigner(opts CertificateSignerOptions) (*CertificateSigner, error) {
	// Validate if required paths exists
	if err := utils.ValidatePathExists("model path", opts.ModelPath); err != nil {
		return nil, err
	}
	if err := utils.ValidateFileExists("private key", opts.PrivateKeyPath); err != nil {
		return nil, err
	}
	if err := utils.ValidateFileExists("signing certificate", opts.SigningCertificatePath); err != nil {
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

	return &CertificateSigner{
		opts:   opts,
		logger: logger,
	}, nil
}

// Sign performs the complete signing flow.
//
// Orchestrates:
// 1. Hashing the model to create a manifest
// 2. Creating a payload from the manifest
// 3. Signing the payload with the private key and signing cert
// 4. Writing the signature bundle to disk
//
// Returns a Result with success status and message, or an error if any step fails.
func (ss *CertificateSigner) Sign(_ context.Context) (signing.Result, error) {
	// Print signing configuration (debug only)
	ss.logger.Debugln("Certificate-based Signing")
	ss.logger.Debug("  MODEL_PATH:             %s", filepath.Clean(ss.opts.ModelPath))
	ss.logger.Debug("  --signature:            %s", filepath.Clean(ss.opts.SignaturePath))
	ss.logger.Debug("  --ignore-paths:         %v", ss.opts.IgnorePaths)
	ss.logger.Debug("  --ignore-git-paths:     %v", ss.opts.IgnoreGitPaths)
	ss.logger.Debug("  --private-key:          %v", ss.opts.PrivateKeyPath)
	ss.logger.Debug("  --allow-symlinks:       %v", ss.opts.AllowSymlinks)
	ss.logger.Debug("  --signing-certificate:  %v", ss.opts.SigningCertificatePath)
	ss.logger.Debug("  --certificate-chain:    %v", ss.opts.CertificateChain)

	// Step 1: Hash the model to create a manifest
	ss.logger.Debugln("\nStep 1: Hashing model...")
	modelManifest, _, err := signing.BuildManifest(signing.ManifestOptions{
		ModelPath:      ss.opts.ModelPath,
		IgnorePaths:    ss.opts.IgnorePaths,
		SignaturePath:  ss.opts.SignaturePath,
		IgnoreGitPaths: ss.opts.IgnoreGitPaths,
		AllowSymlinks:  ss.opts.AllowSymlinks,
	}, ss.logger)
	if err != nil {
		return signing.Result{
			Verified: false,
			Message:  fmt.Sprintf("Failed to build manifest: %v", err),
		}, err
	}

	// Step 2: Create payload from manifest
	ss.logger.Debugln("\nStep 2: Creating signing payload...")
	payload, err := signing.CreatePayload(modelManifest)
	if err != nil {
		return signing.Result{
			Verified: false,
			Message:  fmt.Sprintf("Failed to create payload: %v", err),
		}, err
	}

	// Step 3: Create certificate signer and sign the payload
	ss.logger.Debugln("\nStep 3: Signing with certificate...")
	signerConfig := CertificateSignerConfig{
		KeyConfig: config.KeyConfig{
			Path: ss.opts.PrivateKeyPath,
		},
		SigningCertificatePath: ss.opts.SigningCertificatePath,
		CertificateChainPaths:  ss.opts.CertificateChain,
	}

	signer, err := NewLocalCertificateSigner(signerConfig)
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
	if err := signing.WriteSignature(signature, ss.opts.SignaturePath); err != nil {
		return signing.Result{
			Verified: false,
			Message:  fmt.Sprintf("Failed to write signature: %v", err),
		}, err
	}
	ss.logger.Debug("  Signature written to: %s", ss.opts.SignaturePath)

	return signing.Result{
		Verified: true,
		Message:  fmt.Sprintf("Successfully signed model and saved signature to %s", ss.opts.SignaturePath),
	}, nil
}
