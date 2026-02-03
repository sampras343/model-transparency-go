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

package pkcs11

import (
	"context"
	"fmt"
	"path/filepath"

	"github.com/sigstore/model-signing/pkg/config"
	"github.com/sigstore/model-signing/pkg/interfaces"
	"github.com/sigstore/model-signing/pkg/logging"
	"github.com/sigstore/model-signing/pkg/signing"
	"github.com/sigstore/model-signing/pkg/utils"
)

// Pkcs11SignerOptions configures a Pkcs11Signer instance.
//
//nolint:revive
type Pkcs11SignerOptions struct {
	ModelPath              string         // ModelPath is the path to the model directory or file to sign.
	SignaturePath          string         // SignaturePath is where the signature file will be written.
	IgnorePaths            []string       // IgnorePaths specifies paths to exclude from hashing.
	IgnoreGitPaths         bool           // IgnoreGitPaths indicates whether to exclude git-ignored files.
	AllowSymlinks          bool           // AllowSymlinks indicates whether to follow symbolic links.
	URI                    string         // URI is the PKCS#11 URI identifying the key. [required]
	ModulePaths            []string       // ModulePaths are additional directories to search for PKCS#11 modules.
	SigningCertificatePath string         // SigningCertificatePath is the path to the signing certificate (optional).
	CertificateChain       []string       // CertificateChain are paths to certificate chain files (optional).
	Logger                 logging.Logger // Logger is used for debug and info output.
}

// Pkcs11Signer implements ModelSigner using PKCS#11-based signing.
//
//nolint:revive
type Pkcs11Signer struct {
	opts   Pkcs11SignerOptions
	logger logging.Logger
}

// NewPkcs11Signer creates a new Pkcs11Signer with the given options.
// Validates that required paths exist before returning.
// Returns an error if validation fails.
func NewPkcs11Signer(opts Pkcs11SignerOptions) (*Pkcs11Signer, error) {
	// Validate if required paths exist
	if err := utils.ValidatePathExists("model path", opts.ModelPath); err != nil {
		return nil, err
	}
	if opts.URI == "" {
		return nil, fmt.Errorf("PKCS#11 URI is required")
	}

	// Validate certificate path if provided
	if opts.SigningCertificatePath != "" {
		if err := utils.ValidateFileExists("signing certificate", opts.SigningCertificatePath); err != nil {
			return nil, err
		}
	}

	// Validate certificate chain paths
	if err := utils.ValidateMultiple("certificate chain", opts.CertificateChain, utils.PathTypeFile); err != nil {
		return nil, err
	}

	// Validate ignore paths
	if err := utils.ValidateMultiple("ignore paths", opts.IgnorePaths, utils.PathTypeAny); err != nil {
		return nil, err
	}

	// Use provided logger or create a default non-verbose one
	logger := opts.Logger
	if logger == nil {
		logger = logging.NewLogger(false)
	}

	return &Pkcs11Signer{
		opts:   opts,
		logger: logger,
	}, nil
}

// Sign performs the complete signing flow using PKCS#11.
//
// Orchestrates:
// 1. Hashing the model to create a manifest
// 2. Creating a payload from the manifest
// 3. Signing the payload with the PKCS#11 key
// 4. Writing the signature bundle to disk
//
// Returns a Result with success status and message, or an error if any step fails.
func (ps *Pkcs11Signer) Sign(_ context.Context) (signing.Result, error) {
	// Log signing configuration
	ps.logger.Debug("PKCS#11 signing: model=%s, signature=%s",
		filepath.Clean(ps.opts.ModelPath), filepath.Clean(ps.opts.SignaturePath))

	// Resolve ignore paths
	ignorePaths := ps.opts.IgnorePaths
	// Add signature path to ignore list
	ignorePaths = append(ignorePaths, ps.opts.SignaturePath)

	// Step 1: Hash the model
	hashingConfig := config.NewHashingConfig().
		SetIgnoredPaths(ignorePaths, ps.opts.IgnoreGitPaths).
		SetAllowSymlinks(ps.opts.AllowSymlinks)

	manifest, err := hashingConfig.Hash(ps.opts.ModelPath, nil)
	if err != nil {
		return signing.Result{}, fmt.Errorf("failed to hash model: %w", err)
	}
	ps.logger.Debug("Hashed %d files", len(manifest.ResourceDescriptors()))

	// Step 2: Create payload
	payload, err := interfaces.NewPayload(manifest)
	if err != nil {
		return signing.Result{}, fmt.Errorf("failed to create payload: %w", err)
	}

	// Step 3: Create PKCS#11 signer
	var signer interfaces.BundleSigner
	if ps.opts.SigningCertificatePath != "" {
		signer, err = NewCertSigner(
			ps.opts.URI,
			ps.opts.SigningCertificatePath,
			ps.opts.CertificateChain,
			ps.opts.ModulePaths,
		)
	} else {
		signer, err = NewSigner(ps.opts.URI, ps.opts.ModulePaths)
	}

	if err != nil {
		return signing.Result{}, fmt.Errorf("failed to create PKCS#11 signer: %w", err)
	}

	if closer, ok := signer.(interface{ Close() error }); ok {
		defer closer.Close()
	}

	signature, err := signer.Sign(payload)
	if err != nil {
		return signing.Result{}, fmt.Errorf("failed to sign payload: %w", err)
	}

	// Step 4: Write signature
	if err := signature.Write(ps.opts.SignaturePath); err != nil {
		return signing.Result{}, fmt.Errorf("failed to write signature: %w", err)
	}
	ps.logger.Debug("Signature written to: %s", ps.opts.SignaturePath)

	return signing.Result{
		Verified: true,
		Message:  fmt.Sprintf("Successfully signed model and saved signature to %s", ps.opts.SignaturePath),
	}, nil
}
