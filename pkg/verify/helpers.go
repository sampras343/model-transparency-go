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

package verify

import (
	"fmt"

	"github.com/sigstore/model-signing/pkg/config"
	"github.com/sigstore/model-signing/pkg/interfaces"
	"github.com/sigstore/model-signing/pkg/oci"
	"github.com/sigstore/model-signing/pkg/utils"
)

// VerifyOptions contains options for verifying a model.
// nolint:revive
type VerifyOptions struct {
	ModelPath           string
	SignaturePath       string
	IgnorePaths         []string // Will be copied to avoid mutation
	IgnoreGitPaths      bool
	AllowSymlinks       bool
	IgnoreUnsignedFiles bool
}

// VerifyModel performs verification using the provided verifier, handling both OCI manifests and directories.
//
// This function:
// 1. Copies the ignore paths slice to avoid mutating the caller's slice
// 2. Adds the signature path to the ignore list
// 3. Detects whether the model is an OCI manifest or directory
// 4. Performs the appropriate verification
//
// Returns a Result indicating success or failure.
// nolint:revive
func VerifyModel(verifier interfaces.BundleVerifier, opts VerifyOptions, logger *utils.Logger) (Result, error) {
	// Copy ignore paths to avoid mutating caller's slice
	ignorePaths := append([]string{}, opts.IgnorePaths...)
	// Add signature path to ignore list
	ignorePaths = append(ignorePaths, opts.SignaturePath)

	// Check if the model path is an OCI manifest
	if oci.IsOCIManifest(opts.ModelPath) {
		if logger != nil {
			logger.Debug("  Detected OCI manifest: %s", opts.ModelPath)
		}

		// Load and validate OCI manifest
		ociManifest, err := oci.LoadAndValidateManifest(opts.ModelPath)
		if err != nil {
			return Result{
				Verified: false,
				Message:  fmt.Sprintf("Failed to load OCI manifest: %v", err),
			}, fmt.Errorf("failed to load OCI manifest: %w", err)
		}

		// Create verification config and verify OCI manifest with ignore paths
		verifyConfig := config.NewVerifierConfig().
			SetVerifier(verifier).
			SetIgnoreUnsignedFiles(opts.IgnoreUnsignedFiles)

		if err := verifyConfig.VerifyOCIManifestWithIgnore(ociManifest, opts.SignaturePath, true, ignorePaths); err != nil {
			return Result{
				Verified: false,
				Message:  err.Error(),
			}, err
		}

		return Result{
			Verified: true,
			Message:  "Verification succeeded (OCI manifest)",
		}, nil
	}

	// Standard directory verification
	hashingConfig := config.NewHashingConfig().
		SetIgnoredPaths(ignorePaths, opts.IgnoreGitPaths).
		SetAllowSymlinks(opts.AllowSymlinks)

	verifyConfig := config.NewVerifierConfig().
		SetVerifier(verifier).
		SetHashingConfig(hashingConfig).
		SetIgnoreUnsignedFiles(opts.IgnoreUnsignedFiles)

	if err := verifyConfig.Verify(opts.ModelPath, opts.SignaturePath); err != nil {
		return Result{
			Verified: false,
			Message:  err.Error(),
		}, err
	}

	return Result{
		Verified: true,
		Message:  "Verification succeeded",
	}, nil
}
