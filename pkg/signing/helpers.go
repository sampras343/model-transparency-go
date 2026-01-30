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

package signing

import (
	"fmt"

	"github.com/sigstore/model-signing/pkg/config"
	"github.com/sigstore/model-signing/pkg/interfaces"
	"github.com/sigstore/model-signing/pkg/manifest"
	"github.com/sigstore/model-signing/pkg/oci"
	"github.com/sigstore/model-signing/pkg/utils"
)

// ManifestOptions contains options for building a manifest from a model.
type ManifestOptions struct {
	ModelPath      string
	IgnorePaths    []string // Will be copied to avoid mutation
	SignaturePath  string   // Added to ignore list automatically
	IgnoreGitPaths bool
	AllowSymlinks  bool
}

// BuildManifest creates a manifest from a model, handling both OCI manifests and directories.
//
// This function:
// 1. Copies the ignore paths slice to avoid mutating the caller's slice
// 2. Adds the signature path to the ignore list
// 3. Detects whether the model is an OCI manifest or directory
// 4. Creates the appropriate manifest
//
// Returns the manifest and the resolved ignore paths (for logging purposes).
func BuildManifest(opts ManifestOptions, logger *utils.Logger) (*manifest.Manifest, []string, error) {
	// Copy ignore paths to avoid mutating caller's slice
	ignorePaths := append([]string{}, opts.IgnorePaths...)
	// Add signature path to ignore list
	ignorePaths = append(ignorePaths, opts.SignaturePath)

	// Check if the model path is an OCI manifest
	if oci.IsOCIManifest(opts.ModelPath) {
		if logger != nil {
			logger.Debug("  Detected OCI manifest: %s", opts.ModelPath)
		}

		ociManifest, err := oci.LoadManifest(opts.ModelPath)
		if err != nil {
			return nil, ignorePaths, fmt.Errorf("failed to load OCI manifest: %w", err)
		}

		// Validate the OCI manifest
		if err := ociManifest.Validate(); err != nil {
			return nil, ignorePaths, fmt.Errorf("invalid OCI manifest: %w", err)
		}

		// Create manifest from OCI layers with ignore paths
		modelName := oci.ModelNameFromPath(opts.ModelPath)
		modelManifest, err := oci.CreateManifestFromOCILayersWithIgnore(ociManifest, modelName, true, ignorePaths)
		if err != nil {
			return nil, ignorePaths, fmt.Errorf("failed to create manifest from OCI layers: %w", err)
		}

		if logger != nil {
			logger.Debug("  Created manifest from %d OCI layers", len(modelManifest.ResourceDescriptors()))
		}

		return modelManifest, ignorePaths, nil
	}

	// Standard model directory hashing
	hashingConfig := config.NewHashingConfig().
		SetIgnoredPaths(ignorePaths, opts.IgnoreGitPaths).
		SetAllowSymlinks(opts.AllowSymlinks)

	modelManifest, err := hashingConfig.Hash(opts.ModelPath, nil)
	if err != nil {
		return nil, ignorePaths, fmt.Errorf("failed to hash model: %w", err)
	}

	if logger != nil {
		logger.Debug("  Hashed %d files", len(modelManifest.ResourceDescriptors()))
	}

	return modelManifest, ignorePaths, nil
}

// CreatePayload creates a signing payload from a manifest.
func CreatePayload(m *manifest.Manifest) (*interfaces.Payload, error) {
	payload, err := interfaces.NewPayload(m)
	if err != nil {
		return nil, fmt.Errorf("failed to create payload: %w", err)
	}
	return payload, nil
}

// WriteSignature writes a signature bundle to the specified path.
func WriteSignature(bundle interfaces.SignatureBundle, path string) error {
	if err := bundle.Write(path); err != nil {
		return fmt.Errorf("failed to write signature bundle: %w", err)
	}
	return nil
}

// SignAndWrite signs a payload and writes the signature bundle to disk.
// This is a convenience function that combines signing and writing.
func SignAndWrite(signer interfaces.BundleSigner, payload *interfaces.Payload, signaturePath string) (interfaces.SignatureBundle, error) {
	bundle, err := signer.Sign(payload)
	if err != nil {
		return nil, fmt.Errorf("failed to sign payload: %w", err)
	}

	if err := WriteSignature(bundle, signaturePath); err != nil {
		return nil, err
	}

	return bundle, nil
}
