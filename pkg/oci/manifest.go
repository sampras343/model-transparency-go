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

// Package oci provides types and functions for handling OCI (Open Container Initiative)
// manifests in the model signing workflow.
package oci

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/sigstore/model-signing/pkg/hashing/digests"
	"github.com/sigstore/model-signing/pkg/manifest"
)

// ImageManifest represents an OCI image manifest structure.
// See https://github.com/opencontainers/image-spec/blob/main/manifest.md
type ImageManifest struct {
	SchemaVersion int              `json:"schemaVersion"`
	MediaType     string           `json:"mediaType,omitempty"`
	Config        Descriptor       `json:"config"`
	Layers        []Descriptor     `json:"layers"`
	Annotations   map[string]string `json:"annotations,omitempty"`
}

// Descriptor describes a content-addressable blob.
type Descriptor struct {
	MediaType   string            `json:"mediaType"`
	Digest      string            `json:"digest"`
	Size        int64             `json:"size"`
	Annotations map[string]string `json:"annotations,omitempty"`
}

// ParseManifest parses an OCI manifest from JSON bytes.
func ParseManifest(data []byte) (*ImageManifest, error) {
	var m ImageManifest
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, fmt.Errorf("failed to parse OCI manifest: %w", err)
	}
	return &m, nil
}

// LoadManifest loads and parses an OCI manifest from a file path.
func LoadManifest(path string) (*ImageManifest, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read manifest file: %w", err)
	}
	return ParseManifest(data)
}

// Validate checks if the manifest is a valid OCI image manifest.
func (m *ImageManifest) Validate() error {
	// Check schema version (OCI image manifest uses version 2)
	if m.SchemaVersion != 2 {
		return fmt.Errorf("invalid schemaVersion: expected 2, got %d", m.SchemaVersion)
	}

	// Validate config descriptor
	if m.Config.Digest == "" {
		return fmt.Errorf("config descriptor missing digest")
	}
	if err := validateDigestFormat(m.Config.Digest); err != nil {
		return fmt.Errorf("invalid config digest: %w", err)
	}

	// Validate layers
	if len(m.Layers) == 0 {
		return fmt.Errorf("manifest must have at least one layer")
	}

	for i, layer := range m.Layers {
		if layer.Digest == "" {
			return fmt.Errorf("layer %d missing digest", i)
		}
		if err := validateDigestFormat(layer.Digest); err != nil {
			return fmt.Errorf("layer %d has invalid digest: %w", i, err)
		}
	}

	return nil
}

// validateDigestFormat checks if a digest string is in the correct format (algorithm:hex).
func validateDigestFormat(digest string) error {
	parts := strings.SplitN(digest, ":", 2)
	if len(parts) != 2 {
		return fmt.Errorf("digest must be in format 'algorithm:hex', got %q", digest)
	}

	algorithm := strings.ToLower(parts[0])
	hexValue := parts[1]

	// Validate algorithm
	switch algorithm {
	case "sha256", "sha384", "sha512", "blake2b256", "blake2b384", "blake2b512":
		// Valid algorithms
	default:
		return fmt.Errorf("unsupported digest algorithm: %s", algorithm)
	}

	// Validate hex value
	if _, err := hex.DecodeString(hexValue); err != nil {
		return fmt.Errorf("invalid hex value: %w", err)
	}

	return nil
}

// IsOCIManifest checks if a file path points to a valid OCI manifest.
// Returns true if the file is a JSON file containing OCI manifest structure.
func IsOCIManifest(path string) bool {
	// Check file extension
	if !strings.HasSuffix(strings.ToLower(path), ".json") {
		return false
	}

	// Check if file exists and is not a directory
	info, err := os.Stat(path)
	if err != nil || info.IsDir() {
		return false
	}

	// Try to load and validate
	m, err := LoadManifest(path)
	if err != nil {
		return false
	}

	// Basic structure check - must have layers or schemaVersion
	return len(m.Layers) > 0 || m.SchemaVersion > 0
}

// ModelNameFromPath extracts a model name from the manifest file path.
func ModelNameFromPath(path string) string {
	base := filepath.Base(path)
	ext := filepath.Ext(base)
	return strings.TrimSuffix(base, ext)
}

// shouldIgnoreLayer checks if a layer path should be ignored based on the ignore set.
// It matches against the full path and the base filename.
func shouldIgnoreLayer(layerPath string, ignoreSet map[string]bool) bool {
	// Check full path
	if ignoreSet[layerPath] {
		return true
	}
	// Check base filename
	if ignoreSet[filepath.Base(layerPath)] {
		return true
	}
	// Check for prefix matches (for paths like "dir/file.txt" matching "dir")
	for ignorePath := range ignoreSet {
		if strings.HasPrefix(layerPath, ignorePath+"/") {
			return true
		}
	}
	return false
}

// parseDigestString parses a digest string (e.g., "sha256:abc123") into a Digest.
func parseDigestString(digestStr string) (digests.Digest, error) {
	parts := strings.SplitN(digestStr, ":", 2)

	var algorithm, hexValue string
	if len(parts) == 2 {
		algorithm = strings.ToLower(parts[0])
		hexValue = parts[1]
	} else {
		// Default to sha256 if no algorithm prefix
		algorithm = "sha256"
		hexValue = digestStr
	}

	digestValue, err := hex.DecodeString(hexValue)
	if err != nil {
		return digests.Digest{}, fmt.Errorf("invalid hex digest value in %q: %w", digestStr, err)
	}

	return digests.NewDigest(algorithm, digestValue), nil
}

// LoadAndValidateManifest loads an OCI manifest from a path and validates it.
// This is a convenience function that combines LoadManifest and Validate.
func LoadAndValidateManifest(path string) (*ImageManifest, error) {
	m, err := LoadManifest(path)
	if err != nil {
		return nil, err
	}

	if err := m.Validate(); err != nil {
		return nil, err
	}

	return m, nil
}

// CreateManifestFromPath loads an OCI manifest from a file path and creates
// a model signing manifest from it. This is a convenience function that
// combines loading, validating, and creating the manifest.
//
// Parameters:
//   - path: Path to the OCI manifest JSON file
//   - includeConfig: Whether to include the config blob digest
//
// Returns a Manifest ready for signing/verification, or an error.
func CreateManifestFromPath(path string, includeConfig bool) (*manifest.Manifest, error) {
	ociManifest, err := LoadAndValidateManifest(path)
	if err != nil {
		return nil, fmt.Errorf("failed to load OCI manifest: %w", err)
	}

	modelName := ModelNameFromPath(path)
	return CreateManifestFromOCILayers(ociManifest, modelName, includeConfig)
}

// CompareManifests compares two manifests and returns a detailed error if they differ.
// Returns nil if the manifests are equal.
func CompareManifests(actual, expected *manifest.Manifest) error {
	if actual.Equal(expected) {
		return nil
	}

	// Build detailed diff
	actualHashes := make(map[string]string)
	for _, rd := range actual.ResourceDescriptors() {
		actualHashes[rd.Identifier] = rd.Digest.Hex()
	}

	expectedHashes := make(map[string]string)
	for _, rd := range expected.ResourceDescriptors() {
		expectedHashes[rd.Identifier] = rd.Digest.Hex()
	}

	var diffs []string

	// Find extra files in actual
	for id := range actualHashes {
		if _, exists := expectedHashes[id]; !exists {
			diffs = append(diffs, fmt.Sprintf("extra file in actual: %s", id))
		}
	}

	// Find missing files in actual
	for id := range expectedHashes {
		if _, exists := actualHashes[id]; !exists {
			diffs = append(diffs, fmt.Sprintf("missing file in actual: %s", id))
		}
	}

	// Find hash mismatches
	for id, expectedHash := range expectedHashes {
		if actualHash, exists := actualHashes[id]; exists {
			if actualHash != expectedHash {
				diffs = append(diffs, fmt.Sprintf("hash mismatch for %s: expected %s, got %s",
					id, expectedHash[:16]+"...", actualHash[:16]+"..."))
			}
		}
	}

	if len(diffs) == 0 {
		return fmt.Errorf("manifests differ (unknown reason)")
	}

	return fmt.Errorf("signature mismatch: %s", strings.Join(diffs, "; "))
}

// CreateManifestFromOCILayers creates a model signing manifest from an OCI image manifest.
//
// This function extracts layer digests from an OCI image manifest and creates
// a model signing manifest. Each layer is treated as a file entry.
//
// Parameters:
//   - ociManifest: The parsed OCI image manifest
//   - modelName: Optional name for the model (extracted from path if empty)
//   - includeConfig: Whether to include the config blob digest as a file entry
//
// Returns a Manifest ready for signing, or an error if the manifest is invalid.
func CreateManifestFromOCILayers(ociManifest *ImageManifest, modelName string, includeConfig bool) (*manifest.Manifest, error) {
	return CreateManifestFromOCILayersWithIgnore(ociManifest, modelName, includeConfig, nil)
}

// CreateManifestFromOCILayersWithIgnore creates a model signing manifest from an OCI image manifest,
// filtering out layers that match the ignore paths.
//
// This function extracts layer digests from an OCI image manifest and creates
// a model signing manifest. Each layer is treated as a file entry. Layers whose
// paths (from annotations or generated names) match any of the ignore paths are excluded.
//
// Parameters:
//   - ociManifest: The parsed OCI image manifest
//   - modelName: Optional name for the model (extracted from path if empty)
//   - includeConfig: Whether to include the config blob digest as a file entry
//   - ignorePaths: List of paths/filenames to exclude from the manifest
//
// Returns a Manifest ready for signing, or an error if the manifest is invalid.
func CreateManifestFromOCILayersWithIgnore(ociManifest *ImageManifest, modelName string, includeConfig bool, ignorePaths []string) (*manifest.Manifest, error) {
	if len(ociManifest.Layers) == 0 {
		return nil, fmt.Errorf("OCI manifest missing layers")
	}

	// Build ignore set for efficient lookup
	ignoreSet := make(map[string]bool)
	for _, p := range ignorePaths {
		// Normalize path - use just the filename for matching
		ignoreSet[p] = true
		ignoreSet[filepath.Base(p)] = true
	}

	var items []manifest.ManifestItem

	// Include config blob if requested (unless ignored)
	if includeConfig && ociManifest.Config.Digest != "" {
		if !ignoreSet["config.json"] {
			configDigest, err := parseDigestString(ociManifest.Config.Digest)
			if err != nil {
				return nil, fmt.Errorf("failed to parse config digest: %w", err)
			}
			items = append(items, manifest.NewFileManifestItem("config.json", configDigest))
		}
	}

	// Process layers
	for i, layer := range ociManifest.Layers {
		if layer.Digest == "" {
			continue
		}

		// Try to extract file path from annotations (ORAS-style)
		var layerPath string
		if layer.Annotations != nil {
			if title, ok := layer.Annotations["org.opencontainers.image.title"]; ok {
				layerPath = title
			}
		}

		// Fallback to generic layer name
		if layerPath == "" {
			layerPath = fmt.Sprintf("layer_%03d.tar.gz", i)
		}

		// Check if this layer should be ignored
		if shouldIgnoreLayer(layerPath, ignoreSet) {
			continue
		}

		layerDigest, err := parseDigestString(layer.Digest)
		if err != nil {
			return nil, fmt.Errorf("failed to parse layer %d digest: %w", i, err)
		}

		items = append(items, manifest.NewFileManifestItem(layerPath, layerDigest))
	}

	if len(items) == 0 {
		return nil, fmt.Errorf("no digests found in OCI manifest")
	}

	// Extract model name from annotations if not provided
	if modelName == "" {
		if ociManifest.Annotations != nil {
			if name, ok := ociManifest.Annotations["org.opencontainers.image.name"]; ok {
				modelName = name
			} else if name, ok := ociManifest.Annotations["org.opencontainers.image.base.name"]; ok {
				modelName = name
			}
		}
		if modelName == "" {
			modelName = "oci-image"
		}
	}

	// Create serialization type for OCI manifests
	serializationType := manifest.NewFileSerialization("sha256", false, nil)

	return manifest.NewManifest(modelName, items, serializationType), nil
}
