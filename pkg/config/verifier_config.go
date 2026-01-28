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

// Package config provides configuration types for model signing and verification.
//
// This package includes configurations for verifying models against signatures,
// hashing models with different serialization strategies, and managing cryptographic
// keys and trust roots.
package config

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/sigstore/model-signing/pkg/interfaces"
	"github.com/sigstore/model-signing/pkg/manifest"
	"github.com/sigstore/model-signing/pkg/oci"
	sign "github.com/sigstore/model-signing/pkg/signature"
)

// Config holds configuration for verifying models against signatures.
//
// The verification configuration determines how to read and verify the signature.
// It also supports configuring the hashing configuration, which should match
// the configuration used during signing. By default, it attempts to guess
// the hashing config from the signature.
type Config struct {
	hashingConfig       *HashingConfig
	verifier            interfaces.SignatureVerifier
	ignoreUnsignedFiles bool
}

// NewVerifierConfig creates a new verification configuration with defaults.
//
// Returns a Config with no verifier set, no hashing config (auto-guess enabled),
// and ignoreUnsignedFiles set to false.
func NewVerifierConfig() *Config {
	return &Config{
		hashingConfig:       nil,
		verifier:            nil,
		ignoreUnsignedFiles: false,
	}
}

// Verify verifies that a model conforms to a signature.
//
// This performs the following steps:
// 1. Reads and verifies the cryptographic signature
// 2. Extracts the expected manifest from the signature
// 3. Guesses hashing config if not explicitly set
// 4. Hashes the model files
// 5. Compares actual vs expected manifests
//
// Parameters:
//   - modelPath: Path to the model directory or file to verify
//   - signaturePath: Path to the signature file
//
// Returns an error if verification fails at any step.
func (c *Config) Verify(modelPath, signaturePath string) error {
	if c.verifier == nil {
		return fmt.Errorf("attempting to verify with no configured verifier")
	}

	// Read signature from disk
	// Note: The signature type must match the verifier type
	reader := c.createSignatureReader()
	signature, err := reader.Read(signaturePath)
	if err != nil {
		return fmt.Errorf("failed to read signature: %w", err)
	}

	// Verify signature and extract expected manifest
	expectedManifest, err := c.verifier.Verify(signature)
	if err != nil {
		return fmt.Errorf("signature verification failed: %w", err)
	}

	// Guess hashing config if not set
	if c.hashingConfig == nil {
		if err := c.guessHashingConfig(expectedManifest); err != nil {
			return fmt.Errorf("failed to determine hashing config: %w", err)
		}
	}
	// Determine which files to hash
	var filesToHash []string
	if c.ignoreUnsignedFiles {
		// Only hash files that are in the signature
		for _, rd := range expectedManifest.ResourceDescriptors() {
			filePath := filepath.Join(modelPath, rd.Identifier)
			filesToHash = append(filesToHash, filePath)
		}
	}
	// If filesToHash is nil, all files will be hashed

	// Hash the model
	actualManifest, err := c.hashingConfig.Hash(modelPath, filesToHash)
	if err != nil {
		return fmt.Errorf("failed to hash model: %w", err)
	}

	// Compare manifests
	if !actualManifest.Equal(expectedManifest) {
		diffMessages := c.getManifestDiff(actualManifest, expectedManifest)
		return fmt.Errorf("signature mismatch:\n%s", formatDiffMessages(diffMessages))
	}

	return nil
}

// SetHashingConfig sets the configuration for hashing models.
//
// After calling this method, automatic guessing of the hashing configuration
// is disabled for this Config instance.
//
// Returns the Config for method chaining.
func (c *Config) SetHashingConfig(hashingConfig *HashingConfig) *Config {
	c.hashingConfig = hashingConfig
	return c
}

// SetIgnoreUnsignedFiles sets whether files not in the signature should be ignored.
//
// When enabled, only files present in the manifest are hashed and verified.
// Files not in the manifest are ignored rather than causing verification to fail.
//
// Returns the Config for method chaining.
func (c *Config) SetIgnoreUnsignedFiles(ignore bool) *Config {
	c.ignoreUnsignedFiles = ignore
	return c
}

// SetVerifier sets the signature verifier to use.
//
// This accepts any SignatureVerifier implementation (e.g., Sigstore, certificate-based, key-based).
//
// Returns the Config for method chaining.
func (c *Config) SetVerifier(verifier interfaces.SignatureVerifier) *Config {
	c.verifier = verifier
	return c
}

// createSignatureReader creates a signature reader appropriate for the verifier.
//
// This is a helper method that returns the correct signature reader type.
// In the future, this could be made more sophisticated to handle multiple
// signature formats.
//
// Returns a SignatureReader interface implementation.
func (c *Config) createSignatureReader() interfaces.SignatureReader {
	// Check if the verifier implements SignatureReader interface
	// Certificate verifiers implement this to provide their own signature reading
	if reader, ok := c.verifier.(interfaces.SignatureReader); ok {
		return reader
	}

	// For other verifiers, use standard Sigstore signature
	return &sign.Signature{}
}

// guessHashingConfig attempts to determine the hashing configuration from a manifest.
//
// This parses the serialization parameters in the manifest to reconstruct
// the hashing configuration that was used during signing.
//
// Returns an error if required parameters are missing or invalid.
func (c *Config) guessHashingConfig(sourceManifest *manifest.Manifest) error {
	params := sourceManifest.SerializationParameters()
	extractor := manifest.NewParamExtractor(params)

	// Extract common parameters
	method, err := extractor.GetString("method")
	if err != nil {
		return fmt.Errorf("cannot determine serialization method: %w", err)
	}

	hashType, err := extractor.GetString("hash_type")
	if err != nil {
		return fmt.Errorf("cannot determine hash type: %w", err)
	}

	allowSymlinks, err := extractor.GetBool("allow_symlinks")
	if err != nil {
		return fmt.Errorf("cannot determine allow_symlinks: %w", err)
	}

	// Extract optional ignore_paths
	ignorePaths := extractor.GetStringSliceOptional("ignore_paths")

	// Create config based on serialization method
	switch method {
	case "files":
		c.hashingConfig = NewHashingConfig().UseFileSerialization(
			hashType,
			allowSymlinks,
			ignorePaths,
		)
	case "shards":
		shardSize, err := extractor.GetInt64("shard_size")
		if err != nil {
			return fmt.Errorf("cannot determine shard_size: %w", err)
		}

		c.hashingConfig = NewHashingConfig().UseShardSerialization(
			hashType,
			shardSize,
			allowSymlinks,
			ignorePaths,
		)
	default:
		return fmt.Errorf("unknown serialization method: %s", method)
	}

	return nil
}

// getManifestDiff computes the differences between actual and expected manifests.
//
// Parameters:
//   - actual: The manifest computed from the model being verified
//   - expected: The manifest extracted from the signature
//
// Returns a list of human-readable difference messages.
func (c *Config) getManifestDiff(actual, expected *manifest.Manifest) []string {
	diff := manifest.ComputeDiff(actual, expected)

	var diffs []string

	if len(diff.ExtraFiles) > 0 {
		diffs = append(diffs, fmt.Sprintf(
			"Extra files found in model '%s': %v",
			actual.ModelName(),
			diff.ExtraFiles,
		))
	}

	if len(diff.MissingFiles) > 0 {
		diffs = append(diffs, fmt.Sprintf(
			"Missing files in model '%s': %v",
			actual.ModelName(),
			diff.MissingFiles,
		))
	}

	for _, m := range diff.Mismatches {
		diffs = append(diffs, fmt.Sprintf(
			"Hash mismatch for '%s': Expected '%s', Actual '%s'",
			m.Identifier,
			m.ExpectedHash,
			m.ActualHash,
		))
	}

	return diffs
}

// formatDiffMessages formats a list of diff messages into a single string.
//
// Returns a newline-separated string of all difference messages,
// or "no differences found" if the list is empty.
func formatDiffMessages(diffs []string) string {
	if len(diffs) == 0 {
		return "no differences found"
	}

	return strings.Join(diffs, "\n")
}

// VerifyOCIManifest verifies that an OCI image manifest conforms to a signature.
//
// This method verifies a signature against an OCI image manifest without
// requiring the actual model files. It extracts the expected manifest from
// the signature and compares it with a manifest created from the OCI image
// manifest layers.
//
// Parameters:
//   - ociManifest: The parsed OCI image manifest
//   - signaturePath: Path to the signature file
//   - includeConfig: Whether to include the config blob digest in comparison
//
// Returns an error if verification fails.
func (c *Config) VerifyOCIManifest(ociManifest *oci.ImageManifest, signaturePath string, includeConfig bool) error {
	return c.VerifyOCIManifestWithIgnore(ociManifest, signaturePath, includeConfig, nil)
}

// VerifyOCIManifestWithIgnore verifies that an OCI image manifest conforms to a signature,
// filtering out layers that match the ignore paths.
//
// This method verifies a signature against an OCI image manifest without
// requiring the actual model files. It extracts the expected manifest from
// the signature and compares it with a manifest created from the OCI image
// manifest layers.
//
// Parameters:
//   - ociManifest: The parsed OCI image manifest
//   - signaturePath: Path to the signature file
//   - includeConfig: Whether to include the config blob digest in comparison
//   - ignorePaths: List of paths/filenames to exclude from verification
//
// Returns an error if verification fails.
func (c *Config) VerifyOCIManifestWithIgnore(ociManifest *oci.ImageManifest, signaturePath string, includeConfig bool, ignorePaths []string) error {
	if c.verifier == nil {
		return fmt.Errorf("attempting to verify with no configured verifier")
	}

	// Read signature from disk
	reader := c.createSignatureReader()
	signature, err := reader.Read(signaturePath)
	if err != nil {
		return fmt.Errorf("failed to read signature: %w", err)
	}

	// Verify signature and extract expected manifest
	expectedManifest, err := c.verifier.Verify(signature)
	if err != nil {
		return fmt.Errorf("signature verification failed: %w", err)
	}

	// Create manifest from OCI layers with ignore paths
	actualManifest, err := oci.CreateManifestFromOCILayersWithIgnore(ociManifest, "", includeConfig, ignorePaths)
	if err != nil {
		return fmt.Errorf("failed to create manifest from OCI layers: %w", err)
	}

	// Filter actual manifest to only include files that are present in the expected manifest (signature)
	if c.ignoreUnsignedFiles {
		actualManifest = filterManifestToExpected(actualManifest, expectedManifest)
	}

	// Compare manifests
	if err := oci.CompareManifests(actualManifest, expectedManifest); err != nil {
		return err
	}

	return nil
}

// filterManifestToExpected filters the actual manifest to only include items
// that are present in the expected manifest.
func filterManifestToExpected(actual, expected *manifest.Manifest) *manifest.Manifest {
	// Build set of expected identifiers
	expectedIDs := make(map[string]bool)
	for _, rd := range expected.ResourceDescriptors() {
		expectedIDs[rd.Identifier] = true
	}

	// Filter actual items to only those in expected
	var filteredItems []manifest.ManifestItem
	for _, rd := range actual.ResourceDescriptors() {
		if expectedIDs[rd.Identifier] {
			filteredItems = append(filteredItems, manifest.NewFileManifestItem(rd.Identifier, rd.Digest))
		}
	}

	// Use a default serialization type
	serializationType := manifest.NewFileSerialization("sha256", false, nil)

	return manifest.NewManifest(actual.ModelName(), filteredItems, serializationType)
}
