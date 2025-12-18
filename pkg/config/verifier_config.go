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

package config

import (
	"fmt"
	"path/filepath"
	"sort"
	"strings"

	"github.com/sigstore/model-signing/pkg/interfaces"
	"github.com/sigstore/model-signing/pkg/manifest"
	sigstoresigning "github.com/sigstore/model-signing/pkg/signing/sigstore"
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
func (c *Config) Verify(modelPath, signaturePath string) error {
	if c.verifier == nil {
		return fmt.Errorf("attempting to verify with no configured verifier")
	}

	// Read signature from disk
	// Note: The signature type must match the verifier type
	// For now, we assume it's a Sigstore signature since that's what we support
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

	// Add ignore_paths from manifest to hashing config
	serializationParams := expectedManifest.SerializationParameters()
	if ignorePaths, ok := serializationParams["ignore_paths"]; ok {
		if paths, ok := ignorePaths.([]string); ok {
			absModelPath, err := filepath.Abs(modelPath)
			if err != nil {
				return fmt.Errorf("failed to get absolute path for model: %w", err)
			}
			c.hashingConfig.AddIgnoredPaths(absModelPath, paths)
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
func (c *Config) SetHashingConfig(hashingConfig *HashingConfig) *Config {
	c.hashingConfig = hashingConfig
	return c
}

// SetIgnoreUnsignedFiles sets whether files not in the signature should be ignored.
//
// When enabled, only files present in the manifest are hashed and verified.
// Files not in the manifest are ignored rather than causing verification to fail.
func (c *Config) SetIgnoreUnsignedFiles(ignore bool) *Config {
	c.ignoreUnsignedFiles = ignore
	return c
}

// SetVerifier sets the signature verifier to use.
//
// This accepts any SignatureVerifier implementation (e.g., Sigstore, certificate-based, key-based).
func (c *Config) SetVerifier(verifier interfaces.SignatureVerifier) *Config {
	c.verifier = verifier
	return c
}

// createSignatureReader creates a signature reader appropriate for the verifier.
//
// This is a helper method that returns the correct signature reader type.
// In the future, this could be made more sophisticated to handle multiple
// signature formats.
func (c *Config) createSignatureReader() interfaces.SignatureReader {
	// For now, we only support Sigstore signatures
	// This would need to be extended if we support other signature types
	return &sigstoresigning.Signature{}
}

// guessHashingConfig attempts to determine the hashing configuration from a manifest.
//
// This parses the serialization parameters in the manifest to reconstruct
// the hashing configuration that was used during signing.
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
// Returns a list of human-readable difference messages.
func (c *Config) getManifestDiff(actual, expected *manifest.Manifest) []string {
	var diffs []string

	// Build maps of identifier -> digest
	actualHashes := make(map[string]string)
	for _, rd := range actual.ResourceDescriptors() {
		actualHashes[rd.Identifier] = rd.Digest.Hex()
	}

	expectedHashes := make(map[string]string)
	for _, rd := range expected.ResourceDescriptors() {
		expectedHashes[rd.Identifier] = rd.Digest.Hex()
	}

	// Find extra files in actual model
	extraFiles := make([]string, 0)
	for id := range actualHashes {
		if _, exists := expectedHashes[id]; !exists {
			extraFiles = append(extraFiles, id)
		}
	}
	if len(extraFiles) > 0 {
		sort.Strings(extraFiles)
		diffs = append(diffs, fmt.Sprintf(
			"Extra files found in model '%s': %v",
			actual.ModelName(),
			extraFiles,
		))
	}

	// Find missing files in actual model
	missingFiles := make([]string, 0)
	for id := range expectedHashes {
		if _, exists := actualHashes[id]; !exists {
			missingFiles = append(missingFiles, id)
		}
	}
	if len(missingFiles) > 0 {
		sort.Strings(missingFiles)
		diffs = append(diffs, fmt.Sprintf(
			"Missing files in model '%s': %v",
			actual.ModelName(),
			missingFiles,
		))
	}

	// Find files with hash mismatches
	commonFiles := make([]string, 0)
	for id := range actualHashes {
		if _, exists := expectedHashes[id]; exists {
			commonFiles = append(commonFiles, id)
		}
	}
	sort.Strings(commonFiles)

	for _, id := range commonFiles {
		if actualHashes[id] != expectedHashes[id] {
			diffs = append(diffs, fmt.Sprintf(
				"Hash mismatch for '%s': Expected '%s', Actual '%s'",
				id,
				expectedHashes[id],
				actualHashes[id],
			))
		}
	}

	return diffs
}

// formatDiffMessages formats a list of diff messages into a single string.
func formatDiffMessages(diffs []string) string {
	if len(diffs) == 0 {
		return "no differences found"
	}

	return strings.Join(diffs, "\n")
}
