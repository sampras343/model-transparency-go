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

package modelartifact

import (
	"fmt"
	"strings"

	"github.com/sigstore/model-signing/pkg/config"
	"github.com/sigstore/model-signing/pkg/manifest"
	"github.com/sigstore/model-signing/pkg/oci"
	"github.com/sigstore/model-signing/pkg/utils"
)

// Canonicalize walks a model directory (or OCI manifest), hashes all files,
// and returns a deterministic Manifest.
//
// The resulting manifest contains a mapping from file identifiers (POSIX paths
// relative to the model root) to their cryptographic digests. Resource
// descriptors are sorted alphabetically to ensure determinism.
//
// If modelPath points to an OCI image manifest (.json file with valid OCI
// structure), the manifest is created from the OCI layers instead of walking
// the filesystem.
func Canonicalize(modelPath string, opts Options) (*manifest.Manifest, error) {
	// Handle OCI manifests
	if oci.IsOCIManifest(modelPath) {
		return canonicalizeOCI(modelPath, opts)
	}

	return canonicalizeDirectory(modelPath, opts)
}

// Compare checks whether two manifests match. Returns nil if they are equal,
// or a descriptive error listing extra files, missing files, and hash mismatches.
func Compare(actual, expected *manifest.Manifest) error {
	if actual.Equal(expected) {
		return nil
	}

	diff := manifest.ComputeDiff(actual, expected)
	return formatDiffError(diff, actual.ModelName(), false)
}

// CompareIgnoringExtra checks whether two manifests match, ignoring extra
// files that are present in actual but not in expected. This is useful when
// verifying models where unsigned files may have been added after signing.
//
// Returns nil if all expected files are present with matching digests,
// even if additional files exist in actual. Returns an error if files are
// missing from actual or if any common files have mismatched digests.
func CompareIgnoringExtra(actual, expected *manifest.Manifest) error {
	diff := manifest.ComputeDiff(actual, expected)
	return formatDiffError(diff, actual.ModelName(), true)
}

// formatDiffError formats a ManifestDiff into an error message.
// If ignoreExtra is true, extra files are not reported as errors.
func formatDiffError(diff *manifest.ManifestDiff, modelName string, ignoreExtra bool) error {
	if diff.IsEmpty() {
		return nil
	}

	var messages []string

	if !ignoreExtra && len(diff.ExtraFiles) > 0 {
		messages = append(messages, fmt.Sprintf(
			"extra files found in model '%s': %v",
			modelName,
			diff.ExtraFiles,
		))
	}

	if len(diff.MissingFiles) > 0 {
		messages = append(messages, fmt.Sprintf(
			"missing files in model '%s': %v",
			modelName,
			diff.MissingFiles,
		))
	}

	for _, m := range diff.Mismatches {
		messages = append(messages, fmt.Sprintf(
			"hash mismatch for '%s': expected '%s', actual '%s'",
			m.Identifier,
			m.ExpectedHash,
			m.ActualHash,
		))
	}

	if len(messages) == 0 {
		return nil
	}

	return fmt.Errorf("manifest mismatch:\n%s", strings.Join(messages, "\n"))
}

// canonicalizeDirectory hashes a model directory using the configured options.
func canonicalizeDirectory(modelPath string, opts Options) (*manifest.Manifest, error) {
	hashingConfig := buildHashingConfig(opts)

	m, err := hashingConfig.Hash(modelPath, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to hash model: %w", err)
	}

	if opts.Logger != nil {
		opts.Logger.Debug("  Hashed %d files", len(m.ResourceDescriptors()))
	}

	return m, nil
}

// canonicalizeOCI creates a manifest from an OCI image manifest.
func canonicalizeOCI(modelPath string, opts Options) (*manifest.Manifest, error) {
	if opts.Logger != nil {
		opts.Logger.Debug("  Detected OCI manifest: %s", modelPath)
	}

	ociManifest, err := oci.LoadManifest(modelPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load OCI manifest: %w", err)
	}

	if err := ociManifest.Validate(); err != nil {
		return nil, fmt.Errorf("invalid OCI manifest: %w", err)
	}

	modelName := oci.ModelNameFromPath(modelPath)
	m, err := oci.CreateManifestFromOCILayersWithIgnore(ociManifest, modelName, true, opts.IgnorePaths)
	if err != nil {
		return nil, fmt.Errorf("failed to create manifest from OCI layers: %w", err)
	}

	if opts.Logger != nil {
		opts.Logger.Debug("  Created manifest from %d OCI layers", len(m.ResourceDescriptors()))
	}

	return m, nil
}

// buildHashingConfig creates a HashingConfig from Options.
func buildHashingConfig(opts Options) *config.HashingConfig {
	hashAlgorithm := opts.HashAlgorithm
	if hashAlgorithm == "" {
		hashAlgorithm = utils.DefaultHashAlgorithm
	}

	hc := config.NewHashingConfig()

	if opts.ShardSize > 0 {
		hc.UseShardSerialization(hashAlgorithm, opts.ShardSize, opts.AllowSymlinks, opts.IgnorePaths)
	} else {
		hc.UseFileSerialization(hashAlgorithm, opts.AllowSymlinks, opts.IgnorePaths)
	}

	if opts.IgnoreGitPaths {
		hc.SetIgnoredPaths(opts.IgnorePaths, true)
	}

	return hc
}
