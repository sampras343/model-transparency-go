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

package manifest

import "sort"

// ManifestDiff represents the differences between two manifests.
// It contains structured information about files that differ between
// an actual manifest (computed from the model) and an expected manifest
// (extracted from a signature).
// nolint:revive
type ManifestDiff struct {
	// ExtraFiles contains identifiers of files present in actual but not in expected.
	ExtraFiles []string

	// MissingFiles contains identifiers of files present in expected but not in actual.
	MissingFiles []string

	// Mismatches contains files that exist in both manifests but have different digests.
	Mismatches []HashMismatch
}

// HashMismatch represents a single file with differing digests between manifests.
type HashMismatch struct {
	// Identifier is the file path or name.
	Identifier string

	// ExpectedHash is the digest hex from the expected manifest (signature).
	ExpectedHash string

	// ActualHash is the digest hex from the actual manifest (computed).
	ActualHash string
}

// IsEmpty returns true if there are no differences.
func (d *ManifestDiff) IsEmpty() bool {
	return len(d.ExtraFiles) == 0 && len(d.MissingFiles) == 0 && len(d.Mismatches) == 0
}

// ComputeDiff computes the differences between two manifests.
//
// Parameters:
//   - actual: The manifest computed from the model being verified
//   - expected: The manifest extracted from the signature
//
// Returns a ManifestDiff containing all differences, with slices sorted alphabetically.
func ComputeDiff(actual, expected *Manifest) *ManifestDiff {
	diff := &ManifestDiff{
		ExtraFiles:   []string{},
		MissingFiles: []string{},
		Mismatches:   []HashMismatch{},
	}

	// Build maps of identifier -> digest hex
	actualHashes := make(map[string]string)
	for _, rd := range actual.ResourceDescriptors() {
		actualHashes[rd.Identifier] = rd.Digest.Hex()
	}

	expectedHashes := make(map[string]string)
	for _, rd := range expected.ResourceDescriptors() {
		expectedHashes[rd.Identifier] = rd.Digest.Hex()
	}

	// Find extra files in actual (not in expected)
	for id := range actualHashes {
		if _, exists := expectedHashes[id]; !exists {
			diff.ExtraFiles = append(diff.ExtraFiles, id)
		}
	}
	sort.Strings(diff.ExtraFiles)

	// Find missing files in actual (in expected but not in actual)
	for id := range expectedHashes {
		if _, exists := actualHashes[id]; !exists {
			diff.MissingFiles = append(diff.MissingFiles, id)
		}
	}
	sort.Strings(diff.MissingFiles)

	// Find hash mismatches (files in both but with different digests)
	var commonFiles []string
	for id := range actualHashes {
		if _, exists := expectedHashes[id]; exists {
			commonFiles = append(commonFiles, id)
		}
	}
	sort.Strings(commonFiles)

	for _, id := range commonFiles {
		if actualHashes[id] != expectedHashes[id] {
			diff.Mismatches = append(diff.Mismatches, HashMismatch{
				Identifier:   id,
				ExpectedHash: expectedHashes[id],
				ActualHash:   actualHashes[id],
			})
		}
	}

	return diff
}
