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

import (
	"testing"

	"github.com/sigstore/model-signing/pkg/hashing/digests"
)

func TestComputeDiff_EqualManifests(t *testing.T) {
	digest1 := digests.NewDigest("sha256", []byte{0x01, 0x02, 0x03})
	digest2 := digests.NewDigest("sha256", []byte{0x04, 0x05, 0x06})

	items := []ManifestItem{
		NewFileManifestItem("file1.txt", digest1),
		NewFileManifestItem("file2.txt", digest2),
	}

	serType := NewFileSerialization("sha256", false, nil)
	manifest1 := NewManifest("test-model", items, serType)
	manifest2 := NewManifest("test-model", items, serType)

	diff := ComputeDiff(manifest1, manifest2)

	if !diff.IsEmpty() {
		t.Errorf("Expected empty diff for equal manifests, got: extra=%v, missing=%v, mismatches=%v",
			diff.ExtraFiles, diff.MissingFiles, diff.Mismatches)
	}
}

func TestComputeDiff_ExtraFiles(t *testing.T) {
	digest1 := digests.NewDigest("sha256", []byte{0x01, 0x02, 0x03})
	digest2 := digests.NewDigest("sha256", []byte{0x04, 0x05, 0x06})
	digest3 := digests.NewDigest("sha256", []byte{0x07, 0x08, 0x09})

	serType := NewFileSerialization("sha256", false, nil)

	// Actual has an extra file
	actualItems := []ManifestItem{
		NewFileManifestItem("file1.txt", digest1),
		NewFileManifestItem("file2.txt", digest2),
		NewFileManifestItem("extra.txt", digest3),
	}
	actual := NewManifest("test-model", actualItems, serType)

	expectedItems := []ManifestItem{
		NewFileManifestItem("file1.txt", digest1),
		NewFileManifestItem("file2.txt", digest2),
	}
	expected := NewManifest("test-model", expectedItems, serType)

	diff := ComputeDiff(actual, expected)

	if len(diff.ExtraFiles) != 1 || diff.ExtraFiles[0] != "extra.txt" {
		t.Errorf("Expected extra file 'extra.txt', got: %v", diff.ExtraFiles)
	}
	if len(diff.MissingFiles) != 0 {
		t.Errorf("Expected no missing files, got: %v", diff.MissingFiles)
	}
	if len(diff.Mismatches) != 0 {
		t.Errorf("Expected no mismatches, got: %v", diff.Mismatches)
	}
}

func TestComputeDiff_MissingFiles(t *testing.T) {
	digest1 := digests.NewDigest("sha256", []byte{0x01, 0x02, 0x03})
	digest2 := digests.NewDigest("sha256", []byte{0x04, 0x05, 0x06})
	digest3 := digests.NewDigest("sha256", []byte{0x07, 0x08, 0x09})

	serType := NewFileSerialization("sha256", false, nil)

	// Actual is missing a file
	actualItems := []ManifestItem{
		NewFileManifestItem("file1.txt", digest1),
	}
	actual := NewManifest("test-model", actualItems, serType)

	expectedItems := []ManifestItem{
		NewFileManifestItem("file1.txt", digest1),
		NewFileManifestItem("file2.txt", digest2),
		NewFileManifestItem("file3.txt", digest3),
	}
	expected := NewManifest("test-model", expectedItems, serType)

	diff := ComputeDiff(actual, expected)

	if len(diff.ExtraFiles) != 0 {
		t.Errorf("Expected no extra files, got: %v", diff.ExtraFiles)
	}
	if len(diff.MissingFiles) != 2 {
		t.Errorf("Expected 2 missing files, got: %v", diff.MissingFiles)
	}
	// Should be sorted
	if diff.MissingFiles[0] != "file2.txt" || diff.MissingFiles[1] != "file3.txt" {
		t.Errorf("Expected missing files ['file2.txt', 'file3.txt'], got: %v", diff.MissingFiles)
	}
	if len(diff.Mismatches) != 0 {
		t.Errorf("Expected no mismatches, got: %v", diff.Mismatches)
	}
}

func TestComputeDiff_HashMismatch(t *testing.T) {
	digest1 := digests.NewDigest("sha256", []byte{0x01, 0x02, 0x03})
	digest2 := digests.NewDigest("sha256", []byte{0x04, 0x05, 0x06})
	differentDigest := digests.NewDigest("sha256", []byte{0xFF, 0xFE, 0xFD})

	serType := NewFileSerialization("sha256", false, nil)

	// Same files, different hash for file2
	actualItems := []ManifestItem{
		NewFileManifestItem("file1.txt", digest1),
		NewFileManifestItem("file2.txt", differentDigest),
	}
	actual := NewManifest("test-model", actualItems, serType)

	expectedItems := []ManifestItem{
		NewFileManifestItem("file1.txt", digest1),
		NewFileManifestItem("file2.txt", digest2),
	}
	expected := NewManifest("test-model", expectedItems, serType)

	diff := ComputeDiff(actual, expected)

	if len(diff.ExtraFiles) != 0 {
		t.Errorf("Expected no extra files, got: %v", diff.ExtraFiles)
	}
	if len(diff.MissingFiles) != 0 {
		t.Errorf("Expected no missing files, got: %v", diff.MissingFiles)
	}
	if len(diff.Mismatches) != 1 {
		t.Errorf("Expected 1 mismatch, got: %v", diff.Mismatches)
	}
	if diff.Mismatches[0].Identifier != "file2.txt" {
		t.Errorf("Expected mismatch for 'file2.txt', got: %s", diff.Mismatches[0].Identifier)
	}
	if diff.Mismatches[0].ExpectedHash != digest2.Hex() {
		t.Errorf("Expected hash %s, got: %s", digest2.Hex(), diff.Mismatches[0].ExpectedHash)
	}
	if diff.Mismatches[0].ActualHash != differentDigest.Hex() {
		t.Errorf("Actual hash %s, got: %s", differentDigest.Hex(), diff.Mismatches[0].ActualHash)
	}
}

func TestComputeDiff_MultipleDifferences(t *testing.T) {
	digest1 := digests.NewDigest("sha256", []byte{0x01, 0x02, 0x03})
	digest2 := digests.NewDigest("sha256", []byte{0x04, 0x05, 0x06})
	digest3 := digests.NewDigest("sha256", []byte{0x07, 0x08, 0x09})
	differentDigest := digests.NewDigest("sha256", []byte{0xFF, 0xFE, 0xFD})

	serType := NewFileSerialization("sha256", false, nil)

	// Actual has extra file, missing file, and hash mismatch
	actualItems := []ManifestItem{
		NewFileManifestItem("common.txt", differentDigest), // mismatch
		NewFileManifestItem("extra.txt", digest3),          // extra
	}
	actual := NewManifest("test-model", actualItems, serType)

	expectedItems := []ManifestItem{
		NewFileManifestItem("common.txt", digest1), // mismatch
		NewFileManifestItem("missing.txt", digest2), // missing
	}
	expected := NewManifest("test-model", expectedItems, serType)

	diff := ComputeDiff(actual, expected)

	if len(diff.ExtraFiles) != 1 || diff.ExtraFiles[0] != "extra.txt" {
		t.Errorf("Expected extra file 'extra.txt', got: %v", diff.ExtraFiles)
	}
	if len(diff.MissingFiles) != 1 || diff.MissingFiles[0] != "missing.txt" {
		t.Errorf("Expected missing file 'missing.txt', got: %v", diff.MissingFiles)
	}
	if len(diff.Mismatches) != 1 || diff.Mismatches[0].Identifier != "common.txt" {
		t.Errorf("Expected mismatch for 'common.txt', got: %v", diff.Mismatches)
	}
	if diff.IsEmpty() {
		t.Error("Expected non-empty diff")
	}
}

func TestComputeDiff_SortedResults(t *testing.T) {
	serType := NewFileSerialization("sha256", false, nil)

	// Create manifests with files in non-alphabetical order
	actualItems := []ManifestItem{
		NewFileManifestItem("zebra.txt", digests.NewDigest("sha256", []byte{0x01})),
		NewFileManifestItem("apple.txt", digests.NewDigest("sha256", []byte{0x02})),
		NewFileManifestItem("mango.txt", digests.NewDigest("sha256", []byte{0x03})),
	}
	actual := NewManifest("test-model", actualItems, serType)

	// Expected has none of these files
	expected := NewManifest("test-model", []ManifestItem{}, serType)

	diff := ComputeDiff(actual, expected)

	// Extra files should be sorted alphabetically
	if len(diff.ExtraFiles) != 3 {
		t.Fatalf("Expected 3 extra files, got: %d", len(diff.ExtraFiles))
	}
	if diff.ExtraFiles[0] != "apple.txt" || diff.ExtraFiles[1] != "mango.txt" || diff.ExtraFiles[2] != "zebra.txt" {
		t.Errorf("Expected sorted extra files, got: %v", diff.ExtraFiles)
	}
}

func TestManifestDiff_IsEmpty(t *testing.T) {
	tests := []struct {
		name     string
		diff     ManifestDiff
		expected bool
	}{
		{
			name:     "empty diff",
			diff:     ManifestDiff{},
			expected: true,
		},
		{
			name: "with extra files",
			diff: ManifestDiff{
				ExtraFiles: []string{"file.txt"},
			},
			expected: false,
		},
		{
			name: "with missing files",
			diff: ManifestDiff{
				MissingFiles: []string{"file.txt"},
			},
			expected: false,
		},
		{
			name: "with mismatches",
			diff: ManifestDiff{
				Mismatches: []HashMismatch{{Identifier: "file.txt"}},
			},
			expected: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if tc.diff.IsEmpty() != tc.expected {
				t.Errorf("IsEmpty() = %v, expected %v", tc.diff.IsEmpty(), tc.expected)
			}
		})
	}
}
