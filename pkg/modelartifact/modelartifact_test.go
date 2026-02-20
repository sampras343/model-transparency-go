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
	"os"
	"path/filepath"
	"testing"
)

// createTestModel creates a temporary model directory with test files.
func createTestModel(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()

	// Create some test files
	files := map[string]string{
		"model.bin":      "model binary content",
		"config.json":    `{"layers": 12, "hidden_size": 768}`,
		"tokenizer.json": `{"vocab_size": 30522}`,
	}

	for name, content := range files {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte(content), 0644); err != nil {
			t.Fatalf("failed to create test file %s: %v", name, err)
		}
	}

	return dir
}

// createTestModelWithSubdir creates a model directory with subdirectories.
func createTestModelWithSubdir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()

	subdir := filepath.Join(dir, "weights")
	if err := os.MkdirAll(subdir, 0755); err != nil {
		t.Fatalf("failed to create subdir: %v", err)
	}

	files := map[string]string{
		"config.json":         `{"type": "bert"}`,
		"weights/layer_0.bin": "layer 0 weights",
		"weights/layer_1.bin": "layer 1 weights",
	}

	for name, content := range files {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte(content), 0644); err != nil {
			t.Fatalf("failed to create test file %s: %v", name, err)
		}
	}

	return dir
}

func TestCanonicalize(t *testing.T) {
	modelDir := createTestModel(t)

	m, err := Canonicalize(modelDir, Options{})
	if err != nil {
		t.Fatalf("Canonicalize failed: %v", err)
	}

	descriptors := m.ResourceDescriptors()
	if len(descriptors) != 3 {
		t.Fatalf("expected 3 resource descriptors, got %d", len(descriptors))
	}

	// Verify descriptors are sorted alphabetically
	for i := 1; i < len(descriptors); i++ {
		if descriptors[i].Identifier < descriptors[i-1].Identifier {
			t.Errorf("descriptors not sorted: %s came after %s",
				descriptors[i].Identifier, descriptors[i-1].Identifier)
		}
	}
}

func TestCanonicalizeWithSubdirs(t *testing.T) {
	modelDir := createTestModelWithSubdir(t)

	m, err := Canonicalize(modelDir, Options{})
	if err != nil {
		t.Fatalf("Canonicalize failed: %v", err)
	}

	descriptors := m.ResourceDescriptors()
	if len(descriptors) != 3 {
		t.Fatalf("expected 3 resource descriptors, got %d", len(descriptors))
	}

	// Check that subdirectory paths use POSIX format
	found := false
	for _, desc := range descriptors {
		if desc.Identifier == "weights/layer_0.bin" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected to find 'weights/layer_0.bin' in descriptors")
	}
}

func TestCanonicalizeWithIgnorePaths(t *testing.T) {
	modelDir := createTestModel(t)

	m, err := Canonicalize(modelDir, Options{
		IgnorePaths: []string{"tokenizer.json"},
	})
	if err != nil {
		t.Fatalf("Canonicalize failed: %v", err)
	}

	descriptors := m.ResourceDescriptors()
	if len(descriptors) != 2 {
		t.Fatalf("expected 2 resource descriptors (tokenizer.json ignored), got %d", len(descriptors))
	}

	for _, desc := range descriptors {
		if desc.Identifier == "tokenizer.json" {
			t.Error("tokenizer.json should have been ignored")
		}
	}
}

func TestCanonicalizeDeterministic(t *testing.T) {
	modelDir := createTestModel(t)

	m1, err := Canonicalize(modelDir, Options{})
	if err != nil {
		t.Fatalf("first Canonicalize failed: %v", err)
	}

	m2, err := Canonicalize(modelDir, Options{})
	if err != nil {
		t.Fatalf("second Canonicalize failed: %v", err)
	}

	if !m1.Equal(m2) {
		t.Error("two canonicalizations of the same model should be equal")
	}
}

func TestCanonicalizeWithShards(t *testing.T) {
	modelDir := createTestModel(t)

	m, err := Canonicalize(modelDir, Options{
		ShardSize: 10, // Small shard size to ensure multiple shards
	})
	if err != nil {
		t.Fatalf("Canonicalize with shards failed: %v", err)
	}

	// With small shard size, we should get more descriptors than files
	descriptors := m.ResourceDescriptors()
	if len(descriptors) <= 3 {
		t.Errorf("expected more than 3 descriptors with shard size 10, got %d", len(descriptors))
	}
}

func TestCanonicalizeNonexistentPath(t *testing.T) {
	_, err := Canonicalize("/nonexistent/path", Options{})
	if err == nil {
		t.Error("expected error for nonexistent path")
	}
}

func TestCompareEqual(t *testing.T) {
	modelDir := createTestModel(t)

	m1, err := Canonicalize(modelDir, Options{})
	if err != nil {
		t.Fatalf("Canonicalize failed: %v", err)
	}

	m2, err := Canonicalize(modelDir, Options{})
	if err != nil {
		t.Fatalf("Canonicalize failed: %v", err)
	}

	if err := Compare(m1, m2); err != nil {
		t.Errorf("Compare should return nil for equal manifests, got: %v", err)
	}
}

func TestCompareDifferent(t *testing.T) {
	dir1 := createTestModel(t)
	dir2 := createTestModel(t)

	// Modify a file in dir2
	if err := os.WriteFile(filepath.Join(dir2, "model.bin"), []byte("modified content"), 0644); err != nil {
		t.Fatalf("failed to modify file: %v", err)
	}

	m1, err := Canonicalize(dir1, Options{})
	if err != nil {
		t.Fatalf("Canonicalize dir1 failed: %v", err)
	}

	m2, err := Canonicalize(dir2, Options{})
	if err != nil {
		t.Fatalf("Canonicalize dir2 failed: %v", err)
	}

	err = Compare(m1, m2)
	if err == nil {
		t.Error("Compare should return error for different manifests")
	}
}

func TestRoundTrip(t *testing.T) {
	modelDir := createTestModel(t)

	// 1. Canonicalize
	m, err := Canonicalize(modelDir, Options{})
	if err != nil {
		t.Fatalf("Canonicalize failed: %v", err)
	}

	// 2. Marshal to payload
	payload, err := MarshalPayload(m)
	if err != nil {
		t.Fatalf("MarshalPayload failed: %v", err)
	}

	// Verify payload is valid JSON
	if len(payload) == 0 {
		t.Fatal("MarshalPayload returned empty payload")
	}

	// 3. Unmarshal back to manifest
	reconstructed, err := UnmarshalPayload(payload)
	if err != nil {
		t.Fatalf("UnmarshalPayload failed: %v", err)
	}

	// 4. Compare original and reconstructed
	if err := Compare(m, reconstructed); err != nil {
		t.Errorf("round-trip failed: manifests not equal: %v", err)
	}
}

func TestRoundTripWithShards(t *testing.T) {
	modelDir := createTestModel(t)

	// Canonicalize with shards
	m, err := Canonicalize(modelDir, Options{
		ShardSize: 10,
	})
	if err != nil {
		t.Fatalf("Canonicalize failed: %v", err)
	}

	// Marshal
	payload, err := MarshalPayload(m)
	if err != nil {
		t.Fatalf("MarshalPayload failed: %v", err)
	}

	// Unmarshal
	reconstructed, err := UnmarshalPayload(payload)
	if err != nil {
		t.Fatalf("UnmarshalPayload failed: %v", err)
	}

	// Compare
	if err := Compare(m, reconstructed); err != nil {
		t.Errorf("shard round-trip failed: %v", err)
	}
}

func TestRoundTripWithIgnorePaths(t *testing.T) {
	modelDir := createTestModel(t)

	m, err := Canonicalize(modelDir, Options{
		IgnorePaths: []string{"tokenizer.json"},
	})
	if err != nil {
		t.Fatalf("Canonicalize failed: %v", err)
	}

	payload, err := MarshalPayload(m)
	if err != nil {
		t.Fatalf("MarshalPayload failed: %v", err)
	}

	reconstructed, err := UnmarshalPayload(payload)
	if err != nil {
		t.Fatalf("UnmarshalPayload failed: %v", err)
	}

	if err := Compare(m, reconstructed); err != nil {
		t.Errorf("round-trip with ignore paths failed: %v", err)
	}

	// Verify ignored file is not in the reconstructed manifest
	for _, desc := range reconstructed.ResourceDescriptors() {
		if desc.Identifier == "tokenizer.json" {
			t.Error("tokenizer.json should not be in reconstructed manifest")
		}
	}
}

func TestMarshalPayloadFormat(t *testing.T) {
	modelDir := createTestModel(t)

	m, err := Canonicalize(modelDir, Options{})
	if err != nil {
		t.Fatalf("Canonicalize failed: %v", err)
	}

	payload, err := MarshalPayload(m)
	if err != nil {
		t.Fatalf("MarshalPayload failed: %v", err)
	}

	// Verify the payload contains expected in-toto fields
	payloadStr := string(payload)

	expectedFields := []string{
		`"_type"`,         // in-toto statement type field
		`"subject"`,       // subject with model name
		`"predicateType"`, // predicate type
		`"predicate"`,     // predicate with resources
	}

	for _, field := range expectedFields {
		if !contains(payloadStr, field) {
			t.Errorf("payload missing expected field: %s", field)
		}
	}
}

func TestUnmarshalPayloadInvalid(t *testing.T) {
	tests := []struct {
		name    string
		payload string
	}{
		{"empty", ""},
		{"invalid json", "{not json}"},
		{"missing predicateType", `{"subject": []}`},
		{"wrong predicateType", `{"predicateType": "wrong", "subject": []}`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := UnmarshalPayload([]byte(tt.payload))
			if err == nil {
				t.Errorf("expected error for %s", tt.name)
			}
		})
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && searchString(s, substr)
}

func searchString(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
