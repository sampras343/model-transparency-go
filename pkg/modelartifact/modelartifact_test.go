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
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
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

func TestCanonicalizeWithDefaultShardSize(t *testing.T) {
	modelDir := createTestModel(t)

	m, err := Canonicalize(modelDir, Options{
		ShardSize: -1,
	})
	if err != nil {
		t.Fatalf("Canonicalize with default shard size failed: %v", err)
	}

	// Test files are small (<1 GB), so each file is one shard
	descriptors := m.ResourceDescriptors()
	if len(descriptors) != 3 {
		t.Errorf("expected 3 descriptors (one shard per small file), got %d", len(descriptors))
	}

	params := m.SerializationParameters()
	if params["shard_size"] != DefaultShardSize {
		t.Errorf("expected shard_size=%d, got %v", DefaultShardSize, params["shard_size"])
	}
}

func TestCanonicalizeNonexistentPath(t *testing.T) {
	_, err := Canonicalize("/nonexistent/path", Options{})
	if err == nil {
		t.Error("expected error for nonexistent path")
	}
}

func TestCanonicalizeSymlinkRejected(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "real.txt")
	if err := os.WriteFile(target, []byte("data"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(dir, "link.txt")); err != nil {
		t.Skip("symlinks not supported on this platform")
	}

	_, err := Canonicalize(dir, Options{AllowSymlinks: false})
	if err == nil {
		t.Fatal("expected error when symlink encountered with allow_symlinks=false")
	}
}

func TestCanonicalizeSymlinkAllowed(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "real.txt")
	if err := os.WriteFile(target, []byte("data"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(dir, "link.txt")); err != nil {
		t.Skip("symlinks not supported on this platform")
	}

	m, err := Canonicalize(dir, Options{AllowSymlinks: true})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	descs := m.ResourceDescriptors()
	if len(descs) != 2 {
		t.Fatalf("expected 2 descriptors, got %d", len(descs))
	}
}

func TestCanonicalizeEmptyDirectory(t *testing.T) {
	dir := t.TempDir()

	_, err := Canonicalize(dir, Options{})
	if err == nil {
		t.Fatal("expected error for empty model directory")
	}
	if !errors.Is(err, ErrEmptyModel) {
		t.Errorf("expected ErrEmptyModel, got: %v", err)
	}
}

func TestCanonicalizeDirectoryWithOnlySubdirs(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "subdir", "nested"), 0755); err != nil {
		t.Fatal(err)
	}

	_, err := Canonicalize(dir, Options{})
	if err == nil {
		t.Fatal("expected error for directory with only subdirectories (no regular files)")
	}
	if !errors.Is(err, ErrEmptyModel) {
		t.Errorf("expected ErrEmptyModel, got: %v", err)
	}
}

func TestCanonicalizeAllFilesIgnored(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "only-file.txt"), []byte("data"), 0644); err != nil {
		t.Fatal(err)
	}

	_, err := Canonicalize(dir, Options{
		IgnorePaths: []string{"only-file.txt"},
	})
	if err == nil {
		t.Fatal("expected error when all files are excluded by ignore paths")
	}
	if !errors.Is(err, ErrEmptyModel) {
		t.Errorf("expected ErrEmptyModel, got: %v", err)
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
		errMsg  string
	}{
		{"empty", "", "unmarshal"},
		{"invalid json", "{not json}", "unmarshal"},
		{"missing _type", `{"predicateType": "x", "subject": []}`, "_type field missing"},
		{"wrong _type", `{"_type": "https://in-toto.io/Statement/v0", "predicateType": "x"}`, "unsupported statement type"},
		{"missing predicateType", `{"_type": "https://in-toto.io/Statement/v1", "subject": []}`, "predicateType"},
		{"wrong predicateType", `{"_type": "https://in-toto.io/Statement/v1", "predicateType": "wrong"}`, "predicate type mismatch"},
		{"empty subject name", `{"_type": "https://in-toto.io/Statement/v1", "predicateType": "https://model_signing/signature/v1.0", "subject": [{"name": "", "digest": {"sha256": "abc"}}], "predicate": {}}`, "subject name must not be empty"},
		{"empty resources", `{"_type": "https://in-toto.io/Statement/v1", "predicateType": "https://model_signing/signature/v1.0", "subject": [{"name": "m", "digest": {"sha256": "abc"}}], "predicate": {"serialization": {"method": "files", "hash_type": "sha256", "allow_symlinks": false}, "resources": []}}`, "resources array must contain at least one entry"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := UnmarshalPayload([]byte(tt.payload))
			if err == nil {
				t.Errorf("expected error for %s", tt.name)
			} else if !contains(err.Error(), tt.errMsg) {
				t.Errorf("expected error containing %q, got: %v", tt.errMsg, err)
			}
		})
	}
}

func TestCanonicalizeRejectsInvalidIgnorePaths(t *testing.T) {
	dir := createTestModel(t)

	tests := []struct {
		name string
		path string
	}{
		{"glob star", "dir/*.bin"},
		{"glob question", "dir/file?.txt"},
		{"glob bracket", "dir/[abc].txt"},
		{"leading slash", "/absolute/path"},
		{"dot-dot slash", "../escape/path"},
		{"dot-dot mid", "sub/../escape"},
		{"bare dot-dot", ".."},
		{"backslash separator", `sub\dir\file.txt`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Canonicalize(dir, Options{IgnorePaths: []string{tt.path}})
			if err == nil {
				t.Fatal("expected error for invalid ignore path")
			}
			if !errors.Is(err, ErrInvalidIgnorePath) {
				t.Errorf("expected ErrInvalidIgnorePath, got: %v", err)
			}
		})
	}
}

func TestCanonicalizeAcceptsValidIgnorePaths(t *testing.T) {
	dir := createTestModel(t)

	validPaths := []string{
		"tokenizer.json",
		"weights/layer_0.bin",
		"sub/dir/file.txt",
	}

	for _, p := range validPaths {
		t.Run(p, func(t *testing.T) {
			_, err := Canonicalize(dir, Options{IgnorePaths: []string{p}})
			if errors.Is(err, ErrInvalidIgnorePath) {
				t.Errorf("valid path %q rejected: %v", p, err)
			}
		})
	}
}

func TestCanonicalizeDefaultExcludesGitPaths(t *testing.T) {
	dir := t.TempDir()

	if err := os.WriteFile(filepath.Join(dir, "model.bin"), []byte("weights"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, ".gitignore"), []byte("*.log"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, ".gitattributes"), []byte("* text=auto"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(dir, ".git"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, ".git", "HEAD"), []byte("ref: refs/heads/main"), 0644); err != nil {
		t.Fatal(err)
	}

	// IgnoreGitPaths: true excludes git paths per spec §6.2
	m, err := Canonicalize(dir, Options{IgnoreGitPaths: true})
	if err != nil {
		t.Fatalf("Canonicalize failed: %v", err)
	}

	descs := m.ResourceDescriptors()
	if len(descs) != 1 {
		t.Fatalf("expected 1 descriptor (model.bin only), got %d", len(descs))
	}
	if descs[0].Identifier != "model.bin" {
		t.Errorf("expected model.bin, got %s", descs[0].Identifier)
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

func TestUnmarshalPayload_UnsortedResourcesRejected(t *testing.T) {
	payload := map[string]interface{}{
		"_type":         "https://in-toto.io/Statement/v1",
		"predicateType": "https://model_signing/signature/v1.0",
		"subject": []interface{}{
			map[string]interface{}{
				"name":   "test-model",
				"digest": map[string]interface{}{"sha256": "0000000000000000000000000000000000000000000000000000000000000000"},
			},
		},
		"predicate": map[string]interface{}{
			"serialization": map[string]interface{}{"method": "files", "hash_type": "sha256", "allow_symlinks": false},
			"resources": []interface{}{
				map[string]interface{}{
					"name":      "b.txt",
					"algorithm": "sha256",
					"digest":    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
				},
				map[string]interface{}{
					"name":      "a.txt",
					"algorithm": "sha256",
					"digest":    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
				},
			},
		},
	}

	data, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("failed to marshal test payload: %v", err)
	}

	_, err = UnmarshalPayload(data)
	if err == nil {
		t.Fatal("expected error for unsorted resources")
	}
	if !strings.Contains(err.Error(), "not sorted") {
		t.Fatalf("expected sort order error, got: %v", err)
	}
}

func FuzzUnmarshalPayload(f *testing.F) {
	f.Add([]byte(`{"_type":"https://in-toto.io/Statement/v1","predicateType":"https://model_signing/signature/v1.0","subject":[{"name":"test","digest":{"sha256":"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"}}],"predicate":{"serialization":{"method":"files","hash_type":"sha256","allow_symlinks":false,"ignore_paths":[]},"resources":[]}}`))
	f.Add([]byte(`{"_type":"https://in-toto.io/Statement/v0.1","predicateType":"https://model_signing/Digests/v0.1","subject":[]}`))
	f.Add([]byte(`{}`))
	f.Add([]byte(``))

	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = UnmarshalPayload(data)
	})
}

func FuzzValidateIgnorePaths(f *testing.F) {
	f.Add("cache/tmp")
	f.Add("/absolute/path")
	f.Add("../escape")
	f.Add("glob*pattern")
	f.Add("path\\backslash")
	f.Add("")

	f.Fuzz(func(t *testing.T, path string) {
		_ = validateIgnorePaths([]string{path})
	})
}

func TestUnmarshalPayload_DuplicateResourceNamesRejected(t *testing.T) {
	payload := map[string]interface{}{
		"_type":         "https://in-toto.io/Statement/v1",
		"predicateType": "https://model_signing/signature/v1.0",
		"subject": []interface{}{
			map[string]interface{}{
				"name":   "test-model",
				"digest": map[string]interface{}{"sha256": "0000000000000000000000000000000000000000000000000000000000000000"},
			},
		},
		"predicate": map[string]interface{}{
			"serialization": map[string]interface{}{"method": "files", "hash_type": "sha256", "allow_symlinks": false},
			"resources": []interface{}{
				map[string]interface{}{
					"name":      "a.txt",
					"algorithm": "sha256",
					"digest":    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
				},
				map[string]interface{}{
					"name":      "a.txt",
					"algorithm": "sha256",
					"digest":    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
				},
			},
		},
	}

	data, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("failed to marshal test payload: %v", err)
	}

	_, err = UnmarshalPayload(data)
	if err == nil {
		t.Fatal("expected error for duplicate resource names")
	}
	if !strings.Contains(err.Error(), "not sorted") {
		t.Fatalf("expected sort order error, got: %v", err)
	}
}
