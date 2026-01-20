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
	"os"
	"path/filepath"
	"testing"
)

func TestNewHashingConfig(t *testing.T) {
	config := NewHashingConfig()

	if config.serializationMethod != "files" {
		t.Errorf("Expected serializationMethod to be 'files', got '%s'", config.serializationMethod)
	}

	if config.hashAlgorithm != "sha256" {
		t.Errorf("Expected hashAlgorithm to be 'sha256', got '%s'", config.hashAlgorithm)
	}

	if config.allowSymlinks {
		t.Error("Expected allowSymlinks to be false")
	}

	if config.ignoreGitPaths {
		t.Error("Expected ignoreGitPaths to be false")
	}

	if len(config.ignoredPaths) != 0 {
		t.Errorf("Expected empty ignoredPaths, got %d items", len(config.ignoredPaths))
	}

	if config.chunkSize != 8192 {
		t.Errorf("Expected chunkSize to be 8192, got %d", config.chunkSize)
	}
}

func TestUseFileSerialization(t *testing.T) {
	config := NewHashingConfig()
	ignorePaths := []string{"path1", "path2"}

	config.UseFileSerialization("sha256", true, ignorePaths)

	if config.serializationMethod != "files" {
		t.Errorf("Expected serializationMethod to be 'files', got '%s'", config.serializationMethod)
	}

	if config.hashAlgorithm != "sha256" {
		t.Errorf("Expected hashAlgorithm to be 'sha256', got '%s'", config.hashAlgorithm)
	}

	if !config.allowSymlinks {
		t.Error("Expected allowSymlinks to be true")
	}

	if len(config.ignoredPaths) != 2 {
		t.Errorf("Expected 2 ignoredPaths, got %d", len(config.ignoredPaths))
	}
}

func TestUseShardSerialization(t *testing.T) {
	config := NewHashingConfig()
	ignorePaths := []string{"path1"}
	shardSize := int64(1024 * 1024)

	config.UseShardSerialization("sha256", shardSize, false, ignorePaths)

	if config.serializationMethod != "shards" {
		t.Errorf("Expected serializationMethod to be 'shards', got '%s'", config.serializationMethod)
	}

	if config.shardSize != shardSize {
		t.Errorf("Expected shardSize to be %d, got %d", shardSize, config.shardSize)
	}

	if config.allowSymlinks {
		t.Error("Expected allowSymlinks to be false")
	}
}

func TestSetIgnoredPaths_WithoutGitPaths(t *testing.T) {
	config := NewHashingConfig()
	paths := []string{"custom1", "custom2"}

	config.SetIgnoredPaths(paths, false)

	if len(config.ignoredPaths) != 2 {
		t.Errorf("Expected 2 ignoredPaths, got %d", len(config.ignoredPaths))
	}

	if config.ignoreGitPaths {
		t.Error("Expected ignoreGitPaths to be false")
	}

	// Verify custom paths are present
	for _, p := range paths {
		found := false
		for _, ip := range config.ignoredPaths {
			if ip == p {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Expected path '%s' to be in ignoredPaths", p)
		}
	}
}

func TestSetIgnoredPaths_WithGitPaths(t *testing.T) {
	config := NewHashingConfig()
	customPaths := []string{"custom1"}

	config.SetIgnoredPaths(customPaths, true)

	if !config.ignoreGitPaths {
		t.Error("Expected ignoreGitPaths to be true")
	}

	// Should have at least custom paths + 4 git paths
	expectedMinCount := len(customPaths) + len(gitRelatedPaths)
	if len(config.ignoredPaths) < expectedMinCount {
		t.Errorf("Expected at least %d ignoredPaths (1 custom + 4 git), got %d", expectedMinCount, len(config.ignoredPaths))
	}

	// Verify all git paths are present
	gitPaths := []string{".git", ".gitattributes", ".github", ".gitignore"}
	for _, gitPath := range gitPaths {
		found := false
		for _, ip := range config.ignoredPaths {
			if ip == gitPath {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Expected git path '%s' to be in ignoredPaths", gitPath)
		}
	}
}

func TestSetIgnoredPaths_StoresInManifest(t *testing.T) {
	config := NewHashingConfig()

	// Set ignored paths with git paths
	config.SetIgnoredPaths([]string{}, true)

	// Get serialization type
	serializationType := config.GetSerializationType()

	// Check that ignore_paths are stored
	params := serializationType.Parameters()
	ignorePathsInterface, ok := params["ignore_paths"]
	if !ok {
		t.Fatal("Expected ignore_paths to be in serialization parameters")
	}

	ignorePaths, ok := ignorePathsInterface.([]string)
	if !ok {
		t.Fatal("Expected ignore_paths to be []string")
	}

	// Should contain at least all 4 git paths
	if len(ignorePaths) < 4 {
		t.Errorf("Expected at least 4 git paths in serialization, got %d", len(ignorePaths))
	}

	// Verify all git paths are present
	gitPaths := []string{".git", ".gitattributes", ".github", ".gitignore"}
	for _, gitPath := range gitPaths {
		found := false
		for _, p := range ignorePaths {
			if p == gitPath {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Expected git path '%s' in ignore_paths", gitPath)
		}
	}
}

func TestAddIgnoredPaths(t *testing.T) {
	config := NewHashingConfig()
	modelPath := "/test/model"
	newPaths := []string{"relative/path", "/absolute/path"}

	config.AddIgnoredPaths(modelPath, newPaths)

	if len(config.ignoredPaths) != 2 {
		t.Errorf("Expected 2 ignoredPaths, got %d", len(config.ignoredPaths))
	}

	// Relative path should be converted to absolute
	expectedRelative := filepath.Join(modelPath, "relative/path")
	found := false
	for _, p := range config.ignoredPaths {
		if p == expectedRelative {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("Expected relative path to be converted to '%s'", expectedRelative)
	}

	// Absolute path should remain absolute
	found = false
	for _, p := range config.ignoredPaths {
		if p == "/absolute/path" {
			found = true
			break
		}
	}
	if !found {
		t.Error("Expected absolute path to remain unchanged")
	}
}

func TestSetAllowSymlinks(t *testing.T) {
	config := NewHashingConfig()

	config.SetAllowSymlinks(true)
	if !config.allowSymlinks {
		t.Error("Expected allowSymlinks to be true")
	}

	config.SetAllowSymlinks(false)
	if config.allowSymlinks {
		t.Error("Expected allowSymlinks to be false")
	}
}

func TestSetChunkSize(t *testing.T) {
	config := NewHashingConfig()

	config.SetChunkSize(16384)
	if config.chunkSize != 16384 {
		t.Errorf("Expected chunkSize to be 16384, got %d", config.chunkSize)
	}
}

func TestShouldIgnorePath(t *testing.T) {
	config := NewHashingConfig()
	modelPath := "/test/model"

	tests := []struct {
		name         string
		ignoredPaths []string
		testPath     string
		shouldIgnore bool
	}{
		{
			name:         "exact match relative",
			ignoredPaths: []string{".git"},
			testPath:     filepath.Join(modelPath, ".git"),
			shouldIgnore: true,
		},
		{
			name:         "prefix match",
			ignoredPaths: []string{".git"},
			testPath:     filepath.Join(modelPath, ".git/config"),
			shouldIgnore: true,
		},
		{
			name:         "no match",
			ignoredPaths: []string{".git"},
			testPath:     filepath.Join(modelPath, "file.txt"),
			shouldIgnore: false,
		},
		{
			name:         "absolute path match",
			ignoredPaths: []string{filepath.Join(modelPath, "ignored.txt")},
			testPath:     filepath.Join(modelPath, "ignored.txt"),
			shouldIgnore: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config.ignoredPaths = tt.ignoredPaths
			result := config.shouldIgnorePath(tt.testPath, modelPath)
			if result != tt.shouldIgnore {
				t.Errorf("Expected shouldIgnorePath to return %v, got %v", tt.shouldIgnore, result)
			}
		})
	}
}

func TestGetSerializationType_Files(t *testing.T) {
	config := NewHashingConfig()
	config.UseFileSerialization("sha256", false, []string{"test"})

	serializationType := config.GetSerializationType()

	if serializationType == nil {
		t.Fatal("Expected non-nil serializationType")
	}

	params := serializationType.Parameters()

	if method, ok := params["method"].(string); !ok || method != "files" {
		t.Errorf("Expected method to be 'files', got '%v'", params["method"])
	}

	if hashType, ok := params["hash_type"].(string); !ok || hashType != "sha256" {
		t.Errorf("Expected hash_type to be 'sha256', got '%v'", params["hash_type"])
	}

	if allowSymlinks, ok := params["allow_symlinks"].(bool); !ok || allowSymlinks {
		t.Errorf("Expected allow_symlinks to be false, got '%v'", params["allow_symlinks"])
	}
}

func TestGetSerializationType_Shards(t *testing.T) {
	config := NewHashingConfig()
	shardSize := int64(1024 * 1024)
	config.UseShardSerialization("sha256", shardSize, false, []string{"test"})

	serializationType := config.GetSerializationType()

	if serializationType == nil {
		t.Fatal("Expected non-nil serializationType")
	}

	params := serializationType.Parameters()

	if method, ok := params["method"].(string); !ok || method != "shards" {
		t.Errorf("Expected method to be 'shards', got '%v'", params["method"])
	}

	if shard, ok := params["shard_size"].(int64); !ok || shard != shardSize {
		t.Errorf("Expected shard_size to be %d, got '%v'", shardSize, params["shard_size"])
	}
}

func TestHash_WithGitPaths(t *testing.T) {
	// Create temporary test directory
	tmpDir := t.TempDir()

	// Create test files
	testFiles := []string{
		"file1.txt",
		"file2.txt",
		".git/config",
		".gitignore",
		".gitattributes",
	}

	for _, f := range testFiles {
		path := filepath.Join(tmpDir, f)
		dir := filepath.Dir(path)
		if err := os.MkdirAll(dir, 0755); err != nil {
			t.Fatalf("Failed to create directory %s: %v", dir, err)
		}
		if err := os.WriteFile(path, []byte("test content"), 0644); err != nil {
			t.Fatalf("Failed to create file %s: %v", f, err)
		}
	}

	config := NewHashingConfig()
	config.SetIgnoredPaths([]string{}, true) // Enable git paths ignore

	manifest, err := config.Hash(tmpDir, nil)
	if err != nil {
		t.Fatalf("Hash failed: %v", err)
	}

	if manifest == nil {
		t.Fatal("Expected non-nil manifest")
	}

	// Verify serialization includes ignore_paths
	params := manifest.SerializationParameters()
	ignorePathsInterface, ok := params["ignore_paths"]
	if !ok {
		t.Fatal("Expected ignore_paths in serialization parameters")
	}

	ignorePaths, ok := ignorePathsInterface.([]string)
	if !ok {
		t.Fatal("Expected ignore_paths to be []string")
	}

	// Should contain 4 git paths
	gitPathsFound := 0
	for _, path := range ignorePaths {
		if path == ".git" || path == ".gitignore" || path == ".gitattributes" || path == ".github" {
			gitPathsFound++
		}
	}

	if gitPathsFound != 4 {
		t.Errorf("Expected 4 git paths in ignore_paths, found %d", gitPathsFound)
	}
}

func TestHash_WithSpecificFiles(t *testing.T) {
	// Create temporary test directory
	tmpDir := t.TempDir()

	// Create test files
	testFiles := []string{
		"file1.txt",
		"file2.txt",
		"file3.txt",
	}

	for _, f := range testFiles {
		path := filepath.Join(tmpDir, f)
		if err := os.WriteFile(path, []byte("test content"), 0644); err != nil {
			t.Fatalf("Failed to create file %s: %v", f, err)
		}
	}

	config := NewHashingConfig()

	// Hash only specific files
	filesToHash := []string{"file1.txt", "file2.txt"}
	manifest, err := config.Hash(tmpDir, filesToHash)
	if err != nil {
		t.Fatalf("Hash failed: %v", err)
	}

	// Verify manifest was created
	if manifest == nil {
		t.Fatal("Expected non-nil manifest")
	}

	// Check serialization parameters were set
	params := manifest.SerializationParameters()
	if params == nil {
		t.Fatal("Expected non-nil serialization parameters")
	}
}

func TestHash_NonExistentDirectory(t *testing.T) {
	config := NewHashingConfig()

	_, err := config.Hash("/nonexistent/directory", nil)
	if err == nil {
		t.Error("Expected error for non-existent directory")
	}
}

func TestMethodChaining(t *testing.T) {
	// Test that methods return config for chaining
	config := NewHashingConfig().
		SetIgnoredPaths([]string{"test"}, true).
		SetAllowSymlinks(true).
		SetChunkSize(16384)

	if !config.ignoreGitPaths {
		t.Error("Expected ignoreGitPaths to be true")
	}

	if !config.allowSymlinks {
		t.Error("Expected allowSymlinks to be true")
	}

	if config.chunkSize != 16384 {
		t.Errorf("Expected chunkSize to be 16384, got %d", config.chunkSize)
	}

	// Should have at least git paths + custom path
	if len(config.ignoredPaths) < 5 {
		t.Errorf("Expected at least 5 ignoredPaths, got %d", len(config.ignoredPaths))
	}
}
