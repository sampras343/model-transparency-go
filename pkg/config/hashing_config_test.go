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
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"testing"

	"github.com/sigstore/model-signing/pkg/logging"
	"github.com/sigstore/model-signing/pkg/utils"
)

type capturingLogger struct {
	mu       sync.Mutex
	warnings []string
}

func (l *capturingLogger) Debug(string, ...interface{}) {}
func (l *capturingLogger) Debugln(string)               {}
func (l *capturingLogger) Info(string, ...interface{})  {}
func (l *capturingLogger) Infoln(string)                {}
func (l *capturingLogger) Error(string, ...interface{}) {}
func (l *capturingLogger) Errorln(string)               {}
func (l *capturingLogger) GetLevel() logging.LogLevel   { return logging.LevelDebug }
func (l *capturingLogger) Silent() bool                 { return false }
func (l *capturingLogger) Warnln(msg string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.warnings = append(l.warnings, msg)
}
func (l *capturingLogger) Warn(format string, args ...interface{}) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.warnings = append(l.warnings, fmt.Sprintf(format, args...))
}
func (l *capturingLogger) WithField(string, interface{}) logging.Logger     { return l }
func (l *capturingLogger) WithFields(map[string]interface{}) logging.Logger { return l }
func (l *capturingLogger) Warnings() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]string{}, l.warnings...)
}

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
	newPaths := []string{"relative/path", "/test/model/subdir/file"}

	config.AddIgnoredPaths(modelPath, newPaths)

	if len(config.ignoredPaths) != 2 {
		t.Errorf("Expected 2 ignoredPaths, got %d", len(config.ignoredPaths))
	}

	// Relative path should stay relative with forward slashes
	found := false
	for _, p := range config.ignoredPaths {
		if p == "relative/path" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("Expected relative path 'relative/path', got %v", config.ignoredPaths)
	}

	// Absolute path should be converted to relative POSIX path
	found = false
	for _, p := range config.ignoredPaths {
		if p == "subdir/file" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("Expected absolute path converted to 'subdir/file', got %v", config.ignoredPaths)
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

func TestHash_WithSpecificFilesAndIgnoreGitPaths(t *testing.T) {
	// Create temporary test directory
	tmpDir := t.TempDir()

	// Create test files including git files
	testFiles := []string{
		"file1.txt",
		"file2.txt",
		".gitignore",
		".gitattributes",
	}

	for _, f := range testFiles {
		path := filepath.Join(tmpDir, f)
		if err := os.WriteFile(path, []byte("test content"), 0644); err != nil {
			t.Fatalf("Failed to create file %s: %v", f, err)
		}
	}

	config := NewHashingConfig()
	config.SetIgnoredPaths([]string{}, true) // Enable git paths ignore

	// Provide explicit list including git files (simulating what happens during verification)
	filesToHash := []string{"file1.txt", "file2.txt", ".gitignore", ".gitattributes"}
	manifest, err := config.Hash(tmpDir, filesToHash)
	if err != nil {
		t.Fatalf("Hash failed: %v", err)
	}

	if manifest == nil {
		t.Fatal("Expected non-nil manifest")
	}

	// Verify that git files were filtered out
	resourceDescriptors := manifest.ResourceDescriptors()
	for _, rd := range resourceDescriptors {
		if rd.Identifier == ".gitignore" || rd.Identifier == ".gitattributes" {
			t.Errorf("Expected git file '%s' to be filtered out, but it was included in manifest", rd.Identifier)
		}
	}

	// Verify that only non-git files are in the manifest
	if len(resourceDescriptors) != 2 {
		t.Errorf("Expected 2 files in manifest (file1.txt, file2.txt), got %d", len(resourceDescriptors))
	}
}

func TestHash_WithSpecificFilesWithoutIgnoreGitPaths(t *testing.T) {
	// Create temporary test directory
	tmpDir := t.TempDir()

	// Create test files including git files
	testFiles := []string{
		"file1.txt",
		".gitignore",
	}

	for _, f := range testFiles {
		path := filepath.Join(tmpDir, f)
		if err := os.WriteFile(path, []byte("test content"), 0644); err != nil {
			t.Fatalf("Failed to create file %s: %v", f, err)
		}
	}

	config := NewHashingConfig()
	config.SetIgnoredPaths([]string{}, false) // Disable git paths ignore

	// Provide explicit list including git files
	filesToHash := []string{"file1.txt", ".gitignore"}
	manifest, err := config.Hash(tmpDir, filesToHash)
	if err != nil {
		t.Fatalf("Hash failed: %v", err)
	}

	if manifest == nil {
		t.Fatal("Expected non-nil manifest")
	}

	// Verify that git files were NOT filtered out (since ignoreGitPaths is false)
	resourceDescriptors := manifest.ResourceDescriptors()
	foundGitFile := false
	for _, rd := range resourceDescriptors {
		if rd.Identifier == ".gitignore" {
			foundGitFile = true
			break
		}
	}

	if !foundGitFile {
		t.Error("Expected .gitignore to be included in manifest when ignoreGitPaths is false")
	}

	// Verify that both files are in the manifest
	if len(resourceDescriptors) != 2 {
		t.Errorf("Expected 2 files in manifest (file1.txt, .gitignore), got %d", len(resourceDescriptors))
	}
}

func TestWalkDirectory_SymlinkRejectedWhenNotAllowed(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "real.txt")
	if err := os.WriteFile(target, []byte("data"), 0644); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link.txt")
	if err := os.Symlink(target, link); err != nil {
		t.Skip("symlinks not supported on this platform")
	}

	hc := NewHashingConfig()
	hc.SetAllowSymlinks(false)
	_, err := hc.Hash(dir, nil)
	if err == nil {
		t.Fatal("expected error when symlink encountered with allow_symlinks=false")
	}
	if !errors.Is(err, ErrSymlinkNotAllowed) {
		t.Fatalf("expected ErrSymlinkNotAllowed, got: %v", err)
	}
}

func TestWalkDirectory_SymlinkAllowedIncludesBothEntries(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "real.txt")
	if err := os.WriteFile(target, []byte("data"), 0644); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link.txt")
	if err := os.Symlink(target, link); err != nil {
		t.Skip("symlinks not supported on this platform")
	}

	hc := NewHashingConfig()
	hc.SetAllowSymlinks(true)
	hc.UseFileSerialization("sha256", true, nil)
	m, err := hc.Hash(dir, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	descs := m.ResourceDescriptors()
	if len(descs) != 2 {
		t.Fatalf("expected 2 descriptors (real.txt + link.txt), got %d", len(descs))
	}
	ids := map[string]bool{}
	for _, d := range descs {
		ids[d.Identifier] = true
	}
	if !ids["real.txt"] || !ids["link.txt"] {
		t.Errorf("expected real.txt and link.txt, got %v", ids)
	}
}

func TestWalkDirectory_RelativeSymlinkRejected(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "a.txt"), []byte("a"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("a.txt", filepath.Join(dir, "b.txt")); err != nil {
		t.Skip("symlinks not supported on this platform")
	}

	hc := NewHashingConfig()
	hc.SetAllowSymlinks(false)
	_, err := hc.Hash(dir, nil)
	if !errors.Is(err, ErrSymlinkNotAllowed) {
		t.Fatalf("expected ErrSymlinkNotAllowed for relative symlink, got: %v", err)
	}
}

func TestWalkDirectory_FIFOSkipped(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("FIFOs not supported on Windows")
	}

	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "ok.txt"), []byte("ok"), 0644); err != nil {
		t.Fatal(err)
	}
	fifo := filepath.Join(dir, "pipe.fifo")
	if err := syscall.Mkfifo(fifo, 0600); err != nil {
		t.Skipf("mkfifo not supported: %v", err)
	}

	hc := NewHashingConfig()
	hc.UseFileSerialization("sha256", false, nil)
	m, err := hc.Hash(dir, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	descs := m.ResourceDescriptors()
	if len(descs) != 1 {
		t.Fatalf("expected 1 descriptor (ok.txt only), got %d", len(descs))
	}
	if descs[0].Identifier != "ok.txt" {
		t.Errorf("expected ok.txt, got %s", descs[0].Identifier)
	}
}

func TestWalkDirectory_OnlySymlinks_RejectsSymlink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "hidden.txt")
	if err := os.WriteFile(target, []byte("h"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(dir, "only-link.txt")); err != nil {
		t.Skip("symlinks not supported on this platform")
	}
	if err := os.Remove(target); err != nil {
		t.Fatal(err)
	}

	hc := NewHashingConfig()
	hc.SetAllowSymlinks(false)
	_, err := hc.Hash(dir, nil)
	if !errors.Is(err, ErrSymlinkNotAllowed) {
		t.Fatalf("expected ErrSymlinkNotAllowed, got: %v", err)
	}
}

func TestWalkDirectory_SymlinkOutsideRootWarns(t *testing.T) {
	modelDir := t.TempDir()
	outsideDir := t.TempDir()

	if err := os.WriteFile(filepath.Join(modelDir, "real.txt"), []byte("data"), 0644); err != nil {
		t.Fatal(err)
	}
	outsideFile := filepath.Join(outsideDir, "external.txt")
	if err := os.WriteFile(outsideFile, []byte("external"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outsideFile, filepath.Join(modelDir, "link.txt")); err != nil {
		t.Skip("symlinks not supported on this platform")
	}

	logger := &capturingLogger{}
	hc := NewHashingConfig()
	hc.SetAllowSymlinks(true)
	hc.SetLogger(logger)
	hc.UseFileSerialization("sha256", true, nil)

	m, err := hc.Hash(modelDir, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if m == nil {
		t.Fatal("expected non-nil manifest")
	}

	warnings := logger.Warnings()
	found := false
	for _, w := range warnings {
		if strings.Contains(w, "outside model root") {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected warning about symlink target outside model root, got: %v", warnings)
	}
}

func TestWalkDirectory_SymlinkCycleWarns(t *testing.T) {
	modelDir := t.TempDir()

	if err := os.WriteFile(filepath.Join(modelDir, "real.txt"), []byte("data"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("self", filepath.Join(modelDir, "self")); err != nil {
		t.Skip("symlinks not supported on this platform")
	}

	logger := &capturingLogger{}
	hc := NewHashingConfig()
	hc.SetAllowSymlinks(true)
	hc.SetLogger(logger)
	hc.UseFileSerialization("sha256", true, nil)

	_, err := hc.Hash(modelDir, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	warnings := logger.Warnings()
	found := false
	for _, w := range warnings {
		if strings.Contains(w, "cycle") || strings.Contains(w, "broken link") {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected warning about symlink cycle, got: %v", warnings)
	}
}

func TestWalkDirectory_SymlinkInsideRootNoWarning(t *testing.T) {
	modelDir := t.TempDir()

	target := filepath.Join(modelDir, "real.txt")
	if err := os.WriteFile(target, []byte("data"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(modelDir, "link.txt")); err != nil {
		t.Skip("symlinks not supported on this platform")
	}

	logger := &capturingLogger{}
	hc := NewHashingConfig()
	hc.SetAllowSymlinks(true)
	hc.SetLogger(logger)
	hc.UseFileSerialization("sha256", true, nil)

	_, err := hc.Hash(modelDir, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	for _, w := range logger.Warnings() {
		if strings.Contains(w, "outside model root") {
			t.Errorf("unexpected outside-root warning for internal symlink: %s", w)
		}
	}
}

func TestHashFiles_InvalidUTF8PathRejected(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows does not allow invalid UTF-8 in filenames")
	}

	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "valid.txt"), []byte("ok"), 0644); err != nil {
		t.Fatal(err)
	}

	// Create a file with invalid UTF-8 bytes in the name (0xff is never valid in UTF-8)
	invalidName := "bad\xffname.txt"
	if err := os.WriteFile(filepath.Join(dir, invalidName), []byte("data"), 0644); err != nil {
		t.Skipf("OS rejected invalid UTF-8 filename: %v", err)
	}

	hc := NewHashingConfig()
	hc.UseFileSerialization("sha256", false, nil)

	_, err := hc.Hash(dir, nil)
	if err == nil {
		t.Fatal("expected error for invalid UTF-8 path")
	}
	if !errors.Is(err, ErrInvalidUTF8Path) {
		t.Fatalf("expected ErrInvalidUTF8Path, got: %v", err)
	}
}

func TestHashShards_InvalidUTF8PathRejected(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows does not allow invalid UTF-8 in filenames")
	}

	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "valid.txt"), []byte("ok"), 0644); err != nil {
		t.Fatal(err)
	}

	invalidName := "bad\xffname.txt"
	if err := os.WriteFile(filepath.Join(dir, invalidName), []byte("data"), 0644); err != nil {
		t.Skipf("OS rejected invalid UTF-8 filename: %v", err)
	}

	hc := NewHashingConfig()
	hc.UseShardSerialization("sha256", 16, false, nil)

	_, err := hc.Hash(dir, nil)
	if err == nil {
		t.Fatal("expected error for invalid UTF-8 path")
	}
	if !errors.Is(err, ErrInvalidUTF8Path) {
		t.Fatalf("expected ErrInvalidUTF8Path, got: %v", err)
	}
}

func TestHashFiles_PathTraversalRejected(t *testing.T) {
	modelDir := t.TempDir()
	outsideDir := t.TempDir()

	if err := os.WriteFile(filepath.Join(modelDir, "ok.txt"), []byte("ok"), 0644); err != nil {
		t.Fatal(err)
	}
	escapee := filepath.Join(outsideDir, "secret.txt")
	if err := os.WriteFile(escapee, []byte("secret"), 0644); err != nil {
		t.Fatal(err)
	}

	hc := NewHashingConfig()
	hc.UseFileSerialization("sha256", false, nil)

	_, err := hc.Hash(modelDir, []string{escapee})
	if err == nil {
		t.Fatal("expected error for path traversal")
	}
	if !errors.Is(err, utils.ErrPathTraversal) {
		t.Fatalf("expected utils.ErrPathTraversal, got: %v", err)
	}
}

func TestHashShards_PathTraversalRejected(t *testing.T) {
	modelDir := t.TempDir()
	outsideDir := t.TempDir()

	if err := os.WriteFile(filepath.Join(modelDir, "ok.txt"), []byte("ok"), 0644); err != nil {
		t.Fatal(err)
	}
	escapee := filepath.Join(outsideDir, "secret.txt")
	if err := os.WriteFile(escapee, []byte("secret"), 0644); err != nil {
		t.Fatal(err)
	}

	hc := NewHashingConfig()
	hc.UseShardSerialization("sha256", 16, false, nil)

	_, err := hc.Hash(modelDir, []string{escapee})
	if err == nil {
		t.Fatal("expected error for path traversal")
	}
	if !errors.Is(err, utils.ErrPathTraversal) {
		t.Fatalf("expected utils.ErrPathTraversal, got: %v", err)
	}
}

func TestHashFiles_NonRegularFileSkipped(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("FIFOs are not supported on Windows")
	}

	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "regular.txt"), []byte("data"), 0644); err != nil {
		t.Fatal(err)
	}
	fifoPath := filepath.Join(dir, "myfifo")
	if err := syscall.Mkfifo(fifoPath, 0644); err != nil {
		t.Fatalf("failed to create FIFO: %v", err)
	}

	hc := NewHashingConfig()
	hc.UseFileSerialization("sha256", false, nil)

	m, err := hc.Hash(dir, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	for _, item := range m.ResourceDescriptors() {
		if item.Identifier == "myfifo" {
			t.Error("FIFO should not appear in manifest")
		}
	}
}

func TestHashShards_NonRegularFileSkipped(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("FIFOs are not supported on Windows")
	}

	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "regular.txt"), []byte("data"), 0644); err != nil {
		t.Fatal(err)
	}
	fifoPath := filepath.Join(dir, "myfifo")
	if err := syscall.Mkfifo(fifoPath, 0644); err != nil {
		t.Fatalf("failed to create FIFO: %v", err)
	}

	hc := NewHashingConfig()
	hc.UseShardSerialization("sha256", 16, false, nil)

	m, err := hc.Hash(dir, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	for _, item := range m.ResourceDescriptors() {
		if item.Identifier == "myfifo" {
			t.Error("FIFO should not appear in manifest")
		}
	}
}

func TestHashFiles_NonRegularFileSkippedViaFilesToHash(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("FIFOs are not supported on Windows")
	}

	dir := t.TempDir()
	regularPath := filepath.Join(dir, "regular.txt")
	if err := os.WriteFile(regularPath, []byte("data"), 0644); err != nil {
		t.Fatal(err)
	}
	fifoPath := filepath.Join(dir, "myfifo")
	if err := syscall.Mkfifo(fifoPath, 0644); err != nil {
		t.Fatalf("failed to create FIFO: %v", err)
	}

	hc := NewHashingConfig()
	hc.UseFileSerialization("sha256", false, nil)

	m, err := hc.Hash(dir, []string{regularPath, fifoPath})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	for _, item := range m.ResourceDescriptors() {
		if item.Identifier == "myfifo" {
			t.Error("FIFO passed via filesToHash should not appear in manifest")
		}
	}
	if len(m.ResourceDescriptors()) != 1 {
		t.Errorf("expected 1 manifest item, got %d", len(m.ResourceDescriptors()))
	}
}

func TestHashShards_EmptyFileOmitted(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "data.bin"), []byte("content"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "empty.bin"), []byte{}, 0644); err != nil {
		t.Fatal(err)
	}

	hc := NewHashingConfig()
	hc.UseShardSerialization("sha256", 16, false, nil)

	m, err := hc.Hash(dir, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	for _, d := range m.ResourceDescriptors() {
		if strings.Contains(d.Identifier, "empty") {
			t.Errorf("zero-byte file should be omitted from shard manifest, got: %s", d.Identifier)
		}
	}
	if len(m.ResourceDescriptors()) != 1 {
		t.Fatalf("expected 1 descriptor (data.bin only), got %d", len(m.ResourceDescriptors()))
	}
}

func TestHashFiles_ValidUTF8PathAccepted(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "日本語.txt"), []byte("unicode"), 0644); err != nil {
		t.Skipf("OS rejected unicode filename: %v", err)
	}

	hc := NewHashingConfig()
	hc.UseFileSerialization("sha256", false, nil)

	m, err := hc.Hash(dir, nil)
	if err != nil {
		t.Fatalf("valid UTF-8 path should be accepted: %v", err)
	}
	if len(m.ResourceDescriptors()) != 1 {
		t.Fatalf("expected 1 descriptor, got %d", len(m.ResourceDescriptors()))
	}
}

func TestHashFiles_SingleFileUsesBasename(t *testing.T) {
	dir := t.TempDir()
	filePath := filepath.Join(dir, "model.bin")
	if err := os.WriteFile(filePath, []byte("weights"), 0644); err != nil {
		t.Fatal(err)
	}

	hc := NewHashingConfig()
	hc.UseFileSerialization("sha256", false, nil)

	m, err := hc.Hash(filePath, nil)
	if err != nil {
		t.Fatalf("Hash single file failed: %v", err)
	}

	descs := m.ResourceDescriptors()
	if len(descs) != 1 {
		t.Fatalf("expected 1 descriptor, got %d", len(descs))
	}
	if descs[0].Identifier != "model.bin" {
		t.Errorf("expected resource name 'model.bin', got %q", descs[0].Identifier)
	}
}

func TestHashShards_SingleFileUsesBasename(t *testing.T) {
	dir := t.TempDir()
	filePath := filepath.Join(dir, "model.bin")
	if err := os.WriteFile(filePath, []byte("weights-data"), 0644); err != nil {
		t.Fatal(err)
	}

	hc := NewHashingConfig()
	hc.UseShardSerialization("sha256", 4, false, nil)

	m, err := hc.Hash(filePath, nil)
	if err != nil {
		t.Fatalf("Hash single file with shards failed: %v", err)
	}

	descs := m.ResourceDescriptors()
	if len(descs) == 0 {
		t.Fatal("expected at least 1 descriptor")
	}
	for _, d := range descs {
		if strings.HasPrefix(d.Identifier, ".") {
			t.Errorf("resource name should not start with '.', got %q", d.Identifier)
		}
		if !strings.HasPrefix(d.Identifier, "model.bin") {
			t.Errorf("expected resource name starting with 'model.bin', got %q", d.Identifier)
		}
	}
}
