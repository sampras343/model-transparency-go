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

package serialization

import (
	"os"
	"path/filepath"
	"testing"
)

func TestCheckFileOrDirectory_RegularFile(t *testing.T) {
	tmpDir := t.TempDir()
	filePath := filepath.Join(tmpDir, "test.txt")
	if err := os.WriteFile(filePath, []byte("test"), 0644); err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	err := CheckFileOrDirectory(filePath, false)
	if err != nil {
		t.Errorf("Expected no error for regular file, got: %v", err)
	}
}

func TestCheckFileOrDirectory_Directory(t *testing.T) {
	tmpDir := t.TempDir()

	err := CheckFileOrDirectory(tmpDir, false)
	if err != nil {
		t.Errorf("Expected no error for directory, got: %v", err)
	}
}

func TestCheckFileOrDirectory_NonExistent(t *testing.T) {
	nonExistentPath := "/nonexistent/path/that/does/not/exist"

	err := CheckFileOrDirectory(nonExistentPath, false)
	if err == nil {
		t.Error("Expected error for non-existent path")
	}
}

func TestCheckFileOrDirectory_Symlink_NotAllowed(t *testing.T) {
	tmpDir := t.TempDir()
	targetFile := filepath.Join(tmpDir, "target.txt")
	symlinkPath := filepath.Join(tmpDir, "symlink")

	// Create target file
	if err := os.WriteFile(targetFile, []byte("test"), 0644); err != nil {
		t.Fatalf("Failed to create target file: %v", err)
	}

	// Create symlink
	if err := os.Symlink(targetFile, symlinkPath); err != nil {
		t.Skipf("Cannot create symlink (might be Windows or permission issue): %v", err)
	}

	err := CheckFileOrDirectory(symlinkPath, false)
	if err == nil {
		t.Error("Expected error for symlink when allowSymlinks=false")
	}
}

func TestCheckFileOrDirectory_Symlink_Allowed(t *testing.T) {
	tmpDir := t.TempDir()
	targetFile := filepath.Join(tmpDir, "target.txt")
	symlinkPath := filepath.Join(tmpDir, "symlink")

	// Create target file
	if err := os.WriteFile(targetFile, []byte("test"), 0644); err != nil {
		t.Fatalf("Failed to create target file: %v", err)
	}

	// Create symlink
	if err := os.Symlink(targetFile, symlinkPath); err != nil {
		t.Skipf("Cannot create symlink (might be Windows or permission issue): %v", err)
	}

	err := CheckFileOrDirectory(symlinkPath, true)
	if err != nil {
		t.Errorf("Expected no error for symlink when allowSymlinks=true, got: %v", err)
	}
}

func TestCheckFileOrDirectory_BrokenSymlink(t *testing.T) {
	tmpDir := t.TempDir()
	symlinkPath := filepath.Join(tmpDir, "broken_symlink")

	// Create symlink pointing to non-existent target
	if err := os.Symlink("/nonexistent/target", symlinkPath); err != nil {
		t.Skipf("Cannot create symlink (might be Windows or permission issue): %v", err)
	}

	err := CheckFileOrDirectory(symlinkPath, true)
	if err == nil {
		t.Error("Expected error for broken symlink even when allowSymlinks=true")
	}
}

func TestShouldIgnore_EmptyIgnoreList(t *testing.T) {
	result := ShouldIgnore("/some/path", []string{})
	if result {
		t.Error("Expected false when ignore list is empty")
	}
}

func TestShouldIgnore_ExactMatch(t *testing.T) {
	tmpDir := t.TempDir()
	testPath := filepath.Join(tmpDir, "file.txt")

	// Create the file
	if err := os.WriteFile(testPath, []byte("test"), 0644); err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	result := ShouldIgnore(testPath, []string{testPath})
	if !result {
		t.Error("Expected true for exact path match")
	}
}

func TestShouldIgnore_ParentDirectory(t *testing.T) {
	tmpDir := t.TempDir()
	subDir := filepath.Join(tmpDir, "subdir")
	testFile := filepath.Join(subDir, "file.txt")

	// Create subdirectory and file
	if err := os.MkdirAll(subDir, 0755); err != nil {
		t.Fatalf("Failed to create subdirectory: %v", err)
	}
	if err := os.WriteFile(testFile, []byte("test"), 0644); err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	// Ignore the parent directory
	result := ShouldIgnore(testFile, []string{subDir})
	if !result {
		t.Error("Expected true when parent directory is in ignore list")
	}
}

func TestShouldIgnore_NotInIgnoreList(t *testing.T) {
	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, "file.txt")
	otherFile := filepath.Join(tmpDir, "other.txt")

	// Create files
	if err := os.WriteFile(testFile, []byte("test"), 0644); err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}
	if err := os.WriteFile(otherFile, []byte("other"), 0644); err != nil {
		t.Fatalf("Failed to create other file: %v", err)
	}

	result := ShouldIgnore(testFile, []string{otherFile})
	if result {
		t.Error("Expected false when path is not in ignore list")
	}
}

func TestShouldIgnore_RelativePaths(t *testing.T) {
	tmpDir := t.TempDir()

	// Create a .git directory
	gitDir := filepath.Join(tmpDir, ".git")
	if err := os.MkdirAll(gitDir, 0755); err != nil {
		t.Fatalf("Failed to create .git directory: %v", err)
	}

	gitConfig := filepath.Join(gitDir, "config")
	if err := os.WriteFile(gitConfig, []byte("test"), 0644); err != nil {
		t.Fatalf("Failed to create git config: %v", err)
	}

	// Test with relative path ".git"
	result := ShouldIgnore(gitConfig, []string{".git"})
	if result {
		// This may or may not be ignored depending on current working directory
		// The test verifies the function doesn't crash
		t.Logf("Relative path handling: gitConfig ignored=%v", result)
	}
}

func TestShouldIgnore_EmptyStringInIgnoreList(t *testing.T) {
	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, "file.txt")

	if err := os.WriteFile(testFile, []byte("test"), 0644); err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	// Empty strings should be skipped
	result := ShouldIgnore(testFile, []string{""})
	if result {
		t.Error("Expected false when ignore list only contains empty string")
	}
}

func TestShouldIgnore_MultipleIgnorePaths(t *testing.T) {
	tmpDir := t.TempDir()

	dir1 := filepath.Join(tmpDir, "dir1")
	dir2 := filepath.Join(tmpDir, "dir2")
	file1 := filepath.Join(dir1, "file.txt")
	file2 := filepath.Join(dir2, "file.txt")

	// Create directories and files
	if err := os.MkdirAll(dir1, 0755); err != nil {
		t.Fatalf("Failed to create dir1: %v", err)
	}
	if err := os.MkdirAll(dir2, 0755); err != nil {
		t.Fatalf("Failed to create dir2: %v", err)
	}
	if err := os.WriteFile(file1, []byte("test"), 0644); err != nil {
		t.Fatalf("Failed to create file1: %v", err)
	}
	if err := os.WriteFile(file2, []byte("test"), 0644); err != nil {
		t.Fatalf("Failed to create file2: %v", err)
	}

	ignorePaths := []string{dir1, dir2}

	// Both files should be ignored
	if !ShouldIgnore(file1, ignorePaths) {
		t.Error("Expected file1 to be ignored")
	}
	if !ShouldIgnore(file2, ignorePaths) {
		t.Error("Expected file2 to be ignored")
	}
}

func TestShouldIgnore_DifferentBranch(t *testing.T) {
	tmpDir := t.TempDir()

	dirA := filepath.Join(tmpDir, "dirA")
	dirB := filepath.Join(tmpDir, "dirB")
	fileA := filepath.Join(dirA, "file.txt")
	fileB := filepath.Join(dirB, "file.txt")

	// Create directories and files
	if err := os.MkdirAll(dirA, 0755); err != nil {
		t.Fatalf("Failed to create dirA: %v", err)
	}
	if err := os.MkdirAll(dirB, 0755); err != nil {
		t.Fatalf("Failed to create dirB: %v", err)
	}
	if err := os.WriteFile(fileA, []byte("test"), 0644); err != nil {
		t.Fatalf("Failed to create fileA: %v", err)
	}
	if err := os.WriteFile(fileB, []byte("test"), 0644); err != nil {
		t.Fatalf("Failed to create fileB: %v", err)
	}

	// Ignore only dirA
	result := ShouldIgnore(fileB, []string{dirA})
	if result {
		t.Error("Expected false for file in different directory branch")
	}
}
