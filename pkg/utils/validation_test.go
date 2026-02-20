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

package utils

import (
	"os"
	"path/filepath"
	"testing"
)

func TestValidateFileExists(t *testing.T) {
	// Create temp file
	tmpFile, err := os.CreateTemp("", "test-*.txt")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	defer os.Remove(tmpFile.Name())
	tmpFile.Close()

	tests := []struct {
		name      string
		fieldName string
		path      string
		wantErr   bool
	}{
		{
			name:      "valid file",
			fieldName: "test file",
			path:      tmpFile.Name(),
			wantErr:   false,
		},
		{
			name:      "empty path",
			fieldName: "test file",
			path:      "",
			wantErr:   true,
		},
		{
			name:      "non-existent file",
			fieldName: "test file",
			path:      "/nonexistent/file.txt",
			wantErr:   true,
		},
		{
			name:      "directory instead of file",
			fieldName: "test file",
			path:      os.TempDir(),
			wantErr:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateFileExists(tt.fieldName, tt.path)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateFileExists() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestValidateMultiple(t *testing.T) {
	// Create temp directory with files
	tmpDir, err := os.MkdirTemp("", "test-multi-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	file1 := filepath.Join(tmpDir, "file1.txt")
	file2 := filepath.Join(tmpDir, "file2.txt")
	if err := os.WriteFile(file1, []byte("test"), 0644); err != nil {
		t.Fatalf("Failed to write file1: %v", err)
	}
	if err := os.WriteFile(file2, []byte("test"), 0644); err != nil {
		t.Fatalf("Failed to write file2: %v", err)
	}

	tests := []struct {
		name      string
		fieldName string
		paths     []string
		pathType  PathType
		wantErr   bool
	}{
		{
			name:      "all valid files",
			fieldName: "test files",
			paths:     []string{file1, file2},
			pathType:  PathTypeFile,
			wantErr:   false,
		},
		{
			name:      "empty path in slice",
			fieldName: "test files",
			paths:     []string{file1, "", file2},
			pathType:  PathTypeFile,
			wantErr:   true,
		},
		{
			name:      "non-existent file",
			fieldName: "test files",
			paths:     []string{file1, "/nonexistent.txt"},
			pathType:  PathTypeFile,
			wantErr:   true,
		},
		{
			name:      "empty slice",
			fieldName: "test files",
			paths:     []string{},
			pathType:  PathTypeFile,
			wantErr:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateMultiple(tt.fieldName, tt.paths, tt.pathType)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateMultiple() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestValidateOptionalFile(t *testing.T) {
	tmpFile, err := os.CreateTemp("", "test-*.txt")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	defer os.Remove(tmpFile.Name())
	tmpFile.Close()

	tests := []struct {
		name      string
		fieldName string
		path      string
		wantErr   bool
	}{
		{
			name:      "empty path (optional)",
			fieldName: "optional file",
			path:      "",
			wantErr:   false,
		},
		{
			name:      "valid file",
			fieldName: "optional file",
			path:      tmpFile.Name(),
			wantErr:   false,
		},
		{
			name:      "invalid file",
			fieldName: "optional file",
			path:      "/nonexistent.txt",
			wantErr:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateOptionalFile(tt.fieldName, tt.path)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateOptionalFile() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
