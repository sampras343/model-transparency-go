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

package key

import (
	"os"
	"path/filepath"
	"testing"
)

func TestNewKeySigner_MissingModelPath(t *testing.T) {
	tmpDir := t.TempDir()
	keyFile := filepath.Join(tmpDir, "key.pem")

	// Create a dummy key file
	if err := os.WriteFile(keyFile, []byte("dummy"), 0644); err != nil {
		t.Fatalf("Failed to create key file: %v", err)
	}

	opts := KeySignerOptions{
		ModelPath:      "/nonexistent/model",
		SignaturePath:  filepath.Join(tmpDir, "sig.json"),
		PrivateKeyPath: keyFile,
	}

	_, err := NewKeySigner(opts)
	if err == nil {
		t.Error("Expected error for nonexistent model path, got nil")
	}
}

func TestNewKeySigner_MissingPrivateKey(t *testing.T) {
	tmpDir := t.TempDir()

	opts := KeySignerOptions{
		ModelPath:      tmpDir,
		SignaturePath:  filepath.Join(tmpDir, "sig.json"),
		PrivateKeyPath: "/nonexistent/key.pem",
	}

	_, err := NewKeySigner(opts)
	if err == nil {
		t.Error("Expected error for nonexistent private key, got nil")
	}
}

func TestNewKeySigner_ValidPaths(t *testing.T) {
	tmpDir := t.TempDir()

	// Create model directory
	modelDir := filepath.Join(tmpDir, "model")
	if err := os.MkdirAll(modelDir, 0755); err != nil {
		t.Fatalf("Failed to create model directory: %v", err)
	}

	// Create a dummy key file
	keyFile := filepath.Join(tmpDir, "key.pem")
	if err := os.WriteFile(keyFile, []byte("dummy"), 0644); err != nil {
		t.Fatalf("Failed to create key file: %v", err)
	}

	opts := KeySignerOptions{
		ModelPath:      modelDir,
		SignaturePath:  filepath.Join(tmpDir, "sig.json"),
		IgnorePaths:    []string{},
		IgnoreGitPaths: false,
		AllowSymlinks:  false,
		PrivateKeyPath: keyFile,
	}

	signer, err := NewKeySigner(opts)
	if err != nil {
		t.Fatalf("Expected no error for valid paths, got: %v", err)
	}

	if signer == nil {
		t.Fatal("Expected non-nil signer")
	}
}

func TestNewKeySigner_WithIgnorePaths(t *testing.T) {
	tmpDir := t.TempDir()

	// Create model directory
	modelDir := filepath.Join(tmpDir, "model")
	if err := os.MkdirAll(modelDir, 0755); err != nil {
		t.Fatalf("Failed to create model directory: %v", err)
	}

	// Create ignore path directory
	ignoreDir := filepath.Join(modelDir, "ignored")
	if err := os.MkdirAll(ignoreDir, 0755); err != nil {
		t.Fatalf("Failed to create ignore directory: %v", err)
	}

	// Create a dummy key file
	keyFile := filepath.Join(tmpDir, "key.pem")
	if err := os.WriteFile(keyFile, []byte("dummy"), 0644); err != nil {
		t.Fatalf("Failed to create key file: %v", err)
	}

	opts := KeySignerOptions{
		ModelPath:      modelDir,
		SignaturePath:  filepath.Join(tmpDir, "sig.json"),
		IgnorePaths:    []string{ignoreDir},
		IgnoreGitPaths: true,
		AllowSymlinks:  false,
		PrivateKeyPath: keyFile,
	}

	signer, err := NewKeySigner(opts)
	if err != nil {
		t.Fatalf("Expected no error with valid ignore paths, got: %v", err)
	}

	if signer == nil {
		t.Fatal("Expected non-nil signer")
	}
}

func TestNewKeySigner_InvalidIgnorePath(t *testing.T) {
	tmpDir := t.TempDir()

	// Create model directory
	modelDir := filepath.Join(tmpDir, "model")
	if err := os.MkdirAll(modelDir, 0755); err != nil {
		t.Fatalf("Failed to create model directory: %v", err)
	}

	// Create a dummy key file
	keyFile := filepath.Join(tmpDir, "key.pem")
	if err := os.WriteFile(keyFile, []byte("dummy"), 0644); err != nil {
		t.Fatalf("Failed to create key file: %v", err)
	}

	opts := KeySignerOptions{
		ModelPath:      modelDir,
		SignaturePath:  filepath.Join(tmpDir, "sig.json"),
		IgnorePaths:    []string{"/nonexistent/path"},
		IgnoreGitPaths: false,
		PrivateKeyPath: keyFile,
	}

	_, err := NewKeySigner(opts)
	if err == nil {
		t.Error("Expected error for nonexistent ignore path, got nil")
	}
}

func TestNewKeySigner_EmptyIgnorePaths(t *testing.T) {
	tmpDir := t.TempDir()

	// Create model directory
	modelDir := filepath.Join(tmpDir, "model")
	if err := os.MkdirAll(modelDir, 0755); err != nil {
		t.Fatalf("Failed to create model directory: %v", err)
	}

	// Create a dummy key file
	keyFile := filepath.Join(tmpDir, "key.pem")
	if err := os.WriteFile(keyFile, []byte("dummy"), 0644); err != nil {
		t.Fatalf("Failed to create key file: %v", err)
	}

	opts := KeySignerOptions{
		ModelPath:      modelDir,
		SignaturePath:  filepath.Join(tmpDir, "sig.json"),
		IgnorePaths:    []string{},
		PrivateKeyPath: keyFile,
	}

	signer, err := NewKeySigner(opts)
	if err != nil {
		t.Fatalf("Expected no error with empty ignore paths, got: %v", err)
	}

	if signer == nil {
		t.Fatal("Expected non-nil signer")
	}
}

func TestNewKeySigner_AllOptions(t *testing.T) {
	tmpDir := t.TempDir()

	// Create model directory
	modelDir := filepath.Join(tmpDir, "model")
	if err := os.MkdirAll(modelDir, 0755); err != nil {
		t.Fatalf("Failed to create model directory: %v", err)
	}

	// Create a dummy key file
	keyFile := filepath.Join(tmpDir, "key.pem")
	if err := os.WriteFile(keyFile, []byte("dummy"), 0644); err != nil {
		t.Fatalf("Failed to create key file: %v", err)
	}

	opts := KeySignerOptions{
		ModelPath:      modelDir,
		SignaturePath:  filepath.Join(tmpDir, "sig.json"),
		IgnorePaths:    []string{},
		IgnoreGitPaths: true,
		AllowSymlinks:  true,
		PrivateKeyPath: keyFile,
		Password:       "test-password",
	}

	signer, err := NewKeySigner(opts)
	if err != nil {
		t.Fatalf("Expected no error with all options, got: %v", err)
	}

	if signer == nil {
		t.Fatal("Expected non-nil signer")
	}

	// Verify options are stored
	if signer.opts.Password != "test-password" {
		t.Error("Password not stored correctly")
	}
	if !signer.opts.IgnoreGitPaths {
		t.Error("IgnoreGitPaths not set correctly")
	}
	if !signer.opts.AllowSymlinks {
		t.Error("AllowSymlinks not set correctly")
	}
}
