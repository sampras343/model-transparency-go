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

func TestNewKeyVerifier_MissingModelPath(t *testing.T) {
	tmpDir := t.TempDir()
	sigFile := filepath.Join(tmpDir, "sig.json")
	keyFile := filepath.Join(tmpDir, "key.pub")

	// Create dummy files
	if err := os.WriteFile(sigFile, []byte("{}"), 0644); err != nil {
		t.Fatalf("Failed to create signature file: %v", err)
	}
	if err := os.WriteFile(keyFile, []byte("dummy"), 0644); err != nil {
		t.Fatalf("Failed to create key file: %v", err)
	}

	opts := KeyVerifierOptions{
		ModelPath:     "/nonexistent/model",
		SignaturePath: sigFile,
		PublicKeyPath: keyFile,
	}

	_, err := NewKeyVerifier(opts)
	if err == nil {
		t.Error("Expected error for nonexistent model path, got nil")
	}
}

func TestNewKeyVerifier_MissingSignature(t *testing.T) {
	tmpDir := t.TempDir()
	modelDir := filepath.Join(tmpDir, "model")
	keyFile := filepath.Join(tmpDir, "key.pub")

	if err := os.MkdirAll(modelDir, 0755); err != nil {
		t.Fatalf("Failed to create model directory: %v", err)
	}
	if err := os.WriteFile(keyFile, []byte("dummy"), 0644); err != nil {
		t.Fatalf("Failed to create key file: %v", err)
	}

	opts := KeyVerifierOptions{
		ModelPath:     modelDir,
		SignaturePath: "/nonexistent/sig.json",
		PublicKeyPath: keyFile,
	}

	_, err := NewKeyVerifier(opts)
	if err == nil {
		t.Error("Expected error for nonexistent signature file, got nil")
	}
}

func TestNewKeyVerifier_MissingPublicKey(t *testing.T) {
	tmpDir := t.TempDir()
	modelDir := filepath.Join(tmpDir, "model")
	sigFile := filepath.Join(tmpDir, "sig.json")

	if err := os.MkdirAll(modelDir, 0755); err != nil {
		t.Fatalf("Failed to create model directory: %v", err)
	}
	if err := os.WriteFile(sigFile, []byte("{}"), 0644); err != nil {
		t.Fatalf("Failed to create signature file: %v", err)
	}

	opts := KeyVerifierOptions{
		ModelPath:     modelDir,
		SignaturePath: sigFile,
		PublicKeyPath: "/nonexistent/key.pub",
	}

	_, err := NewKeyVerifier(opts)
	if err == nil {
		t.Error("Expected error for nonexistent public key, got nil")
	}
}

func TestNewKeyVerifier_ValidPaths(t *testing.T) {
	tmpDir := t.TempDir()

	// Create model directory
	modelDir := filepath.Join(tmpDir, "model")
	if err := os.MkdirAll(modelDir, 0755); err != nil {
		t.Fatalf("Failed to create model directory: %v", err)
	}

	// Create signature file
	sigFile := filepath.Join(tmpDir, "sig.json")
	if err := os.WriteFile(sigFile, []byte("{}"), 0644); err != nil {
		t.Fatalf("Failed to create signature file: %v", err)
	}

	// Create dummy public key file
	keyFile := filepath.Join(tmpDir, "key.pub")
	if err := os.WriteFile(keyFile, []byte("dummy"), 0644); err != nil {
		t.Fatalf("Failed to create key file: %v", err)
	}

	opts := KeyVerifierOptions{
		ModelPath:      modelDir,
		SignaturePath:  sigFile,
		PublicKeyPath:  keyFile,
		IgnorePaths:    []string{},
		IgnoreGitPaths: false,
		AllowSymlinks:  false,
	}

	verifier, err := NewKeyVerifier(opts)
	if err != nil {
		t.Fatalf("Expected no error for valid paths, got: %v", err)
	}

	if verifier == nil {
		t.Fatal("Expected non-nil verifier")
	}
}

func TestNewKeyVerifier_WithIgnorePaths(t *testing.T) {
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

	// Create signature file
	sigFile := filepath.Join(tmpDir, "sig.json")
	if err := os.WriteFile(sigFile, []byte("{}"), 0644); err != nil {
		t.Fatalf("Failed to create signature file: %v", err)
	}

	// Create dummy public key file
	keyFile := filepath.Join(tmpDir, "key.pub")
	if err := os.WriteFile(keyFile, []byte("dummy"), 0644); err != nil {
		t.Fatalf("Failed to create key file: %v", err)
	}

	opts := KeyVerifierOptions{
		ModelPath:      modelDir,
		SignaturePath:  sigFile,
		PublicKeyPath:  keyFile,
		IgnorePaths:    []string{ignoreDir},
		IgnoreGitPaths: true,
		AllowSymlinks:  false,
	}

	verifier, err := NewKeyVerifier(opts)
	if err != nil {
		t.Fatalf("Expected no error with valid ignore paths, got: %v", err)
	}

	if verifier == nil {
		t.Fatal("Expected non-nil verifier")
	}
}

func TestNewKeyVerifier_InvalidIgnorePath(t *testing.T) {
	tmpDir := t.TempDir()

	// Create model directory
	modelDir := filepath.Join(tmpDir, "model")
	if err := os.MkdirAll(modelDir, 0755); err != nil {
		t.Fatalf("Failed to create model directory: %v", err)
	}

	// Create signature file
	sigFile := filepath.Join(tmpDir, "sig.json")
	if err := os.WriteFile(sigFile, []byte("{}"), 0644); err != nil {
		t.Fatalf("Failed to create signature file: %v", err)
	}

	// Create dummy public key file
	keyFile := filepath.Join(tmpDir, "key.pub")
	if err := os.WriteFile(keyFile, []byte("dummy"), 0644); err != nil {
		t.Fatalf("Failed to create key file: %v", err)
	}

	opts := KeyVerifierOptions{
		ModelPath:     modelDir,
		SignaturePath: sigFile,
		PublicKeyPath: keyFile,
		IgnorePaths:   []string{"/nonexistent/path"},
	}

	_, err := NewKeyVerifier(opts)
	if err == nil {
		t.Error("Expected error for nonexistent ignore path, got nil")
	}
}

func TestNewKeyVerifier_EmptyIgnorePaths(t *testing.T) {
	tmpDir := t.TempDir()

	// Create model directory
	modelDir := filepath.Join(tmpDir, "model")
	if err := os.MkdirAll(modelDir, 0755); err != nil {
		t.Fatalf("Failed to create model directory: %v", err)
	}

	// Create signature file
	sigFile := filepath.Join(tmpDir, "sig.json")
	if err := os.WriteFile(sigFile, []byte("{}"), 0644); err != nil {
		t.Fatalf("Failed to create signature file: %v", err)
	}

	// Create dummy public key file
	keyFile := filepath.Join(tmpDir, "key.pub")
	if err := os.WriteFile(keyFile, []byte("dummy"), 0644); err != nil {
		t.Fatalf("Failed to create key file: %v", err)
	}

	opts := KeyVerifierOptions{
		ModelPath:     modelDir,
		SignaturePath: sigFile,
		PublicKeyPath: keyFile,
		IgnorePaths:   []string{},
	}

	verifier, err := NewKeyVerifier(opts)
	if err != nil {
		t.Fatalf("Expected no error with empty ignore paths, got: %v", err)
	}

	if verifier == nil {
		t.Fatal("Expected non-nil verifier")
	}
}

func TestNewKeyVerifier_AllOptions(t *testing.T) {
	tmpDir := t.TempDir()

	// Create model directory
	modelDir := filepath.Join(tmpDir, "model")
	if err := os.MkdirAll(modelDir, 0755); err != nil {
		t.Fatalf("Failed to create model directory: %v", err)
	}

	// Create signature file
	sigFile := filepath.Join(tmpDir, "sig.json")
	if err := os.WriteFile(sigFile, []byte("{}"), 0644); err != nil {
		t.Fatalf("Failed to create signature file: %v", err)
	}

	// Create dummy public key file
	keyFile := filepath.Join(tmpDir, "key.pub")
	if err := os.WriteFile(keyFile, []byte("dummy"), 0644); err != nil {
		t.Fatalf("Failed to create key file: %v", err)
	}

	opts := KeyVerifierOptions{
		ModelPath:           modelDir,
		SignaturePath:       sigFile,
		PublicKeyPath:       keyFile,
		IgnorePaths:         []string{},
		IgnoreGitPaths:      true,
		AllowSymlinks:       true,
		IgnoreUnsignedFiles: true,
	}

	verifier, err := NewKeyVerifier(opts)
	if err != nil {
		t.Fatalf("Expected no error with all options, got: %v", err)
	}

	if verifier == nil {
		t.Fatal("Expected non-nil verifier")
	}

	// Verify options are stored
	if !verifier.opts.IgnoreGitPaths {
		t.Error("IgnoreGitPaths not set correctly")
	}
	if !verifier.opts.AllowSymlinks {
		t.Error("AllowSymlinks not set correctly")
	}
	if !verifier.opts.IgnoreUnsignedFiles {
		t.Error("IgnoreUnsignedFiles not set correctly")
	}
}
