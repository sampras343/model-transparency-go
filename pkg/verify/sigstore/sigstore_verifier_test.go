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

package sigstore

import (
	"os"
	"path/filepath"
	"testing"
)

func TestNewSigstoreVerifier_MissingModelPath(t *testing.T) {
	tmpDir := t.TempDir()
	sigFile := filepath.Join(tmpDir, "sig.json")

	// Create signature file
	if err := os.WriteFile(sigFile, []byte("{}"), 0644); err != nil {
		t.Fatalf("Failed to create signature file: %v", err)
	}

	opts := SigstoreVerifierOptions{
		ModelPath:        "/nonexistent/model",
		SignaturePath:    sigFile,
		Identity:         "test@example.com",
		IdentityProvider: "https://accounts.google.com",
	}

	_, err := NewSigstoreVerifier(opts)
	if err == nil {
		t.Error("Expected error for nonexistent model path, got nil")
	}
}

func TestNewSigstoreVerifier_MissingSignature(t *testing.T) {
	tmpDir := t.TempDir()
	modelDir := filepath.Join(tmpDir, "model")

	if err := os.MkdirAll(modelDir, 0755); err != nil {
		t.Fatalf("Failed to create model directory: %v", err)
	}

	opts := SigstoreVerifierOptions{
		ModelPath:        modelDir,
		SignaturePath:    "/nonexistent/sig.json",
		Identity:         "test@example.com",
		IdentityProvider: "https://accounts.google.com",
	}

	_, err := NewSigstoreVerifier(opts)
	if err == nil {
		t.Error("Expected error for nonexistent signature file, got nil")
	}
}

func TestNewSigstoreVerifier_MissingIdentity(t *testing.T) {
	tmpDir := t.TempDir()
	modelDir := filepath.Join(tmpDir, "model")
	sigFile := filepath.Join(tmpDir, "sig.json")

	if err := os.MkdirAll(modelDir, 0755); err != nil {
		t.Fatalf("Failed to create model directory: %v", err)
	}
	if err := os.WriteFile(sigFile, []byte("{}"), 0644); err != nil {
		t.Fatalf("Failed to create signature file: %v", err)
	}

	opts := SigstoreVerifierOptions{
		ModelPath:        modelDir,
		SignaturePath:    sigFile,
		Identity:         "",
		IdentityProvider: "https://accounts.google.com",
	}

	_, err := NewSigstoreVerifier(opts)
	if err == nil {
		t.Error("Expected error for missing identity, got nil")
	}
}

func TestNewSigstoreVerifier_MissingIdentityProvider(t *testing.T) {
	tmpDir := t.TempDir()
	modelDir := filepath.Join(tmpDir, "model")
	sigFile := filepath.Join(tmpDir, "sig.json")

	if err := os.MkdirAll(modelDir, 0755); err != nil {
		t.Fatalf("Failed to create model directory: %v", err)
	}
	if err := os.WriteFile(sigFile, []byte("{}"), 0644); err != nil {
		t.Fatalf("Failed to create signature file: %v", err)
	}

	opts := SigstoreVerifierOptions{
		ModelPath:        modelDir,
		SignaturePath:    sigFile,
		Identity:         "test@example.com",
		IdentityProvider: "",
	}

	_, err := NewSigstoreVerifier(opts)
	if err == nil {
		t.Error("Expected error for missing identity provider, got nil")
	}
}

func TestNewSigstoreVerifier_InvalidIdentityProviderURL(t *testing.T) {
	tmpDir := t.TempDir()
	modelDir := filepath.Join(tmpDir, "model")
	sigFile := filepath.Join(tmpDir, "sig.json")

	if err := os.MkdirAll(modelDir, 0755); err != nil {
		t.Fatalf("Failed to create model directory: %v", err)
	}
	if err := os.WriteFile(sigFile, []byte("{}"), 0644); err != nil {
		t.Fatalf("Failed to create signature file: %v", err)
	}

	opts := SigstoreVerifierOptions{
		ModelPath:        modelDir,
		SignaturePath:    sigFile,
		Identity:         "test@example.com",
		IdentityProvider: "not-a-valid-url",
	}

	_, err := NewSigstoreVerifier(opts)
	if err == nil {
		t.Error("Expected error for invalid identity provider URL, got nil")
	}
}

func TestNewSigstoreVerifier_ValidPaths(t *testing.T) {
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

	opts := SigstoreVerifierOptions{
		ModelPath:        modelDir,
		SignaturePath:    sigFile,
		Identity:         "test@example.com",
		IdentityProvider: "https://accounts.google.com",
		IgnorePaths:      []string{},
		IgnoreGitPaths:   false,
		AllowSymlinks:    false,
	}

	verifier, err := NewSigstoreVerifier(opts)
	if err != nil {
		t.Fatalf("Expected no error for valid paths, got: %v", err)
	}

	if verifier == nil {
		t.Fatal("Expected non-nil verifier")
	}
}

func TestNewSigstoreVerifier_WithIgnorePaths(t *testing.T) {
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

	opts := SigstoreVerifierOptions{
		ModelPath:        modelDir,
		SignaturePath:    sigFile,
		Identity:         "test@example.com",
		IdentityProvider: "https://accounts.google.com",
		IgnorePaths:      []string{ignoreDir},
		IgnoreGitPaths:   true,
		AllowSymlinks:    false,
	}

	verifier, err := NewSigstoreVerifier(opts)
	if err != nil {
		t.Fatalf("Expected no error with valid ignore paths, got: %v", err)
	}

	if verifier == nil {
		t.Fatal("Expected non-nil verifier")
	}
}

func TestNewSigstoreVerifier_InvalidIgnorePath(t *testing.T) {
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

	opts := SigstoreVerifierOptions{
		ModelPath:        modelDir,
		SignaturePath:    sigFile,
		Identity:         "test@example.com",
		IdentityProvider: "https://accounts.google.com",
		IgnorePaths:      []string{"/nonexistent/path"},
	}

	_, err := NewSigstoreVerifier(opts)
	if err == nil {
		t.Error("Expected error for nonexistent ignore path, got nil")
	}
}

func TestNewSigstoreVerifier_EmptyIgnorePaths(t *testing.T) {
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

	opts := SigstoreVerifierOptions{
		ModelPath:        modelDir,
		SignaturePath:    sigFile,
		Identity:         "test@example.com",
		IdentityProvider: "https://accounts.google.com",
		IgnorePaths:      []string{},
	}

	verifier, err := NewSigstoreVerifier(opts)
	if err != nil {
		t.Fatalf("Expected no error with empty ignore paths, got: %v", err)
	}

	if verifier == nil {
		t.Fatal("Expected non-nil verifier")
	}
}

func TestNewSigstoreVerifier_WithTrustConfig(t *testing.T) {
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

	// Create a dummy trust config file
	trustConfigPath := filepath.Join(tmpDir, "trust_root.json")
	if err := os.WriteFile(trustConfigPath, []byte("{}"), 0644); err != nil {
		t.Fatalf("Failed to create trust config file: %v", err)
	}

	opts := SigstoreVerifierOptions{
		ModelPath:        modelDir,
		SignaturePath:    sigFile,
		Identity:         "test@example.com",
		IdentityProvider: "https://accounts.google.com",
		TrustConfigPath:  trustConfigPath,
	}

	verifier, err := NewSigstoreVerifier(opts)
	if err != nil {
		t.Fatalf("Expected no error with valid trust config, got: %v", err)
	}

	if verifier == nil {
		t.Fatal("Expected non-nil verifier")
	}
}

func TestNewSigstoreVerifier_InvalidTrustConfig(t *testing.T) {
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

	opts := SigstoreVerifierOptions{
		ModelPath:        modelDir,
		SignaturePath:    sigFile,
		Identity:         "test@example.com",
		IdentityProvider: "https://accounts.google.com",
		TrustConfigPath:  "/nonexistent/trust_root.json",
	}

	_, err := NewSigstoreVerifier(opts)
	if err == nil {
		t.Error("Expected error for nonexistent trust config, got nil")
	}
}

func TestNewSigstoreVerifier_EmptyTrustConfig(t *testing.T) {
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

	opts := SigstoreVerifierOptions{
		ModelPath:        modelDir,
		SignaturePath:    sigFile,
		Identity:         "test@example.com",
		IdentityProvider: "https://accounts.google.com",
		TrustConfigPath:  "", // Empty is valid (will use default)
	}

	verifier, err := NewSigstoreVerifier(opts)
	if err != nil {
		t.Fatalf("Expected no error with empty trust config path, got: %v", err)
	}

	if verifier == nil {
		t.Fatal("Expected non-nil verifier")
	}
}

func TestNewSigstoreVerifier_AllOptions(t *testing.T) {
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

	opts := SigstoreVerifierOptions{
		ModelPath:           modelDir,
		SignaturePath:       sigFile,
		Identity:            "test@example.com",
		IdentityProvider:    "https://accounts.google.com",
		IgnorePaths:         []string{},
		IgnoreGitPaths:      true,
		AllowSymlinks:       true,
		UseStaging:          true,
		IgnoreUnsignedFiles: true,
		TrustConfigPath:     "",
	}

	verifier, err := NewSigstoreVerifier(opts)
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
	if !verifier.opts.UseStaging {
		t.Error("UseStaging not set correctly")
	}
	if !verifier.opts.IgnoreUnsignedFiles {
		t.Error("IgnoreUnsignedFiles not set correctly")
	}
	if verifier.opts.Identity != "test@example.com" {
		t.Error("Identity not stored correctly")
	}
	if verifier.opts.IdentityProvider != "https://accounts.google.com" {
		t.Error("IdentityProvider not stored correctly")
	}
}

func TestNewSigstoreVerifier_ProductionDefaults(t *testing.T) {
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

	opts := SigstoreVerifierOptions{
		ModelPath:        modelDir,
		SignaturePath:    sigFile,
		Identity:         "test@example.com",
		IdentityProvider: "https://accounts.google.com",
		// All boolean flags default to false (production mode)
	}

	verifier, err := NewSigstoreVerifier(opts)
	if err != nil {
		t.Fatalf("Expected no error with production defaults, got: %v", err)
	}

	if verifier == nil {
		t.Fatal("Expected non-nil verifier")
	}

	// Verify production defaults
	if verifier.opts.UseStaging {
		t.Error("Expected UseStaging to be false by default")
	}
	if verifier.opts.IgnoreGitPaths {
		t.Error("Expected IgnoreGitPaths to be false by default")
	}
	if verifier.opts.AllowSymlinks {
		t.Error("Expected AllowSymlinks to be false by default")
	}
	if verifier.opts.IgnoreUnsignedFiles {
		t.Error("Expected IgnoreUnsignedFiles to be false by default")
	}
}

func TestNewSigstoreVerifier_StagingMode(t *testing.T) {
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

	opts := SigstoreVerifierOptions{
		ModelPath:        modelDir,
		SignaturePath:    sigFile,
		Identity:         "test@example.com",
		IdentityProvider: "https://accounts.google.com",
		UseStaging:       true,
	}

	verifier, err := NewSigstoreVerifier(opts)
	if err != nil {
		t.Fatalf("Expected no error with staging mode, got: %v", err)
	}

	if !verifier.opts.UseStaging {
		t.Error("Expected UseStaging to be true")
	}
}
