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

func TestNewSigstoreSigner_MissingModelPath(t *testing.T) {
	opts := SigstoreSignerOptions{
		ModelPath:     "/nonexistent/model",
		SignaturePath: "/tmp/sig.json",
	}

	_, err := NewSigstoreSigner(opts)
	if err == nil {
		t.Error("Expected error for nonexistent model path, got nil")
	}
}

func TestNewSigstoreSigner_ValidPaths(t *testing.T) {
	tmpDir := t.TempDir()

	// Create model directory
	modelDir := filepath.Join(tmpDir, "model")
	if err := os.MkdirAll(modelDir, 0755); err != nil {
		t.Fatalf("Failed to create model directory: %v", err)
	}

	opts := SigstoreSignerOptions{
		ModelPath:      modelDir,
		SignaturePath:  filepath.Join(tmpDir, "sig.json"),
		IgnorePaths:    []string{},
		IgnoreGitPaths: false,
		AllowSymlinks:  false,
	}

	signer, err := NewSigstoreSigner(opts)
	if err != nil {
		t.Fatalf("Expected no error for valid paths, got: %v", err)
	}

	if signer == nil {
		t.Fatal("Expected non-nil signer")
	}
}

func TestNewSigstoreSigner_WithIgnorePaths(t *testing.T) {
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

	opts := SigstoreSignerOptions{
		ModelPath:      modelDir,
		SignaturePath:  filepath.Join(tmpDir, "sig.json"),
		IgnorePaths:    []string{ignoreDir},
		IgnoreGitPaths: true,
		AllowSymlinks:  false,
	}

	signer, err := NewSigstoreSigner(opts)
	if err != nil {
		t.Fatalf("Expected no error with valid ignore paths, got: %v", err)
	}

	if signer == nil {
		t.Fatal("Expected non-nil signer")
	}
}

func TestNewSigstoreSigner_InvalidIgnorePath(t *testing.T) {
	tmpDir := t.TempDir()

	// Create model directory
	modelDir := filepath.Join(tmpDir, "model")
	if err := os.MkdirAll(modelDir, 0755); err != nil {
		t.Fatalf("Failed to create model directory: %v", err)
	}

	opts := SigstoreSignerOptions{
		ModelPath:     modelDir,
		SignaturePath: filepath.Join(tmpDir, "sig.json"),
		IgnorePaths:   []string{"/nonexistent/path"},
	}

	_, err := NewSigstoreSigner(opts)
	if err == nil {
		t.Error("Expected error for nonexistent ignore path, got nil")
	}
}

func TestNewSigstoreSigner_EmptyIgnorePaths(t *testing.T) {
	tmpDir := t.TempDir()

	// Create model directory
	modelDir := filepath.Join(tmpDir, "model")
	if err := os.MkdirAll(modelDir, 0755); err != nil {
		t.Fatalf("Failed to create model directory: %v", err)
	}

	opts := SigstoreSignerOptions{
		ModelPath:     modelDir,
		SignaturePath: filepath.Join(tmpDir, "sig.json"),
		IgnorePaths:   []string{},
	}

	signer, err := NewSigstoreSigner(opts)
	if err != nil {
		t.Fatalf("Expected no error with empty ignore paths, got: %v", err)
	}

	if signer == nil {
		t.Fatal("Expected non-nil signer")
	}
}

func TestNewSigstoreSigner_WithInvalidTrustConfigContent(t *testing.T) {
	tmpDir := t.TempDir()

	// Create model directory
	modelDir := filepath.Join(tmpDir, "model")
	if err := os.MkdirAll(modelDir, 0755); err != nil {
		t.Fatalf("Failed to create model directory: %v", err)
	}

	// Create a dummy trust config file with invalid content
	// The constructor now eagerly loads the trust root, so invalid content should fail
	trustConfigPath := filepath.Join(tmpDir, "trust_root.json")
	if err := os.WriteFile(trustConfigPath, []byte("{}"), 0644); err != nil {
		t.Fatalf("Failed to create trust config file: %v", err)
	}

	opts := SigstoreSignerOptions{
		ModelPath:       modelDir,
		SignaturePath:   filepath.Join(tmpDir, "sig.json"),
		TrustConfigPath: trustConfigPath,
	}

	_, err := NewSigstoreSigner(opts)
	if err == nil {
		t.Error("Expected error for invalid trust config content, got nil")
	}
}

func TestNewSigstoreSigner_InvalidTrustConfig(t *testing.T) {
	tmpDir := t.TempDir()

	// Create model directory
	modelDir := filepath.Join(tmpDir, "model")
	if err := os.MkdirAll(modelDir, 0755); err != nil {
		t.Fatalf("Failed to create model directory: %v", err)
	}

	opts := SigstoreSignerOptions{
		ModelPath:       modelDir,
		SignaturePath:   filepath.Join(tmpDir, "sig.json"),
		TrustConfigPath: "/nonexistent/trust_root.json",
	}

	_, err := NewSigstoreSigner(opts)
	if err == nil {
		t.Error("Expected error for nonexistent trust config, got nil")
	}
}

func TestNewSigstoreSigner_EmptyTrustConfig(t *testing.T) {
	tmpDir := t.TempDir()

	// Create model directory
	modelDir := filepath.Join(tmpDir, "model")
	if err := os.MkdirAll(modelDir, 0755); err != nil {
		t.Fatalf("Failed to create model directory: %v", err)
	}

	opts := SigstoreSignerOptions{
		ModelPath:       modelDir,
		SignaturePath:   filepath.Join(tmpDir, "sig.json"),
		TrustConfigPath: "", // Empty is valid (will use default)
	}

	signer, err := NewSigstoreSigner(opts)
	if err != nil {
		t.Fatalf("Expected no error with empty trust config path, got: %v", err)
	}

	if signer == nil {
		t.Fatal("Expected non-nil signer")
	}
}

func TestNewSigstoreSigner_AllOptions(t *testing.T) {
	tmpDir := t.TempDir()

	// Create model directory
	modelDir := filepath.Join(tmpDir, "model")
	if err := os.MkdirAll(modelDir, 0755); err != nil {
		t.Fatalf("Failed to create model directory: %v", err)
	}

	opts := SigstoreSignerOptions{
		ModelPath:             modelDir,
		SignaturePath:         filepath.Join(tmpDir, "sig.json"),
		IgnorePaths:           []string{},
		IgnoreGitPaths:        true,
		AllowSymlinks:         true,
		UseStaging:            true,
		OAuthForceOob:         true,
		UseAmbientCredentials: true,
		IdentityToken:         "test-token",
		ClientID:              "test-client-id",
		ClientSecret:          "test-secret",
		TrustConfigPath:       "",
	}

	signer, err := NewSigstoreSigner(opts)
	if err != nil {
		t.Fatalf("Expected no error with all options, got: %v", err)
	}

	if signer == nil {
		t.Fatal("Expected non-nil signer")
	}

	// Verify options are stored
	if !signer.opts.IgnoreGitPaths {
		t.Error("IgnoreGitPaths not set correctly")
	}
	if !signer.opts.AllowSymlinks {
		t.Error("AllowSymlinks not set correctly")
	}
	if !signer.opts.UseStaging {
		t.Error("UseStaging not set correctly")
	}
	if !signer.opts.OAuthForceOob {
		t.Error("OAuthForceOob not set correctly")
	}
	if !signer.opts.UseAmbientCredentials {
		t.Error("UseAmbientCredentials not set correctly")
	}
	if signer.opts.IdentityToken != "test-token" {
		t.Error("IdentityToken not stored correctly")
	}
	if signer.opts.ClientID != "test-client-id" {
		t.Error("ClientID not stored correctly")
	}
	if signer.opts.ClientSecret != "test-secret" {
		t.Error("ClientSecret not stored correctly")
	}
}

func TestNewSigstoreSigner_ProductionDefaults(t *testing.T) {
	tmpDir := t.TempDir()

	// Create model directory
	modelDir := filepath.Join(tmpDir, "model")
	if err := os.MkdirAll(modelDir, 0755); err != nil {
		t.Fatalf("Failed to create model directory: %v", err)
	}

	opts := SigstoreSignerOptions{
		ModelPath:     modelDir,
		SignaturePath: filepath.Join(tmpDir, "sig.json"),
		// All boolean flags default to false (production mode)
	}

	signer, err := NewSigstoreSigner(opts)
	if err != nil {
		t.Fatalf("Expected no error with production defaults, got: %v", err)
	}

	if signer == nil {
		t.Fatal("Expected non-nil signer")
	}

	// Verify production defaults
	if signer.opts.UseStaging {
		t.Error("Expected UseStaging to be false by default")
	}
	if signer.opts.UseAmbientCredentials {
		t.Error("Expected UseAmbientCredentials to be false by default")
	}
	if signer.opts.OAuthForceOob {
		t.Error("Expected OAuthForceOob to be false by default")
	}
}

func TestNewSigstoreSigner_StagingMode(t *testing.T) {
	tmpDir := t.TempDir()

	// Create model directory
	modelDir := filepath.Join(tmpDir, "model")
	if err := os.MkdirAll(modelDir, 0755); err != nil {
		t.Fatalf("Failed to create model directory: %v", err)
	}

	opts := SigstoreSignerOptions{
		ModelPath:     modelDir,
		SignaturePath: filepath.Join(tmpDir, "sig.json"),
		UseStaging:    true,
	}

	signer, err := NewSigstoreSigner(opts)
	if err != nil {
		t.Fatalf("Expected no error with staging mode, got: %v", err)
	}

	if !signer.opts.UseStaging {
		t.Error("Expected UseStaging to be true")
	}
}
