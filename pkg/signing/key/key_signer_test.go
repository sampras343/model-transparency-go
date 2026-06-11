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
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
)

func writeECKeyPEM(t *testing.T, dir string, curve elliptic.Curve) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate EC key: %v", err)
	}
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("failed to marshal EC key: %v", err)
	}
	path := filepath.Join(dir, "key.pem")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if err := pem.Encode(f, &pem.Block{Type: "EC PRIVATE KEY", Bytes: der}); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestNewModelKeypair_ECCurves(t *testing.T) {
	curves := []struct {
		name  string
		curve elliptic.Curve
	}{
		{"P-256", elliptic.P256()},
		{"P-384", elliptic.P384()},
		{"P-521", elliptic.P521()},
	}

	for _, tc := range curves {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			keyPath := writeECKeyPEM(t, dir, tc.curve)

			kp, err := NewModelKeypair(keyPath, "")
			if err != nil {
				t.Fatalf("NewModelKeypair failed for %s: %v", tc.name, err)
			}

			if kp.GetKeyAlgorithm() != "ECDSA" {
				t.Errorf("expected ECDSA, got %s", kp.GetKeyAlgorithm())
			}

			if len(kp.GetHint()) == 0 {
				t.Error("expected non-empty key hint")
			}

			pubPEM, err := kp.GetPublicKeyPem()
			if err != nil {
				t.Fatalf("GetPublicKeyPem failed: %v", err)
			}
			if pubPEM == "" {
				t.Error("expected non-empty public key PEM")
			}
		})
	}
}

func TestModelKeypair_P521_SignData(t *testing.T) {
	dir := t.TempDir()
	keyPath := writeECKeyPEM(t, dir, elliptic.P521())

	kp, err := NewModelKeypair(keyPath, "")
	if err != nil {
		t.Fatalf("NewModelKeypair failed: %v", err)
	}

	data := []byte("test payload for P-521 signing")
	sig, signed, err := kp.SignData(context.Background(), data)
	if err != nil {
		t.Fatalf("SignData failed: %v", err)
	}

	if len(sig) == 0 {
		t.Error("expected non-empty signature")
	}
	if len(signed) == 0 {
		t.Error("expected non-empty signed data")
	}

	pubKey, ok := kp.GetPublicKey().(*ecdsa.PublicKey)
	if !ok {
		t.Fatal("expected *ecdsa.PublicKey")
	}
	if pubKey.Curve != elliptic.P521() {
		t.Errorf("expected P-521 curve, got %s", pubKey.Curve.Params().Name)
	}
}

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
		IgnorePaths:    []string{"ignored"},
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
		IgnorePaths:    []string{"nonexistent/path"},
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
		TSAUrl:         "https://tsa.example.com",
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
	if signer.opts.TSAUrl != "https://tsa.example.com" {
		t.Errorf("TSAUrl not stored correctly: got %q", signer.opts.TSAUrl)
	}
}

func TestNewKeySigner_WithTSAUrl(t *testing.T) {
	tmpDir := t.TempDir()

	modelDir := filepath.Join(tmpDir, "model")
	if err := os.MkdirAll(modelDir, 0755); err != nil {
		t.Fatalf("Failed to create model directory: %v", err)
	}

	keyFile := filepath.Join(tmpDir, "key.pem")
	if err := os.WriteFile(keyFile, []byte("dummy"), 0644); err != nil {
		t.Fatalf("Failed to create key file: %v", err)
	}

	opts := KeySignerOptions{
		ModelPath:      modelDir,
		SignaturePath:  filepath.Join(tmpDir, "sig.json"),
		PrivateKeyPath: keyFile,
		TSAUrl:         "https://freetsa.org/tsr",
	}

	signer, err := NewKeySigner(opts)
	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}

	if signer.opts.TSAUrl != "https://freetsa.org/tsr" {
		t.Errorf("TSAUrl: got %q, want %q", signer.opts.TSAUrl, "https://freetsa.org/tsr")
	}
}

func TestNewKeySigner_EmptyTSAUrl(t *testing.T) {
	tmpDir := t.TempDir()

	modelDir := filepath.Join(tmpDir, "model")
	if err := os.MkdirAll(modelDir, 0755); err != nil {
		t.Fatalf("Failed to create model directory: %v", err)
	}

	keyFile := filepath.Join(tmpDir, "key.pem")
	if err := os.WriteFile(keyFile, []byte("dummy"), 0644); err != nil {
		t.Fatalf("Failed to create key file: %v", err)
	}

	opts := KeySignerOptions{
		ModelPath:      modelDir,
		SignaturePath:  filepath.Join(tmpDir, "sig.json"),
		PrivateKeyPath: keyFile,
	}

	signer, err := NewKeySigner(opts)
	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}

	if signer.opts.TSAUrl != "" {
		t.Errorf("TSAUrl: expected empty, got %q", signer.opts.TSAUrl)
	}
}
