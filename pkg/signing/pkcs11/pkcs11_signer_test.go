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

package pkcs11

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestNewPkcs11Signer_MissingModelPath(t *testing.T) {
	tmpDir := t.TempDir()

	opts := Pkcs11SignerOptions{
		ModelPath:     "/nonexistent/model",
		SignaturePath: filepath.Join(tmpDir, "sig.json"),
		URI:           "pkcs11:token=test;object=test",
	}

	_, err := NewPkcs11Signer(opts)
	if err == nil {
		t.Error("Expected error for nonexistent model path, got nil")
	}
}

func TestNewPkcs11Signer_MissingURI(t *testing.T) {
	tmpDir := t.TempDir()

	opts := Pkcs11SignerOptions{
		ModelPath:     tmpDir,
		SignaturePath: filepath.Join(tmpDir, "sig.json"),
		URI:           "", // Missing URI
	}

	_, err := NewPkcs11Signer(opts)
	if err == nil {
		t.Error("Expected error for missing PKCS#11 URI, got nil")
	}
}

func TestNewPkcs11Signer_MissingSigningCertificate(t *testing.T) {
	tmpDir := t.TempDir()

	// Create model directory
	modelDir := filepath.Join(tmpDir, "model")
	if err := os.MkdirAll(modelDir, 0755); err != nil {
		t.Fatalf("Failed to create model directory: %v", err)
	}

	opts := Pkcs11SignerOptions{
		ModelPath:              modelDir,
		SignaturePath:          filepath.Join(tmpDir, "sig.json"),
		URI:                    "pkcs11:token=test;object=test",
		SigningCertificatePath: "/nonexistent/cert.pem",
	}

	_, err := NewPkcs11Signer(opts)
	if err == nil {
		t.Error("Expected error for nonexistent signing certificate, got nil")
	}
}

func TestNewPkcs11Signer_ValidPaths(t *testing.T) {
	tmpDir := t.TempDir()

	// Create model directory
	modelDir := filepath.Join(tmpDir, "model")
	if err := os.MkdirAll(modelDir, 0755); err != nil {
		t.Fatalf("Failed to create model directory: %v", err)
	}

	opts := Pkcs11SignerOptions{
		ModelPath:      modelDir,
		SignaturePath:  filepath.Join(tmpDir, "sig.json"),
		URI:            "pkcs11:token=test;object=test",
		IgnorePaths:    []string{},
		IgnoreGitPaths: false,
		AllowSymlinks:  false,
	}

	signer, err := NewPkcs11Signer(opts)
	if err != nil {
		t.Fatalf("Expected no error for valid paths, got: %v", err)
	}

	if signer == nil {
		t.Fatal("Expected non-nil signer")
	}

	if signer.opts.URI != opts.URI {
		t.Errorf("Expected PKCS#11 URI %s, got %s", opts.URI, signer.opts.URI)
	}
}

func TestNewPkcs11Signer_WithCertificateChain(t *testing.T) {
	tmpDir := t.TempDir()

	// Create model directory
	modelDir := filepath.Join(tmpDir, "model")
	if err := os.MkdirAll(modelDir, 0755); err != nil {
		t.Fatalf("Failed to create model directory: %v", err)
	}

	// Create dummy certificate files
	certFile := filepath.Join(tmpDir, "cert.pem")
	if err := os.WriteFile(certFile, []byte("dummy cert"), 0644); err != nil {
		t.Fatalf("Failed to create cert file: %v", err)
	}

	chainFile1 := filepath.Join(tmpDir, "chain1.pem")
	if err := os.WriteFile(chainFile1, []byte("dummy chain1"), 0644); err != nil {
		t.Fatalf("Failed to create chain file: %v", err)
	}

	chainFile2 := filepath.Join(tmpDir, "chain2.pem")
	if err := os.WriteFile(chainFile2, []byte("dummy chain2"), 0644); err != nil {
		t.Fatalf("Failed to create chain file: %v", err)
	}

	opts := Pkcs11SignerOptions{
		ModelPath:              modelDir,
		SignaturePath:          filepath.Join(tmpDir, "sig.json"),
		URI:                    "pkcs11:token=test;object=test",
		SigningCertificatePath: certFile,
		CertificateChain:       []string{chainFile1, chainFile2},
		IgnorePaths:            []string{},
		IgnoreGitPaths:         false,
		AllowSymlinks:          false,
	}

	signer, err := NewPkcs11Signer(opts)
	if err != nil {
		t.Fatalf("Expected no error for valid certificate chain, got: %v", err)
	}

	if signer == nil {
		t.Fatal("Expected non-nil signer")
	}

	if len(signer.opts.CertificateChain) != 2 {
		t.Errorf("Expected 2 certificates in chain, got %d", len(signer.opts.CertificateChain))
	}
}

func TestNewPkcs11Signer_WithModulePaths(t *testing.T) {
	tmpDir := t.TempDir()

	// Create model directory
	modelDir := filepath.Join(tmpDir, "model")
	if err := os.MkdirAll(modelDir, 0755); err != nil {
		t.Fatalf("Failed to create model directory: %v", err)
	}

	modulePath := "/usr/lib64/pkcs11"

	opts := Pkcs11SignerOptions{
		ModelPath:      modelDir,
		SignaturePath:  filepath.Join(tmpDir, "sig.json"),
		URI:            "pkcs11:token=test;object=test",
		ModulePaths:    []string{modulePath},
		IgnorePaths:    []string{},
		IgnoreGitPaths: false,
		AllowSymlinks:  false,
	}

	signer, err := NewPkcs11Signer(opts)
	if err != nil {
		t.Fatalf("Expected no error for valid module paths, got: %v", err)
	}

	if signer == nil {
		t.Fatal("Expected non-nil signer")
	}

	if len(signer.opts.ModulePaths) != 1 {
		t.Errorf("Expected 1 module path, got %d", len(signer.opts.ModulePaths))
	}

	if signer.opts.ModulePaths[0] != modulePath {
		t.Errorf("Expected module path %s, got %s", modulePath, signer.opts.ModulePaths[0])
	}
}

func TestNewPkcs11Signer_URIFormatValidation(t *testing.T) {
	tmpDir := t.TempDir()

	// Create model directory
	modelDir := filepath.Join(tmpDir, "model")
	if err := os.MkdirAll(modelDir, 0755); err != nil {
		t.Fatalf("Failed to create model directory: %v", err)
	}

	tests := []struct {
		name      string
		uri       string
		wantError bool
		errorMsg  string
	}{
		{
			name:      "valid URI with token and object",
			uri:       "pkcs11:token=mytoken;object=mykey",
			wantError: false,
		},
		{
			name:      "valid URI with token, object, and pin-value",
			uri:       "pkcs11:token=mytoken;object=mykey?pin-value=1234",
			wantError: false,
		},
		{
			name:      "valid URI with token, object, and module-name",
			uri:       "pkcs11:token=mytoken;object=mykey?module-name=softhsm2",
			wantError: false,
		},
		{
			name:      "valid URI with full RFC 7512 format",
			uri:       "pkcs11:token=mytoken;object=mykey?module-name=softhsm2&pin-value=1234",
			wantError: false,
		},
		{
			name:      "valid URI with id instead of object",
			uri:       "pkcs11:token=mytoken;id=%AB%CD",
			wantError: false,
		},
		{
			name:      "valid URI with slot-id",
			uri:       "pkcs11:slot-id=0;object=mykey",
			wantError: false,
		},
		{
			name:      "missing pkcs11 prefix",
			uri:       "token=mytoken;object=mykey",
			wantError: true,
			errorMsg:  "missing 'pkcs11:' prefix",
		},
		{
			name:      "empty URI",
			uri:       "pkcs11:",
			wantError: true,
			errorMsg:  "must specify at least one of",
		},
		{
			name:      "malformed path attribute (missing value)",
			uri:       "pkcs11:token=mytoken;object",
			wantError: true,
			errorMsg:  "malformed path attribute",
		},
		{
			name:      "malformed query attribute (missing value)",
			uri:       "pkcs11:token=mytoken;object=mykey?pin-value",
			wantError: true,
			errorMsg:  "malformed query attribute",
		},
		{
			name:      "conflicting PIN attributes",
			uri:       "pkcs11:token=mytoken;object=mykey?pin-value=1234&pin-source=file:///pin.txt",
			wantError: true,
			errorMsg:  "must not contain both pin-source and pin-value",
		},
		{
			name:      "invalid slot-id (not a number)",
			uri:       "pkcs11:slot-id=abc;object=mykey",
			wantError: true,
			errorMsg:  "slot-id must be a number",
		},
		{
			name:      "invalid type",
			uri:       "pkcs11:token=mytoken;object=mykey;type=invalid",
			wantError: true,
			errorMsg:  "invalid type",
		},
		{
			name:      "relative module-path",
			uri:       "pkcs11:token=mytoken;object=mykey?module-path=relative/path",
			wantError: true,
			errorMsg:  "must be absolute",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			opts := Pkcs11SignerOptions{
				ModelPath:     modelDir,
				SignaturePath: filepath.Join(tmpDir, "sig.json"),
				URI:           tt.uri,
			}

			signer, err := NewPkcs11Signer(opts)

			if tt.wantError {
				if err == nil {
					t.Errorf("Expected error for URI %q, got nil", tt.uri)
				} else if tt.errorMsg != "" && !strings.Contains(err.Error(), tt.errorMsg) {
					t.Errorf("Expected error containing %q, got: %v", tt.errorMsg, err)
				}
				if signer != nil {
					t.Error("Expected nil signer when error occurs")
				}
			} else {
				if err != nil {
					t.Errorf("Expected no error for valid URI %q, got: %v", tt.uri, err)
				}
				if signer == nil {
					t.Error("Expected non-nil signer for valid URI")
				}
			}
		})
	}
}
