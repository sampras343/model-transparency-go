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
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestKeyConfig_LoadPublicKey tests loading public keys.
func TestKeyConfig_LoadPublicKey(t *testing.T) {
	tests := []struct {
		name        string
		generateKey func() (interface{}, error)
	}{
		{
			name: "ECDSA P-256",
			generateKey: func() (interface{}, error) {
				key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
				if err != nil {
					return nil, err
				}
				return &key.PublicKey, nil
			},
		},
		{
			name: "ECDSA P-384",
			generateKey: func() (interface{}, error) {
				key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
				if err != nil {
					return nil, err
				}
				return &key.PublicKey, nil
			},
		},
		{
			name: "ECDSA P-521",
			generateKey: func() (interface{}, error) {
				key, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
				if err != nil {
					return nil, err
				}
				return &key.PublicKey, nil
			},
		},
		{
			name: "RSA 2048",
			generateKey: func() (interface{}, error) {
				key, err := rsa.GenerateKey(rand.Reader, 2048)
				if err != nil {
					return nil, err
				}
				return &key.PublicKey, nil
			},
		},
		{
			name: "Ed25519",
			generateKey: func() (interface{}, error) {
				pub, _, err := ed25519.GenerateKey(rand.Reader)
				return pub, err
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pubKey, err := tt.generateKey()
			if err != nil {
				t.Fatalf("Failed to generate key: %v", err)
			}

			// Marshal to PKIX
			keyBytes, err := x509.MarshalPKIXPublicKey(pubKey)
			if err != nil {
				t.Fatalf("Failed to marshal public key: %v", err)
			}

			// Write to temp file
			tmpFile := filepath.Join(t.TempDir(), "public.pem")
			pemBlock := &pem.Block{Type: "PUBLIC KEY", Bytes: keyBytes}
			if err := os.WriteFile(tmpFile, pem.EncodeToMemory(pemBlock), 0644); err != nil {
				t.Fatalf("Failed to write test key file: %v", err)
			}

			// Test loading
			cfg := KeyConfig{Path: tmpFile}
			loadedKey, err := cfg.LoadPublicKey()
			if err != nil {
				t.Fatalf("LoadPublicKey() error = %v", err)
			}

			if loadedKey == nil {
				t.Error("LoadPublicKey() returned nil")
			}
		})
	}
}

// TestKeyConfig_LoadPublicKey_Errors tests error cases for LoadPublicKey.
func TestKeyConfig_LoadPublicKey_Errors(t *testing.T) {
	tests := []struct {
		name        string
		setupFunc   func(t *testing.T) string
		expectError string
	}{
		{
			name: "empty path",
			setupFunc: func(t *testing.T) string {
				return ""
			},
			expectError: "key path is required",
		},
		{
			name: "nonexistent file",
			setupFunc: func(t *testing.T) string {
				return "/nonexistent/path/key.pem"
			},
			expectError: "failed to read public key file",
		},
		{
			name: "invalid PEM",
			setupFunc: func(t *testing.T) string {
				tmpFile := filepath.Join(t.TempDir(), "invalid.pem")
				os.WriteFile(tmpFile, []byte("not a PEM file"), 0644)
				return tmpFile
			},
			expectError: "failed to decode PEM block",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := tt.setupFunc(t)
			cfg := KeyConfig{Path: path}
			_, err := cfg.LoadPublicKey()
			if err == nil {
				t.Error("Expected error, got nil")
			} else if tt.expectError != "" && !strings.Contains(err.Error(), tt.expectError) {
				t.Errorf("Error = %q, want to contain %q", err.Error(), tt.expectError)
			}
		})
	}
}
