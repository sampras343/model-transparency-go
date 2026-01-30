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
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestKeyConfig_LoadPrivateKey_ECDSA tests loading ECDSA private keys.
func TestKeyConfig_LoadPrivateKey_ECDSA(t *testing.T) {
	// Generate test key
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate ECDSA key: %v", err)
	}

	// Marshal to PKCS8
	keyBytes, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		t.Fatalf("Failed to marshal private key: %v", err)
	}

	// Write to temp file
	tmpFile := filepath.Join(t.TempDir(), "ec_private.pem")
	pemBlock := &pem.Block{Type: "PRIVATE KEY", Bytes: keyBytes}
	if err := os.WriteFile(tmpFile, pem.EncodeToMemory(pemBlock), 0600); err != nil {
		t.Fatalf("Failed to write test key file: %v", err)
	}

	// Test loading
	cfg := KeyConfig{Path: tmpFile}
	loadedKey, err := cfg.LoadPrivateKey()
	if err != nil {
		t.Fatalf("LoadPrivateKey() error = %v", err)
	}

	// Verify key type
	ecKey, ok := loadedKey.(*ecdsa.PrivateKey)
	if !ok {
		t.Fatalf("LoadPrivateKey() returned %T, want *ecdsa.PrivateKey", loadedKey)
	}

	// Verify key matches
	if !ecKey.PublicKey.Equal(&privateKey.PublicKey) {
		t.Error("Loaded key does not match original key")
	}
}

// TestKeyConfig_LoadPrivateKey_RSA tests loading RSA private keys.
func TestKeyConfig_LoadPrivateKey_RSA(t *testing.T) {
	// Generate test key
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key: %v", err)
	}

	// Marshal to PKCS8
	keyBytes, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		t.Fatalf("Failed to marshal private key: %v", err)
	}

	// Write to temp file
	tmpFile := filepath.Join(t.TempDir(), "rsa_private.pem")
	pemBlock := &pem.Block{Type: "PRIVATE KEY", Bytes: keyBytes}
	if err := os.WriteFile(tmpFile, pem.EncodeToMemory(pemBlock), 0600); err != nil {
		t.Fatalf("Failed to write test key file: %v", err)
	}

	// Test loading
	cfg := KeyConfig{Path: tmpFile}
	loadedKey, err := cfg.LoadPrivateKey()
	if err != nil {
		t.Fatalf("LoadPrivateKey() error = %v", err)
	}

	// Verify key type
	rsaKey, ok := loadedKey.(*rsa.PrivateKey)
	if !ok {
		t.Fatalf("LoadPrivateKey() returned %T, want *rsa.PrivateKey", loadedKey)
	}

	// Verify key matches
	if !rsaKey.PublicKey.Equal(&privateKey.PublicKey) {
		t.Error("Loaded key does not match original key")
	}
}

// TestKeyConfig_LoadPrivateKey_Ed25519 tests loading Ed25519 private keys.
func TestKeyConfig_LoadPrivateKey_Ed25519(t *testing.T) {
	// Generate test key
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate Ed25519 key: %v", err)
	}

	// Marshal to PKCS8
	keyBytes, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		t.Fatalf("Failed to marshal private key: %v", err)
	}

	// Write to temp file
	tmpFile := filepath.Join(t.TempDir(), "ed25519_private.pem")
	pemBlock := &pem.Block{Type: "PRIVATE KEY", Bytes: keyBytes}
	if err := os.WriteFile(tmpFile, pem.EncodeToMemory(pemBlock), 0600); err != nil {
		t.Fatalf("Failed to write test key file: %v", err)
	}

	// Test loading
	cfg := KeyConfig{Path: tmpFile}
	loadedKey, err := cfg.LoadPrivateKey()
	if err != nil {
		t.Fatalf("LoadPrivateKey() error = %v", err)
	}

	// Verify key type
	edKey, ok := loadedKey.(ed25519.PrivateKey)
	if !ok {
		t.Fatalf("LoadPrivateKey() returned %T, want ed25519.PrivateKey", loadedKey)
	}

	// Verify key matches
	if !edKey.Equal(privateKey) {
		t.Error("Loaded key does not match original key")
	}
}

// TestKeyConfig_LoadPrivateKey_ECFormat tests loading EC private keys in traditional format.
func TestKeyConfig_LoadPrivateKey_ECFormat(t *testing.T) {
	// Generate test key
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate ECDSA key: %v", err)
	}

	// Marshal to EC private key format
	keyBytes, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		t.Fatalf("Failed to marshal EC private key: %v", err)
	}

	// Write to temp file
	tmpFile := filepath.Join(t.TempDir(), "ec_private.pem")
	pemBlock := &pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBytes}
	if err := os.WriteFile(tmpFile, pem.EncodeToMemory(pemBlock), 0600); err != nil {
		t.Fatalf("Failed to write test key file: %v", err)
	}

	// Test loading
	cfg := KeyConfig{Path: tmpFile}
	loadedKey, err := cfg.LoadPrivateKey()
	if err != nil {
		t.Fatalf("LoadPrivateKey() error = %v", err)
	}

	// Verify key type
	_, ok := loadedKey.(*ecdsa.PrivateKey)
	if !ok {
		t.Fatalf("LoadPrivateKey() returned %T, want *ecdsa.PrivateKey", loadedKey)
	}
}

// TestKeyConfig_LoadPrivateKey_PKCS1Format tests loading RSA keys in PKCS1 format.
func TestKeyConfig_LoadPrivateKey_PKCS1Format(t *testing.T) {
	// Generate test key
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key: %v", err)
	}

	// Marshal to PKCS1 format
	keyBytes := x509.MarshalPKCS1PrivateKey(privateKey)

	// Write to temp file
	tmpFile := filepath.Join(t.TempDir(), "rsa_private.pem")
	pemBlock := &pem.Block{Type: "RSA PRIVATE KEY", Bytes: keyBytes}
	if err := os.WriteFile(tmpFile, pem.EncodeToMemory(pemBlock), 0600); err != nil {
		t.Fatalf("Failed to write test key file: %v", err)
	}

	// Test loading
	cfg := KeyConfig{Path: tmpFile}
	loadedKey, err := cfg.LoadPrivateKey()
	if err != nil {
		t.Fatalf("LoadPrivateKey() error = %v", err)
	}

	// Verify key type
	_, ok := loadedKey.(*rsa.PrivateKey)
	if !ok {
		t.Fatalf("LoadPrivateKey() returned %T, want *rsa.PrivateKey", loadedKey)
	}
}

// TestKeyConfig_LoadPrivateKey_Errors tests error cases for LoadPrivateKey.
func TestKeyConfig_LoadPrivateKey_Errors(t *testing.T) {
	tests := []struct {
		name        string
		setupFunc   func(t *testing.T) string
		password    string
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
			expectError: "failed to read private key file",
		},
		{
			name: "invalid PEM",
			setupFunc: func(t *testing.T) string {
				tmpFile := filepath.Join(t.TempDir(), "invalid.pem")
				os.WriteFile(tmpFile, []byte("not a PEM file"), 0600)
				return tmpFile
			},
			expectError: "failed to decode PEM block",
		},
		{
			name: "password on unencrypted key",
			setupFunc: func(t *testing.T) string {
				privateKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
				keyBytes, _ := x509.MarshalPKCS8PrivateKey(privateKey)
				tmpFile := filepath.Join(t.TempDir(), "unencrypted.pem")
				pemBlock := &pem.Block{Type: "PRIVATE KEY", Bytes: keyBytes}
				os.WriteFile(tmpFile, pem.EncodeToMemory(pemBlock), 0600)
				return tmpFile
			},
			password:    "unused-password",
			expectError: "password provided but key is not encrypted",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := tt.setupFunc(t)
			cfg := KeyConfig{Path: path, Password: tt.password}
			_, err := cfg.LoadPrivateKey()
			if err == nil {
				t.Error("Expected error, got nil")
			} else if tt.expectError != "" && !containsString(err.Error(), tt.expectError) {
				t.Errorf("Error = %q, want to contain %q", err.Error(), tt.expectError)
			}
		})
	}
}

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
			} else if tt.expectError != "" && !containsString(err.Error(), tt.expectError) {
				t.Errorf("Error = %q, want to contain %q", err.Error(), tt.expectError)
			}
		})
	}
}

// TestExtractPublicKey tests extracting public keys from private keys.
func TestExtractPublicKey(t *testing.T) {
	t.Run("ECDSA", func(t *testing.T) {
		privateKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		pubKey, err := ExtractPublicKey(privateKey)
		if err != nil {
			t.Fatalf("ExtractPublicKey() error = %v", err)
		}
		ecPub, ok := pubKey.(*ecdsa.PublicKey)
		if !ok {
			t.Fatalf("ExtractPublicKey() returned %T, want *ecdsa.PublicKey", pubKey)
		}
		if !ecPub.Equal(&privateKey.PublicKey) {
			t.Error("Extracted public key does not match")
		}
	})

	t.Run("RSA", func(t *testing.T) {
		privateKey, _ := rsa.GenerateKey(rand.Reader, 2048)
		pubKey, err := ExtractPublicKey(privateKey)
		if err != nil {
			t.Fatalf("ExtractPublicKey() error = %v", err)
		}
		rsaPub, ok := pubKey.(*rsa.PublicKey)
		if !ok {
			t.Fatalf("ExtractPublicKey() returned %T, want *rsa.PublicKey", pubKey)
		}
		if !rsaPub.Equal(&privateKey.PublicKey) {
			t.Error("Extracted public key does not match")
		}
	})

	t.Run("Ed25519", func(t *testing.T) {
		pubKey, privateKey, _ := ed25519.GenerateKey(rand.Reader)
		extracted, err := ExtractPublicKey(privateKey)
		if err != nil {
			t.Fatalf("ExtractPublicKey() error = %v", err)
		}
		edPub, ok := extracted.(ed25519.PublicKey)
		if !ok {
			t.Fatalf("ExtractPublicKey() returned %T, want ed25519.PublicKey", extracted)
		}
		if !edPub.Equal(pubKey) {
			t.Error("Extracted public key does not match")
		}
	})

	t.Run("unsupported type", func(t *testing.T) {
		_, err := ExtractPublicKey("not a key")
		if err == nil {
			t.Error("Expected error for unsupported key type")
		}
	})
}

// TestComputePublicKeyHash tests computing public key hashes.
func TestComputePublicKeyHash(t *testing.T) {
	privateKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	pubKey := &privateKey.PublicKey

	hash1, err := ComputePublicKeyHash(pubKey)
	if err != nil {
		t.Fatalf("ComputePublicKeyHash() error = %v", err)
	}

	// Hash should be hex-encoded SHA256 (64 characters)
	if len(hash1) != 64 {
		t.Errorf("ComputePublicKeyHash() length = %d, want 64", len(hash1))
	}

	// Same key should produce same hash
	hash2, _ := ComputePublicKeyHash(pubKey)
	if hash1 != hash2 {
		t.Error("ComputePublicKeyHash() not deterministic")
	}

	// Different key should produce different hash
	otherKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	hash3, _ := ComputePublicKeyHash(&otherKey.PublicKey)
	if hash1 == hash3 {
		t.Error("Different keys produced same hash")
	}
}

// TestComputePublicKeyHashFromFile tests computing hash from key file.
func TestComputePublicKeyHashFromFile(t *testing.T) {
	// Create a test public key file
	privateKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	keyBytes, _ := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	pemBlock := &pem.Block{Type: "PUBLIC KEY", Bytes: keyBytes}

	tmpFile := filepath.Join(t.TempDir(), "public.pem")
	if err := os.WriteFile(tmpFile, pem.EncodeToMemory(pemBlock), 0644); err != nil {
		t.Fatalf("Failed to write test key file: %v", err)
	}

	hash, err := ComputePublicKeyHashFromFile(tmpFile)
	if err != nil {
		t.Fatalf("ComputePublicKeyHashFromFile() error = %v", err)
	}

	if len(hash) != 64 {
		t.Errorf("ComputePublicKeyHashFromFile() length = %d, want 64", len(hash))
	}

	// Test error case
	_, err = ComputePublicKeyHashFromFile("/nonexistent/file")
	if err == nil {
		t.Error("Expected error for nonexistent file")
	}
}

// TestLoadCertificate tests loading X509 certificates.
func TestLoadCertificate(t *testing.T) {
	// Create a self-signed certificate
	cert := createTestCertificate(t)

	// Write to temp file
	tmpFile := filepath.Join(t.TempDir(), "cert.pem")
	pemBlock := &pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}
	if err := os.WriteFile(tmpFile, pem.EncodeToMemory(pemBlock), 0644); err != nil {
		t.Fatalf("Failed to write test cert file: %v", err)
	}

	// Test loading
	loadedCert, err := LoadCertificate(tmpFile)
	if err != nil {
		t.Fatalf("LoadCertificate() error = %v", err)
	}

	if !loadedCert.Equal(cert) {
		t.Error("Loaded certificate does not match original")
	}
}

// TestLoadCertificate_Errors tests error cases for LoadCertificate.
func TestLoadCertificate_Errors(t *testing.T) {
	tests := []struct {
		name        string
		path        string
		setupFunc   func(t *testing.T) string
		expectError string
	}{
		{
			name:        "empty path",
			path:        "",
			expectError: "certificate path is required",
		},
		{
			name:        "nonexistent file",
			path:        "/nonexistent/path/cert.pem",
			expectError: "failed to read certificate file",
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
			path := tt.path
			if tt.setupFunc != nil {
				path = tt.setupFunc(t)
			}
			_, err := LoadCertificate(path)
			if err == nil {
				t.Error("Expected error, got nil")
			} else if !containsString(err.Error(), tt.expectError) {
				t.Errorf("Error = %q, want to contain %q", err.Error(), tt.expectError)
			}
		})
	}
}

// TestLoadCertificateChain tests loading certificate chains.
func TestLoadCertificateChain(t *testing.T) {
	// Create test certificates
	cert1 := createTestCertificate(t)
	cert2 := createTestCertificate(t)

	tmpDir := t.TempDir()

	// Write individual cert files
	file1 := filepath.Join(tmpDir, "cert1.pem")
	pemBlock1 := &pem.Block{Type: "CERTIFICATE", Bytes: cert1.Raw}
	os.WriteFile(file1, pem.EncodeToMemory(pemBlock1), 0644)

	file2 := filepath.Join(tmpDir, "cert2.pem")
	pemBlock2 := &pem.Block{Type: "CERTIFICATE", Bytes: cert2.Raw}
	os.WriteFile(file2, pem.EncodeToMemory(pemBlock2), 0644)

	// Test loading chain from multiple files
	certs, err := LoadCertificateChain([]string{file1, file2})
	if err != nil {
		t.Fatalf("LoadCertificateChain() error = %v", err)
	}

	if len(certs) != 2 {
		t.Errorf("LoadCertificateChain() returned %d certs, want 2", len(certs))
	}
}

// TestLoadCertificateChain_MultipleCertsInFile tests loading multiple certs from one file.
func TestLoadCertificateChain_MultipleCertsInFile(t *testing.T) {
	// Create test certificates
	cert1 := createTestCertificate(t)
	cert2 := createTestCertificate(t)

	// Write both certs to single file
	tmpFile := filepath.Join(t.TempDir(), "chain.pem")
	var pemData []byte
	pemData = append(pemData, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert1.Raw})...)
	pemData = append(pemData, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert2.Raw})...)
	os.WriteFile(tmpFile, pemData, 0644)

	// Test loading chain from single file
	certs, err := LoadCertificateChain([]string{tmpFile})
	if err != nil {
		t.Fatalf("LoadCertificateChain() error = %v", err)
	}

	if len(certs) != 2 {
		t.Errorf("LoadCertificateChain() returned %d certs, want 2", len(certs))
	}
}

// TestParseCertificates tests parsing certificates from bytes.
func TestParseCertificates(t *testing.T) {
	t.Run("single PEM certificate", func(t *testing.T) {
		cert := createTestCertificate(t)
		pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})

		certs, err := ParseCertificates(pemBytes)
		if err != nil {
			t.Fatalf("ParseCertificates() error = %v", err)
		}
		if len(certs) != 1 {
			t.Errorf("ParseCertificates() returned %d certs, want 1", len(certs))
		}
	})

	t.Run("multiple PEM certificates", func(t *testing.T) {
		cert1 := createTestCertificate(t)
		cert2 := createTestCertificate(t)

		var pemBytes []byte
		pemBytes = append(pemBytes, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert1.Raw})...)
		pemBytes = append(pemBytes, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert2.Raw})...)

		certs, err := ParseCertificates(pemBytes)
		if err != nil {
			t.Fatalf("ParseCertificates() error = %v", err)
		}
		if len(certs) != 2 {
			t.Errorf("ParseCertificates() returned %d certs, want 2", len(certs))
		}
	})

	t.Run("DER certificate", func(t *testing.T) {
		cert := createTestCertificate(t)

		certs, err := ParseCertificates(cert.Raw)
		if err != nil {
			t.Fatalf("ParseCertificates() error = %v", err)
		}
		if len(certs) != 1 {
			t.Errorf("ParseCertificates() returned %d certs, want 1", len(certs))
		}
	})

	t.Run("invalid data", func(t *testing.T) {
		_, err := ParseCertificates([]byte("invalid data"))
		if err == nil {
			t.Error("Expected error for invalid certificate data")
		}
	})
}

// TestValidatePublicKeysMatch tests public key matching.
func TestValidatePublicKeysMatch(t *testing.T) {
	t.Run("matching ECDSA keys", func(t *testing.T) {
		key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		err := ValidatePublicKeysMatch(&key.PublicKey, &key.PublicKey)
		if err != nil {
			t.Errorf("ValidatePublicKeysMatch() error = %v for matching keys", err)
		}
	})

	t.Run("matching RSA keys", func(t *testing.T) {
		key, _ := rsa.GenerateKey(rand.Reader, 2048)
		err := ValidatePublicKeysMatch(&key.PublicKey, &key.PublicKey)
		if err != nil {
			t.Errorf("ValidatePublicKeysMatch() error = %v for matching keys", err)
		}
	})

	t.Run("matching Ed25519 keys", func(t *testing.T) {
		pub, _, _ := ed25519.GenerateKey(rand.Reader)
		err := ValidatePublicKeysMatch(pub, pub)
		if err != nil {
			t.Errorf("ValidatePublicKeysMatch() error = %v for matching keys", err)
		}
	})

	t.Run("different ECDSA keys", func(t *testing.T) {
		key1, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		key2, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		err := ValidatePublicKeysMatch(&key1.PublicKey, &key2.PublicKey)
		if err == nil {
			t.Error("Expected error for different keys")
		}
	})

	t.Run("type mismatch ECDSA vs RSA", func(t *testing.T) {
		ecKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
		err := ValidatePublicKeysMatch(&ecKey.PublicKey, &rsaKey.PublicKey)
		if err == nil {
			t.Error("Expected error for type mismatch")
		}
	})

	t.Run("unsupported key type", func(t *testing.T) {
		err := ValidatePublicKeysMatch("not a key", "not a key")
		if err == nil {
			t.Error("Expected error for unsupported key type")
		}
	})
}

// Helper function to create a self-signed test certificate.
func createTestCertificate(t *testing.T) *x509.Certificate {
	t.Helper()

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate key for certificate: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Test Org"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}

	certBytes, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	if err != nil {
		t.Fatalf("Failed to create certificate: %v", err)
	}

	cert, err := x509.ParseCertificate(certBytes)
	if err != nil {
		t.Fatalf("Failed to parse created certificate: %v", err)
	}

	return cert
}

// Helper function for string containment check.
func containsString(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(substr) == 0 ||
		(len(s) > 0 && containsSubstringHelper(s, substr)))
}

func containsSubstringHelper(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
