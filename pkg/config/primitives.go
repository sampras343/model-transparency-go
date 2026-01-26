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
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"

	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/tuf"
)

// TrustRootConfig handles Sigstore trust root configuration.
//
// This provides a unified way to load trust roots for both signing and verification,
// supporting staging environments, custom trust roots, and production defaults.
//
// Configuration Priority (first match wins):
//  1. If UseStaging is true → fetch staging trust root from network (TrustRootPath ignored)
//  2. If TrustRootPath is set → load custom trust root from file
//  3. Otherwise → fetch production trust root from network (default)
//
// Examples:
//
//	// Use production (default)
//	cfg := TrustRootConfig{}
//
//	// Use staging for testing
//	cfg := TrustRootConfig{UseStaging: true}
//
//	// Use custom trust root
//	cfg := TrustRootConfig{TrustRootPath: "/path/to/trust-root.json"}
//
//	// Invalid: UseStaging takes precedence, TrustRootPath will be ignored
//	cfg := TrustRootConfig{UseStaging: true, TrustRootPath: "/path/to/trust-root.json"}
type TrustRootConfig struct {
	// UseStaging uses staging configurations instead of production.
	// When true, staging trust root is fetched from network.
	// Should only be set to true when testing. Default is false.
	//
	// IMPORTANT: When UseStaging is true, TrustRootPath is ignored.
	UseStaging bool

	// TrustRootPath is a path to a custom trust root JSON file.
	// When provided (and UseStaging is false), this custom trust root
	// is loaded instead of the default Sigstore trust root.
	//
	// IMPORTANT: This field is ignored if UseStaging is true.
	TrustRootPath string
}

// LoadTrustRoot loads a trust root based on configuration.
//
// The loading strategy follows a priority order:
//  1. UseStaging=true → Fetch staging trust root from network
//  2. TrustRootPath set → Load from specified file path
//  3. Default → Fetch production trust root from network
//
// Returns a TrustedRoot containing the loaded trust material,
// or an error if the selected trust root cannot be loaded.
func (c *TrustRootConfig) LoadTrustRoot() (*root.TrustedRoot, error) {
	// Priority 1: Staging environment (for testing)
	if c.UseStaging {
		// Use staging TUF options with staging mirror and root
		tufOpts := tuf.DefaultOptions().
			WithRepositoryBaseURL(tuf.StagingMirror).
			WithRoot(tuf.StagingRoot())

		trustRoot, err := root.FetchTrustedRootWithOptions(tufOpts)
		if err != nil {
			return nil, fmt.Errorf("failed to fetch staging trust root: %w", err)
		}
		return trustRoot, nil
	}

	// Priority 2: Custom trust root from file
	if c.TrustRootPath != "" {
		trustRoot, err := root.NewTrustedRootFromPath(c.TrustRootPath)
		if err != nil {
			return nil, fmt.Errorf("failed to load trust root from file: %w", err)
		}
		return trustRoot, nil
	}

	// Priority 3: Production trust root (default)
	trustRoot, err := root.FetchTrustedRoot()
	if err != nil {
		return nil, fmt.Errorf("failed to fetch production trust root: %w", err)
	}
	return trustRoot, nil
}

// KeyConfig handles cryptographic key file configuration.
//
// This provides a unified way to load and manage cryptographic keys
// for signing and verification operations.
type KeyConfig struct {
	// Path is the file path to the key (PEM format).
	Path string

	// Password is the optional password for encrypted private keys.
	// Only used when loading private keys.
	Password string
}

// LoadPrivateKey loads a private key from the configured path.
//
// Supports PKCS8, PKCS1, and EC private key formats.
// Handles both encrypted and unencrypted keys.
//
// Returns a crypto.PrivateKey interface containing the loaded key,
// or an error if the key cannot be loaded or parsed.
func (c *KeyConfig) LoadPrivateKey() (crypto.PrivateKey, error) {
	if c.Path == "" {
		return nil, fmt.Errorf("key path is required")
	}

	pemBytes, err := os.ReadFile(c.Path)
	if err != nil {
		return nil, fmt.Errorf("failed to read private key file: %w", err)
	}

	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}

	var keyBytes []byte
	if c.Password != "" {
		// Decrypt the key if password is provided
		//nolint:staticcheck // SA1019: x509.IsEncryptedPEMBlock is deprecated but needed for PKCS1
		if x509.IsEncryptedPEMBlock(block) {
			//nolint:staticcheck // SA1019: x509.DecryptPEMBlock is deprecated but needed for PKCS1
			keyBytes, err = x509.DecryptPEMBlock(block, []byte(c.Password))
			if err != nil {
				return nil, fmt.Errorf("failed to decrypt private key: %w", err)
			}
		} else {
			return nil, fmt.Errorf("password provided but key is not encrypted")
		}
	} else {
		keyBytes = block.Bytes
	}

	// Try parsing as different key types
	// Try PKCS8 (most common)
	if key, err := x509.ParsePKCS8PrivateKey(keyBytes); err == nil {
		return key, nil
	}

	// Try EC private key
	if key, err := x509.ParseECPrivateKey(keyBytes); err == nil {
		return key, nil
	}

	// Try RSA private key
	if key, err := x509.ParsePKCS1PrivateKey(keyBytes); err == nil {
		return key, nil
	}

	return nil, fmt.Errorf("failed to parse private key (unsupported format)")
}

// LoadPublicKey loads a public key from the configured path.
//
// Supports PKIX and PKCS1 public key formats.
// Validates that the key type is supported (ECDSA, RSA, Ed25519).
//
// Returns a crypto.PublicKey interface containing the loaded key,
// or an error if the key cannot be loaded, parsed, or is unsupported.
func (c *KeyConfig) LoadPublicKey() (crypto.PublicKey, error) {
	if c.Path == "" {
		return nil, fmt.Errorf("key path is required")
	}

	pemBytes, err := os.ReadFile(c.Path)
	if err != nil {
		return nil, fmt.Errorf("failed to read public key file: %w", err)
	}

	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}

	// Try parsing as PKIX public key (most common format)
	if key, err := x509.ParsePKIXPublicKey(block.Bytes); err == nil {
		return validatePublicKey(key)
	}

	// Try parsing as PKCS1 RSA public key
	if key, err := x509.ParsePKCS1PublicKey(block.Bytes); err == nil {
		return validatePublicKey(key)
	}

	return nil, fmt.Errorf("failed to parse public key (unsupported format)")
}

// ExtractPublicKey extracts the public key from a private key.
//
// Supports ECDSA, RSA, and Ed25519 private keys.
//
// Returns the corresponding public key, or an error if the
// private key type is unsupported.
func ExtractPublicKey(privateKey crypto.PrivateKey) (crypto.PublicKey, error) {
	switch key := privateKey.(type) {
	case *ecdsa.PrivateKey:
		return &key.PublicKey, nil
	case *rsa.PrivateKey:
		return &key.PublicKey, nil
	case ed25519.PrivateKey:
		return key.Public(), nil
	default:
		return nil, fmt.Errorf("unsupported private key type: %T", privateKey)
	}
}

// ComputePublicKeyHash computes the SHA256 hash of the PEM-encoded public key.
//
// This hash is used as a hint in the verification material to identify which
// public key was used for signing.
//
// Returns the hex-encoded SHA256 hash string, or an error if the key
// cannot be marshaled.
func ComputePublicKeyHash(publicKey crypto.PublicKey) (string, error) {
	// Marshal public key to PKIX format
	pubKeyBytes, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return "", fmt.Errorf("failed to marshal public key: %w", err)
	}

	// Encode to PEM
	pemBlock := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubKeyBytes,
	}
	pemBytes := pem.EncodeToMemory(pemBlock)

	// Compute SHA256 hash
	hashBytes := sha256.Sum256(pemBytes)
	return fmt.Sprintf("%x", hashBytes), nil
}

// ComputePublicKeyHashFromFile computes the SHA256 hash of a PEM-encoded public key file.
//
// This is useful for verification material hints when you have the key file path.
//
// Returns the hex-encoded SHA256 hash string, or an error if the file
// cannot be read.
func ComputePublicKeyHashFromFile(path string) (string, error) {
	keyBytes, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("failed to read public key for hashing: %w", err)
	}

	hashBytes := sha256.Sum256(keyBytes)
	return fmt.Sprintf("%x", hashBytes), nil
}

// validatePublicKey checks if the public key type is supported.
//
// Validates ECDSA curves (P-256, P-384, P-521), RSA keys, and Ed25519 keys.
//
// Returns the public key if valid, or an error if the key type or
// curve is unsupported.
func validatePublicKey(key interface{}) (crypto.PublicKey, error) {
	switch k := key.(type) {
	case *ecdsa.PublicKey:
		// Validate curve is supported
		curveName := k.Curve.Params().Name
		if curveName != "P-256" && curveName != "P-384" && curveName != "P-521" {
			return nil, fmt.Errorf("unsupported elliptic curve: %s (supported: P-256, P-384, P-521)", curveName)
		}
		return k, nil
	case *rsa.PublicKey:
		// RSA keys are supported
		return k, nil
	case ed25519.PublicKey:
		// Ed25519 keys are supported
		return k, nil
	default:
		return nil, fmt.Errorf("unsupported public key type: %T", key)
	}
}

// LoadCertificate loads a single X509 certificate from a PEM-encoded file.
//
// Returns the parsed certificate, or an error if the file cannot be read
// or the certificate cannot be parsed.
func LoadCertificate(path string) (*x509.Certificate, error) {
	if path == "" {
		return nil, fmt.Errorf("certificate path is required")
	}

	pemBytes, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read certificate file: %w", err)
	}

	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block from certificate file")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate: %w", err)
	}

	return cert, nil
}

// LoadCertificateChain loads multiple X509 certificates from PEM-encoded files.
// Each file may contain one or more certificates.
//
// Returns the list of parsed certificates, or an error if any file cannot be read
// or any certificate cannot be parsed.
func LoadCertificateChain(paths []string) ([]*x509.Certificate, error) {
	var certificates []*x509.Certificate

	for _, path := range paths {
		pemBytes, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("failed to read certificate chain file %s: %w", path, err)
		}

		// Parse all certificates in the file
		certs, err := ParseCertificates(pemBytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse certificates from %s: %w", path, err)
		}

		certificates = append(certificates, certs...)
	}

	return certificates, nil
}

// ParseCertificates parses one or more PEM-encoded certificates from raw bytes.
// Supports files with multiple concatenated PEM certificate blocks.
// Falls back to DER format if no PEM blocks are found.
//
// Returns the list of parsed certificates, or an error if parsing fails.
func ParseCertificates(certBytes []byte) ([]*x509.Certificate, error) {
	var certs []*x509.Certificate

	// Try parsing as PEM-encoded certificates
	// Multiple certificates may be in the same file
	remaining := certBytes
	for {
		block, rest := pem.Decode(remaining)
		if block == nil {
			break
		}

		if block.Type == "CERTIFICATE" {
			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				return nil, fmt.Errorf("failed to parse PEM certificate: %w", err)
			}
			certs = append(certs, cert)
		}

		remaining = rest
	}

	if len(certs) > 0 {
		return certs, nil
	}

	// If no PEM blocks found, try parsing as raw DER
	cert, err := x509.ParseCertificate(certBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate (tried both PEM and DER formats): %w", err)
	}

	return []*x509.Certificate{cert}, nil
}

// ValidatePublicKeysMatch validates that two public keys are equal.
// Supports ECDSA, RSA, and Ed25519 key types.
//
// Returns an error if the keys don't match or are of different types.
func ValidatePublicKeysMatch(keyFromPrivate, keyFromCert crypto.PublicKey) error {
	switch priv := keyFromPrivate.(type) {
	case *ecdsa.PublicKey:
		pub, ok := keyFromCert.(*ecdsa.PublicKey)
		if !ok {
			return fmt.Errorf("public key type mismatch: private key is ECDSA, certificate is %T", keyFromCert)
		}
		if !priv.Equal(pub) {
			return fmt.Errorf("the public key from the certificate does not match the public key paired with the private key")
		}
	case *rsa.PublicKey:
		pub, ok := keyFromCert.(*rsa.PublicKey)
		if !ok {
			return fmt.Errorf("public key type mismatch: private key is RSA, certificate is %T", keyFromCert)
		}
		if !priv.Equal(pub) {
			return fmt.Errorf("the public key from the certificate does not match the public key paired with the private key")
		}
	case ed25519.PublicKey:
		pub, ok := keyFromCert.(ed25519.PublicKey)
		if !ok {
			return fmt.Errorf("public key type mismatch: private key is Ed25519, certificate is %T", keyFromCert)
		}
		if !priv.Equal(pub) {
			return fmt.Errorf("the public key from the certificate does not match the public key paired with the private key")
		}
	default:
		return fmt.Errorf("unsupported public key type: %T", keyFromPrivate)
	}

	return nil
}
