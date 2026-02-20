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
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"

	prototrustroot "github.com/sigstore/protobuf-specs/gen/pb-go/trustroot/v1"
	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/tuf"
	"google.golang.org/protobuf/encoding/protojson"
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
// When loading from file, this function supports both formats:
//   - ClientTrustConfig: A wrapper containing trustedRoot and signingConfig fields
//   - TrustedRoot: The raw trusted root format with tlogs, certificateAuthorities, etc.
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
		trustRoot, err := loadTrustRootFromFile(c.TrustRootPath)
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

// loadTrustRootFromFile loads a trust root from a JSON file.
// It supports both ClientTrustConfig format (with nested trustedRoot)
// and raw TrustedRoot format.
func loadTrustRootFromFile(path string) (*root.TrustedRoot, error) {
	fileBytes, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read trust root file: %w", err)
	}

	// First, try to parse as ClientTrustConfig (wrapper format)
	clientConfig := &prototrustroot.ClientTrustConfig{}
	if err := protojson.Unmarshal(fileBytes, clientConfig); err == nil {
		// Successfully parsed as ClientTrustConfig
		if clientConfig.GetTrustedRoot() != nil {
			return root.NewTrustedRootFromProtobuf(clientConfig.GetTrustedRoot())
		}
		return nil, fmt.Errorf("ClientTrustConfig does not contain a trustedRoot")
	}

	// Fall back to parsing as raw TrustedRoot
	return root.NewTrustedRootFromJSON(fileBytes)
}

// LoadTrustMaterial loads both TrustedRoot and SigningConfig from the configuration.
//
// This method is useful when you need both verification material (TrustedRoot)
// and signing service URLs (SigningConfig) from a ClientTrustConfig file.
//
// Returns:
//   - TrustedRoot: The trust material for verification
//   - SigningConfig: The signing service configuration (may be nil if not available)
//   - error: Any error encountered during loading
func (c *TrustRootConfig) LoadTrustMaterial() (*root.TrustedRoot, *root.SigningConfig, error) {
	// Staging environment (for testing)
	if c.UseStaging {
		tufOpts := tuf.DefaultOptions().
			WithRepositoryBaseURL(tuf.StagingMirror).
			WithRoot(tuf.StagingRoot())

		trustRoot, err := root.FetchTrustedRootWithOptions(tufOpts)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to fetch staging trust root: %w", err)
		}

		signingConfig, err := root.FetchSigningConfigWithOptions(tufOpts)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to fetch staging signing config: %w", err)
		}

		return trustRoot, signingConfig, nil
	}

	// Custom trust config from file
	if c.TrustRootPath != "" {
		return loadTrustMaterialFromFile(c.TrustRootPath)
	}

	// Production (default)
	trustRoot, err := root.FetchTrustedRoot()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to fetch production trust root: %w", err)
	}

	signingConfig, err := root.FetchSigningConfig()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to fetch production signing config: %w", err)
	}

	return trustRoot, signingConfig, nil
}

// loadTrustMaterialFromFile loads both TrustedRoot and SigningConfig from a JSON file.
// It supports both ClientTrustConfig format (with nested trustedRoot and signingConfig)
// and raw TrustedRoot format (returns nil SigningConfig).
func loadTrustMaterialFromFile(path string) (*root.TrustedRoot, *root.SigningConfig, error) {
	fileBytes, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read trust config file: %w", err)
	}

	// First, try to parse as ClientTrustConfig (wrapper format)
	clientConfig := &prototrustroot.ClientTrustConfig{}
	if err := protojson.Unmarshal(fileBytes, clientConfig); err == nil {
		// Successfully parsed as ClientTrustConfig
		if clientConfig.GetTrustedRoot() == nil {
			return nil, nil, fmt.Errorf("ClientTrustConfig does not contain a trustedRoot")
		}

		trustRoot, err := root.NewTrustedRootFromProtobuf(clientConfig.GetTrustedRoot())
		if err != nil {
			return nil, nil, fmt.Errorf("failed to parse trustedRoot: %w", err)
		}

		var signingConfig *root.SigningConfig
		if clientConfig.GetSigningConfig() != nil {
			signingConfig, err = root.NewSigningConfigFromProtobuf(clientConfig.GetSigningConfig())
			if err != nil {
				return nil, nil, fmt.Errorf("failed to parse signingConfig: %w", err)
			}
		}

		return trustRoot, signingConfig, nil
	}

	// Fall back to parsing as raw TrustedRoot (no SigningConfig available)
	trustRoot, err := root.NewTrustedRootFromJSON(fileBytes)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse trust root: %w", err)
	}

	return trustRoot, nil, nil
}

// KeyConfig handles cryptographic key file configuration.
//
// This provides a unified way to load public keys for verification operations.
type KeyConfig struct {
	// Path is the file path to the key (PEM format).
	Path string
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
		return k, nil
	case ed25519.PublicKey:
		return k, nil
	default:
		return nil, fmt.Errorf("unsupported public key type: %T", key)
	}
}
