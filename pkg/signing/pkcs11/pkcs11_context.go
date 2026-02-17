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

// PKCS#11 context and module management.
//
// This file provides Context which manages PKCS#11 module loading and
// key discovery using the crypto11 library. It handles module path resolution,
// token initialization, and key finding based on PKCS#11 URIs.
package pkcs11

import (
	"crypto"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/ThalesGroup/crypto11"
)

// Context wraps a crypto11 context for managing PKCS#11 sessions.
type Context struct {
	ctx *crypto11.Context
}

// LoadContext loads a PKCS#11 module and creates a context from a parsed URI.
// It searches for the module in the provided module paths.
func LoadContext(uri *URI, modulePaths []string) (*Context, error) {
	// Find the PKCS#11 module library
	modulePath, err := findPKCS11Module(uri, modulePaths)
	if err != nil {
		return nil, fmt.Errorf("failed to find PKCS#11 module: %w", err)
	}

	// Get token label and PIN from URI
	tokenLabel := uri.GetTokenLabel()
	if tokenLabel == "" {
		return nil, fmt.Errorf("token label not specified in PKCS#11 URI")
	}

	pin, err := uri.GetPIN()
	if err != nil || pin == "" {
		// Try to get PIN from environment variable
		pin = os.Getenv("PKCS11_PIN")
	}

	// Configure crypto11
	config := &crypto11.Config{
		Path:       modulePath,
		TokenLabel: tokenLabel,
		Pin:        pin,
	}

	// Open PKCS#11 context
	ctx, err := crypto11.Configure(config)
	if err != nil {
		return nil, fmt.Errorf("failed to configure PKCS#11 context: %w", err)
	}

	return &Context{ctx: ctx}, nil
}

// FindSigner finds a crypto.Signer (private key) in the PKCS#11 token based on the URI.
func (pc *Context) FindSigner(uri *URI) (crypto.Signer, error) {
	// Get key identifier from URI
	keyID, keyLabel, err := uri.GetKeyIDAndLabel()
	if err != nil {
		return nil, fmt.Errorf("failed to get key ID/label from URI: %w", err)
	}

	// Try to find the key by ID first, then by label
	var signer crypto.Signer

	if len(keyID) > 0 {
		// Find by key ID
		signer, err = pc.ctx.FindKeyPair(keyID, nil)
		if err == nil && signer != nil {
			return signer, nil
		}
	}

	if keyLabel != "" {
		// Find by key label
		signer, err = pc.ctx.FindKeyPair(nil, []byte(keyLabel))
		if err == nil && signer != nil {
			return signer, nil
		}
	}

	// If no specific key was found, try to use the first available key
	signers, err := pc.ctx.FindAllKeyPairs()
	if err != nil {
		return nil, fmt.Errorf("failed to find key pairs: %w", err)
	}

	if len(signers) == 0 {
		return nil, fmt.Errorf("no key pairs found in PKCS#11 token")
	}

	// Use the first available key
	return signers[0], nil
}

// Close closes the PKCS#11 context and releases resources.
func (pc *Context) Close() error {
	if pc.ctx != nil {
		return pc.ctx.Close()
	}
	return nil
}

// findPKCS11Module finds the PKCS#11 module library path.
// It checks the module-path attribute in the URI and the provided module paths.
func findPKCS11Module(uri *URI, modulePaths []string) (string, error) {
	// Check if module path is specified in URI
	modulePath, err := uri.GetModule()
	if err == nil && modulePath != "" {
		if _, err := os.Stat(modulePath); err == nil {
			return modulePath, nil
		}
	}

	// Search in provided module paths
	for _, dir := range modulePaths {
		matches, err := filepath.Glob(filepath.Join(dir, "*.so"))
		if err != nil {
			continue
		}
		if len(matches) > 0 {
			return matches[0], nil
		}
	}

	// Try common default paths for SoftHSM2
	defaultPaths := []string{
		"/usr/lib/softhsm/libsofthsm2.so",
		"/usr/lib64/softhsm/libsofthsm2.so",
		"/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so",
		"/usr/lib64/pkcs11/libsofthsm2.so",
		"/usr/lib/pkcs11/libsofthsm2.so",
		"/usr/local/lib/softhsm/libsofthsm2.so",
		"/opt/homebrew/lib/softhsm/libsofthsm2.so",               // macOS ARM
		"/usr/local/Cellar/softhsm/*/lib/softhsm/libsofthsm2.so", // macOS Intel
	}

	for _, path := range defaultPaths {
		// Handle glob patterns
		if strings.Contains(path, "*") {
			matches, err := filepath.Glob(path)
			if err == nil && len(matches) > 0 {
				return matches[0], nil
			}
		} else {
			if _, err := os.Stat(path); err == nil {
				return path, nil
			}
		}
	}

	return "", fmt.Errorf("PKCS#11 module not found in any standard location")
}

// ParsePKCS11URI parses a PKCS#11 URI string and returns a URI object.
func ParsePKCS11URI(uriString string) (*URI, error) {
	uri := NewURI()
	if err := uri.Parse(uriString); err != nil {
		return nil, err
	}

	// Validate that URI has sufficient information to locate a key
	tokenLabel := uri.GetTokenLabel()
	keyID, keyLabel, _ := uri.GetKeyIDAndLabel()
	if tokenLabel == "" && keyID == nil && keyLabel == "" {
		return nil, fmt.Errorf("PKCS#11 URI must specify at least one of: token, id, or object (key label)")
	}

	return uri, nil
}
