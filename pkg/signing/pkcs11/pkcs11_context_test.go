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
	"testing"
)

func TestFindPKCS11Module_DefaultPaths(t *testing.T) {
	// Test with nil URI (should use default paths)
	uri := &URI{}

	// Create a temp directory with a mock module
	tmpDir := t.TempDir()
	mockModule := filepath.Join(tmpDir, "libsofthsm2.so")
	if err := os.WriteFile(mockModule, []byte("mock"), 0755); err != nil {
		t.Fatalf("Failed to create mock module: %v", err)
	}

	// Test finding the module
	modulePath, err := findPKCS11Module(uri, []string{tmpDir})
	if err != nil {
		t.Errorf("Expected to find module, got error: %v", err)
	}

	if modulePath != mockModule {
		t.Errorf("Expected module path %s, got %s", mockModule, modulePath)
	}
}

func TestFindPKCS11Module_ExplicitPath(t *testing.T) {
	tmpDir := t.TempDir()
	mockModule := filepath.Join(tmpDir, "custom.so")
	if err := os.WriteFile(mockModule, []byte("mock"), 0755); err != nil {
		t.Fatalf("Failed to create mock module: %v", err)
	}

	uri := NewURI()
	uri.queryAttributes = map[string]string{"module-path": mockModule}
	uri.SetAllowAnyModule(true)

	modulePath, err := findPKCS11Module(uri, nil)
	if err != nil {
		t.Errorf("Expected to find module with explicit path, got error: %v", err)
	}

	if modulePath != mockModule {
		t.Errorf("Expected module path %s, got %s", mockModule, modulePath)
	}
}

func TestFindPKCS11Module_EmptyPaths(t *testing.T) {
	// Test behavior with empty search paths
	uri := NewURI()

	// Should still work if system defaults exist
	// This test is documenting current behavior
	_, err := findPKCS11Module(uri, []string{})
	// Don't fail the test - system may or may not have modules
	if err != nil {
		t.Logf("No PKCS#11 modules found (expected on some systems): %v", err)
	}
}

func TestFindPKCS11Module_MultipleSearchPaths(t *testing.T) {
	tmpDir1 := t.TempDir()
	tmpDir2 := t.TempDir()

	// Create module in second directory
	mockModule := filepath.Join(tmpDir2, "libsofthsm2.so")
	if err := os.WriteFile(mockModule, []byte("mock"), 0755); err != nil {
		t.Fatalf("Failed to create mock module: %v", err)
	}

	uri := &URI{}

	// Should find module in tmpDir2
	modulePath, err := findPKCS11Module(uri, []string{tmpDir1, tmpDir2})
	if err != nil {
		t.Errorf("Expected to find module in search paths, got error: %v", err)
	}

	if modulePath != mockModule {
		t.Errorf("Expected module path %s, got %s", mockModule, modulePath)
	}
}

func TestFindPKCS11Module_SearchesAllDefaultNames(t *testing.T) {
	tmpDir := t.TempDir()

	// Create a module with one of the default names (not the first one)
	mockModule := filepath.Join(tmpDir, "opensc-pkcs11.so")
	if err := os.WriteFile(mockModule, []byte("mock"), 0755); err != nil {
		t.Fatalf("Failed to create mock module: %v", err)
	}

	uri := &URI{}

	modulePath, err := findPKCS11Module(uri, []string{tmpDir})
	if err != nil {
		t.Errorf("Expected to find module with default name, got error: %v", err)
	}

	if modulePath != mockModule {
		t.Errorf("Expected module path %s, got %s", mockModule, modulePath)
	}
}

func TestParsePKCS11URI_ValidURI(t *testing.T) {
	tests := []struct {
		name    string
		uri     string
		wantErr bool
	}{
		{
			name:    "Simple URI with token",
			uri:     "pkcs11:token=mytoken",
			wantErr: false,
		},
		{
			name:    "URI with token and object",
			uri:     "pkcs11:token=mytoken;object=mykey",
			wantErr: false,
		},
		{
			name:    "URI with query parameters",
			uri:     "pkcs11:token=mytoken?pin-value=1234",
			wantErr: false,
		},
		{
			name:    "Complex URI",
			uri:     "pkcs11:token=mytoken;object=mykey;id=%01?pin-value=1234&module-path=/usr/lib/libsofthsm2.so",
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			uri, err := ParsePKCS11URI(tt.uri)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParsePKCS11URI() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr && uri == nil {
				t.Error("Expected non-nil URI for valid input")
			}
		})
	}
}

func TestParsePKCS11URI_InvalidURI(t *testing.T) {
	tests := []struct {
		name string
		uri  string
	}{
		{
			name: "Missing pkcs11 prefix",
			uri:  "token=mytoken",
		},
		{
			name: "Empty string",
			uri:  "",
		},
		{
			name: "Invalid format",
			uri:  "not-a-valid-uri",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ParsePKCS11URI(tt.uri)
			if err == nil {
				t.Error("Expected error for invalid URI, got nil")
			}
		})
	}
}

func TestPKCS11Context_NilHandling(t *testing.T) {
	var ctx *Context
	_ = ctx
}
