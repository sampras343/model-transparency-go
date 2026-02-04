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

func TestPkcs11URI_ParseBasic(t *testing.T) {
	tests := []struct {
		name        string
		uri         string
		wantErr     bool
		checkToken  string
		checkObject string
	}{
		{
			name:        "empty URI",
			uri:         "pkcs11:",
			wantErr:     false,
			checkToken:  "",
			checkObject: "",
		},
		{
			name:        "token and object",
			uri:         "pkcs11:token=mytoken;object=mykey",
			wantErr:     false,
			checkToken:  "mytoken",
			checkObject: "mykey",
		},
		{
			name:        "with type",
			uri:         "pkcs11:object=my-pubkey;type=public",
			wantErr:     false,
			checkObject: "my-pubkey",
		},
		{
			name:    "with module-name",
			uri:     "pkcs11:object=my-sign-key;type=private?module-name=mypkcs11",
			wantErr: false,
		},
		{
			name:    "with PIN",
			uri:     "pkcs11:token=mytoken;object=mykey?pin-value=1234",
			wantErr: false,
		},
		{
			name:    "missing pkcs11 prefix",
			uri:     "token=mytoken",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			uri := NewPkcs11URI()
			err := uri.Parse(tt.uri)

			if (err != nil) != tt.wantErr {
				t.Errorf("Parse() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if err == nil {
				if tt.checkToken != "" {
					token := uri.GetTokenLabel()
					if token != tt.checkToken {
						t.Errorf("Expected token %s, got %s", tt.checkToken, token)
					}
				}
				if tt.checkObject != "" {
					_, label, _ := uri.GetKeyIDAndLabel()
					if label != tt.checkObject {
						t.Errorf("Expected object %s, got %s", tt.checkObject, label)
					}
				}
			}
		})
	}
}

func TestPkcs11URI_ParsePercentEncoding(t *testing.T) {
	tests := []struct {
		name         string
		uri          string
		expectedAttr string
		expectedVal  string
	}{
		{
			name:         "percent encoded spaces",
			uri:          "pkcs11:token=Software%20PKCS%2311%20softtoken",
			expectedAttr: "token",
			expectedVal:  "Software PKCS#11 softtoken",
		},
		{
			name:         "percent encoded special chars",
			uri:          "pkcs11:token=My%20token%25%20created%20by%20Joe",
			expectedAttr: "token",
			expectedVal:  "My token% created by Joe",
		},
		{
			name:         "manufacturer with comma",
			uri:          "pkcs11:manufacturer=Snake%20Oil,%20Inc.",
			expectedAttr: "manufacturer",
			expectedVal:  "Snake Oil, Inc.",
		},
		{
			name:         "unicode character",
			uri:          "pkcs11:token=Name%20with%20a%20small%20A%20with%20acute:%20%C3%A1",
			expectedAttr: "token",
			expectedVal:  "Name with a small A with acute: á",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			uri := NewPkcs11URI()
			err := uri.Parse(tt.uri)
			if err != nil {
				t.Fatalf("Parse() error = %v", err)
			}

			// Check decoded value
			if tt.expectedAttr == "token" {
				token := uri.GetTokenLabel()
				if token != tt.expectedVal {
					t.Errorf("Expected token '%s', got '%s'", tt.expectedVal, token)
				}
			}
		})
	}
}

func TestPkcs11URI_SlotID(t *testing.T) {
	tests := []struct {
		name      string
		uri       string
		wantSlot  int
		wantErr   bool
		errString string
	}{
		{
			name:     "valid slot-id",
			uri:      "pkcs11:slot-id=0",
			wantSlot: 0,
			wantErr:  false,
		},
		{
			name:     "slot-id 42",
			uri:      "pkcs11:slot-id=42",
			wantSlot: 42,
			wantErr:  false,
		},
		{
			name:      "negative slot-id",
			uri:       "pkcs11:slot-id=-1",
			wantErr:   true,
			errString: "must be a number",
		},
		{
			name:      "non-numeric slot-id",
			uri:       "pkcs11:slot-id=abc",
			wantErr:   true,
			errString: "must be a number",
		},
		{
			name:      "slot-id too large",
			uri:       "pkcs11:slot-id=4294967296", // 2^32
			wantErr:   true,
			errString: "must be a number",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			uri := NewPkcs11URI()
			// Validation happens during Parse() in Go implementation
			err := uri.Parse(tt.uri)

			if tt.wantErr {
				if err == nil {
					t.Errorf("Expected error containing '%s', got nil", tt.errString)
				} else if !strings.Contains(err.Error(), tt.errString) {
					t.Errorf("Expected error containing '%s', got '%s'", tt.errString, err.Error())
				}
			} else {
				if err != nil {
					t.Fatalf("Parse() error = %v", err)
				}
				slotID, err := uri.GetSlotID()
				if err != nil {
					t.Errorf("Unexpected error: %v", err)
				}
				if slotID != tt.wantSlot {
					t.Errorf("Expected slot-id %d, got %d", tt.wantSlot, slotID)
				}
			}
		})
	}
}

func TestPkcs11URI_PINSource(t *testing.T) {
	tmpDir := t.TempDir()
	pinFile := filepath.Join(tmpDir, "pinfile")
	expectedPIN := "mysecretpin"

	err := os.WriteFile(pinFile, []byte(expectedPIN), 0600)
	if err != nil {
		t.Fatalf("Failed to create PIN file: %v", err)
	}

	tests := []struct {
		name       string
		uri        string
		wantPIN    string
		wantHasPIN bool
		wantErr    bool
	}{
		{
			name:       "pin-value",
			uri:        "pkcs11:token=test?pin-value=1234",
			wantPIN:    "1234",
			wantHasPIN: true,
			wantErr:    false,
		},
		{
			name:       "pin-source with file URI",
			uri:        "pkcs11:token=test?pin-source=file://" + pinFile,
			wantPIN:    expectedPIN,
			wantHasPIN: true,
			wantErr:    false,
		},
		{
			name:       "pin-source without file URI prefix",
			uri:        "pkcs11:token=test?pin-source=" + pinFile,
			wantPIN:    expectedPIN,
			wantHasPIN: true,
			wantErr:    false,
		},
		{
			name:       "no PIN",
			uri:        "pkcs11:token=test",
			wantHasPIN: false,
			wantErr:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			uri := NewPkcs11URI()
			err := uri.Parse(tt.uri)
			if err != nil {
				t.Fatalf("Parse() error = %v", err)
			}

			hasPIN := uri.HasPIN()
			if hasPIN != tt.wantHasPIN {
				t.Errorf("HasPIN() = %v, want %v", hasPIN, tt.wantHasPIN)
			}

			if tt.wantHasPIN {
				pin, err := uri.GetPIN()
				if tt.wantErr {
					if err == nil {
						t.Error("Expected error, got nil")
					}
				} else {
					if err != nil {
						t.Errorf("GetPIN() error = %v", err)
					}
					if pin != tt.wantPIN {
						t.Errorf("GetPIN() = %s, want %s", pin, tt.wantPIN)
					}
				}
			}
		})
	}
}

func TestPkcs11URI_KeyIDAndLabel(t *testing.T) {
	tests := []struct {
		name      string
		uri       string
		wantLabel string
		wantIDHex string
		wantErr   bool
	}{
		{
			name:      "only label",
			uri:       "pkcs11:object=mykey",
			wantLabel: "mykey",
		},
		{
			name:      "only ID",
			uri:       "pkcs11:id=%01%02%03",
			wantIDHex: "010203",
		},
		{
			name:      "both label and ID",
			uri:       "pkcs11:id=%FF%FE;object=testkey",
			wantLabel: "testkey",
			wantIDHex: "fffe",
		},
		{
			name:    "neither label nor ID",
			uri:     "pkcs11:token=test",
			wantErr: false, // Not an error until GetKeyIDAndLabel is called
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			uri := NewPkcs11URI()
			err := uri.Parse(tt.uri)
			if err != nil {
				t.Fatalf("Parse() error = %v", err)
			}

			keyID, label, err := uri.GetKeyIDAndLabel()

			if tt.wantErr {
				if err == nil {
					t.Error("Expected error, got nil")
				}
			} else {
				if err != nil && (tt.wantIDHex != "" || tt.wantLabel != "") {
					t.Errorf("GetKeyIDAndLabel() error = %v", err)
				}

				if tt.wantLabel != "" && label != tt.wantLabel {
					t.Errorf("Expected label %s, got %s", tt.wantLabel, label)
				}

				if tt.wantIDHex != "" {
					gotHex := ""
					for _, b := range keyID {
						gotHex += string("0123456789abcdef"[b>>4])
						gotHex += string("0123456789abcdef"[b&0xf])
					}
					if gotHex != tt.wantIDHex {
						t.Errorf("Expected ID hex %s, got %s", tt.wantIDHex, gotHex)
					}
				}
			}
		})
	}
}

func TestPkcs11URI_RFC7512Examples(t *testing.T) {
	// Test URIs from RFC 7512
	examples := []string{
		"pkcs11:",
		"pkcs11:object=my-pubkey;type=public",
		"pkcs11:object=my-key;type=private?pin-source=file:/etc/token",
		"pkcs11:token=The%20Software%20PKCS%2311%20Softtoken;manufacturer=Snake%20Oil,%20Inc.;model=1.0;object=my-certificate;type=cert;id=%69%95%3E%5C%F4%BD%EC%91;serial=?pin-source=file:/etc/token_pin",
		"pkcs11:object=my-sign-key;type=private?module-name=mypkcs11",
		"pkcs11:token=Software%20PKCS%2311%20softtoken;manufacturer=Snake%20Oil,%20Inc.?pin-value=the-pin",
		"pkcs11:slot-description=Sun%20Metaslot",
		"pkcs11:library-manufacturer=Snake%20Oil,%20Inc.;library-description=Soft%20Token%20Library;library-version=1.23",
		"pkcs11:token=My%20token%25%20created%20by%20Joe;library-version=3;id=%01%02%03%Ba%dd%Ca%fe%04%05%06",
		"pkcs11:token=A%20name%20with%20a%20substring%20%25%3B;object=my-certificate;type=cert",
		"pkcs11:token=Name%20with%20a%20small%20A%20with%20acute:%20%C3%A1;object=my-certificate;type=cert",
	}

	for _, uriString := range examples {
		t.Run(uriString, func(t *testing.T) {
			uri := NewPkcs11URI()
			err := uri.Parse(uriString)
			if err != nil {
				t.Errorf("Failed to parse RFC 7512 example URI: %v", err)
			}
		})
	}
}

func TestPkcs11URI_ModuleName(t *testing.T) {
	uri := NewPkcs11URI()
	uri.SetModuleDirectories(DefaultModulePaths)
	uri.SetAllowAnyModule(true)

	err := uri.Parse("pkcs11:?module-name=softhsm2")
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}

	// Try to get module - will succeed if SoftHSM2 is installed
	_, err = uri.GetModule()
	// Don't fail if SoftHSM2 is not installed, just skip
	if err != nil && !strings.Contains(err.Error(), "could not find module") {
		t.Logf("GetModule() returned: %v (this is OK if SoftHSM2 is not installed)", err)
	}
}

func TestPkcs11URI_MissingSearchCriteria(t *testing.T) {
	uri := NewPkcs11URI()
	err := uri.Parse("pkcs11:token=test")
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}

	// Should return error when neither id nor label are provided
	_, _, err = uri.GetKeyIDAndLabel()
	if err == nil {
		t.Error("Expected error for missing search criteria, got nil")
	}
	// Accept various error messages about missing id/object
	if !strings.Contains(err.Error(), "neither") && !strings.Contains(err.Error(), "not found") {
		t.Errorf("Expected error about missing id/object, got: %v", err)
	}
}

func TestPkcs11URI_TokenValidation(t *testing.T) {
	tests := []struct {
		name    string
		uri     string
		wantErr bool
	}{
		{
			name:    "valid token",
			uri:     "pkcs11:token=mytoken",
			wantErr: false,
		},
		{
			name:    "token with spaces",
			uri:     "pkcs11:token=my%20token",
			wantErr: false,
		},
		{
			name:    "empty URI",
			uri:     "pkcs11:",
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			uri := NewPkcs11URI()
			err := uri.Parse(tt.uri)

			if (err != nil) != tt.wantErr {
				t.Errorf("Parse() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// TestPkcs11URI_GetPIN_FromFile tests reading PIN from a file
func TestPkcs11URI_GetPIN_FromFile(t *testing.T) {
	tmpDir := t.TempDir()
	pinFile := filepath.Join(tmpDir, "pin.txt")

	// Write PIN to file
	pinContent := "secret1234"
	err := os.WriteFile(pinFile, []byte(pinContent), 0600)
	if err != nil {
		t.Fatalf("Failed to write PIN file: %v", err)
	}

	uri := NewPkcs11URI()
	err = uri.Parse("pkcs11:token=test;object=key?pin-source=file://" + pinFile)
	if err != nil {
		t.Fatalf("Failed to parse URI: %v", err)
	}

	pin, err := uri.GetPIN()
	if err != nil {
		t.Fatalf("Failed to get PIN from file: %v", err)
	}

	if pin != pinContent {
		t.Errorf("Expected PIN %q, got %q", pinContent, pin)
	}
}

// TestPkcs11URI_GetPIN_FromValue tests reading PIN from pin-value
func TestPkcs11URI_GetPIN_FromValue(t *testing.T) {
	uri := NewPkcs11URI()
	err := uri.Parse("pkcs11:token=test;object=key?pin-value=1234")
	if err != nil {
		t.Fatalf("Failed to parse URI: %v", err)
	}

	pin, err := uri.GetPIN()
	if err != nil {
		t.Fatalf("Failed to get PIN: %v", err)
	}

	if pin != "1234" {
		t.Errorf("Expected PIN \"1234\", got %q", pin)
	}
}

// TestPkcs11URI_GetPIN_MissingFile tests error when PIN file doesn't exist
func TestPkcs11URI_GetPIN_MissingFile(t *testing.T) {
	uri := NewPkcs11URI()
	err := uri.Parse("pkcs11:token=test;object=key?pin-source=file:///nonexistent/pin.txt")
	if err != nil {
		t.Fatalf("Failed to parse URI: %v", err)
	}

	_, err = uri.GetPIN()
	if err == nil {
		t.Error("Expected error for missing PIN file, got nil")
	}
}

// TestPkcs11URI_GetModule_WithModuleName tests module resolution by name
func TestPkcs11URI_GetModule_WithModuleName(t *testing.T) {
	tmpDir := t.TempDir()

	// Create a mock module directory with a .so file
	moduleDir := filepath.Join(tmpDir, "pkcs11")
	err := os.MkdirAll(moduleDir, 0755)
	if err != nil {
		t.Fatalf("Failed to create module dir: %v", err)
	}

	modulePath := filepath.Join(moduleDir, "libtest.so")
	err = os.WriteFile(modulePath, []byte("mock module"), 0755)
	if err != nil {
		t.Fatalf("Failed to create module file: %v", err)
	}

	uri := NewPkcs11URI()
	uri.SetModuleDirectories([]string{moduleDir})
	uri.SetAllowAnyModule(true)

	err = uri.Parse("pkcs11:token=test;object=key?module-name=libtest")
	if err != nil {
		t.Fatalf("Failed to parse URI: %v", err)
	}

	module, err := uri.GetModule()
	if err != nil {
		t.Fatalf("Failed to get module: %v", err)
	}

	if !strings.HasSuffix(module, "libtest.so") {
		t.Errorf("Expected module path ending with libtest.so, got %s", module)
	}
}

// TestPkcs11URI_GetModule_WithModulePath tests direct module path
func TestPkcs11URI_GetModule_WithModulePath(t *testing.T) {
	tmpDir := t.TempDir()
	modulePath := filepath.Join(tmpDir, "libdirect.so")

	err := os.WriteFile(modulePath, []byte("mock module"), 0755)
	if err != nil {
		t.Fatalf("Failed to create module file: %v", err)
	}

	uri := NewPkcs11URI()
	uri.SetAllowAnyModule(true)

	err = uri.Parse("pkcs11:token=test;object=key?module-path=" + modulePath)
	if err != nil {
		t.Fatalf("Failed to parse URI: %v", err)
	}

	module, err := uri.GetModule()
	if err != nil {
		t.Fatalf("Failed to get module: %v", err)
	}

	if module != modulePath {
		t.Errorf("Expected module path %s, got %s", modulePath, module)
	}
}

// TestPkcs11URI_GetModule_NotAllowed tests module path restriction
func TestPkcs11URI_GetModule_NotAllowed(t *testing.T) {
	uri := NewPkcs11URI()
	uri.SetAllowAnyModule(false)
	uri.SetAllowedModulePaths([]string{"/allowed/path"})

	err := uri.Parse("pkcs11:token=test;object=key?module-path=/forbidden/path/module.so")
	if err != nil {
		t.Fatalf("Failed to parse URI: %v", err)
	}

	_, err = uri.GetModule()
	if err == nil {
		t.Error("Expected error for forbidden module path, got nil")
	}
}

// TestPkcs11URI_SetAllowedModulePaths tests setting allowed module paths
func TestPkcs11URI_SetAllowedModulePaths(t *testing.T) {
	tmpDir := t.TempDir()
	modulePath := filepath.Join(tmpDir, "module.so")

	// Create the module file
	err := os.WriteFile(modulePath, []byte("mock module"), 0755)
	if err != nil {
		t.Fatalf("Failed to create module file: %v", err)
	}

	uri := NewPkcs11URI()

	// Add trailing separator to allow modules in this directory
	allowedPaths := []string{tmpDir + string(filepath.Separator)}
	uri.SetAllowedModulePaths(allowedPaths)

	// Parse a URI and verify module path validation works
	uri.SetAllowAnyModule(false)

	err = uri.Parse("pkcs11:token=test;object=key?module-path=" + modulePath)
	if err != nil {
		t.Fatalf("Failed to parse URI: %v", err)
	}

	// This should succeed since tmpDir is allowed
	gotModule, err := uri.GetModule()
	if err != nil {
		t.Errorf("Expected module from allowed path to succeed, got error: %v", err)
	}

	if gotModule != modulePath {
		t.Errorf("Expected module path %s, got %s", modulePath, gotModule)
	}
}

// TestPkcs11URI_GetModule_NoModuleSpecified tests default module behavior
func TestPkcs11URI_GetModule_NoModuleSpecified(t *testing.T) {
	uri := NewPkcs11URI()
	uri.SetModuleDirectories([]string{"/usr/lib64/pkcs11"})
	uri.SetAllowAnyModule(true)

	err := uri.Parse("pkcs11:token=test;object=key")
	if err != nil {
		t.Fatalf("Failed to parse URI: %v", err)
	}

	// Should try to find a default module
	_, err = uri.GetModule()
	// Error is expected if no default module exists, but we're testing the path
	if err != nil {
		t.Logf("No default module found (expected in test environment): %v", err)
	}
}
