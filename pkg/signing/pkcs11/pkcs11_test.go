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
	"testing"
)

// TestTrimNullBytes tests the trimNullBytes helper function
func TestTrimNullBytes(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "no null bytes",
			input:    "hello",
			expected: "hello",
		},
		{
			name:     "trailing null bytes",
			input:    "hello\x00\x00",
			expected: "hello",
		},
		{
			name:     "only null bytes",
			input:    "\x00\x00\x00",
			expected: "",
		},
		{
			name:     "empty string",
			input:    "",
			expected: "",
		},
		{
			name:     "null bytes in middle",
			input:    "hel\x00lo",
			expected: "hel", // trimNullBytes stops at first null byte
		},
		{
			name:     "multiple trailing nulls",
			input:    "test\x00\x00\x00\x00",
			expected: "test",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := trimNullBytes(tt.input)
			if result != tt.expected {
				t.Errorf("trimNullBytes() = %q, want %q", result, tt.expected)
			}
		})
	}
}

// TestDefaultModulePaths verifies that default module paths are defined
func TestDefaultModulePaths(t *testing.T) {
	if len(DefaultModulePaths) == 0 {
		t.Error("DefaultModulePaths should not be empty")
	}

	// Check that paths are non-empty strings
	for i, path := range DefaultModulePaths {
		if path == "" {
			t.Errorf("DefaultModulePaths[%d] is empty string", i)
		}
	}
}

// TestNewSigner_InvalidURI tests error handling for invalid PKCS#11 URIs
func TestNewSigner_InvalidURI(t *testing.T) {
	tests := []struct {
		name      string
		uri       string
		wantError bool
	}{
		{
			name:      "empty URI",
			uri:       "",
			wantError: true,
		},
		{
			name:      "missing prefix",
			uri:       "token=test;object=key",
			wantError: true,
		},
		{
			name:      "malformed URI",
			uri:       "pkcs11:::",
			wantError: true, // Parser catches malformed URIs
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NewSigner(tt.uri, nil)
			if tt.wantError && err == nil {
				t.Error("Expected error for invalid URI, got nil")
			}
			if !tt.wantError && err != nil && tt.uri != "" {
				// We expect errors for empty URI, but not for malformed ones (parser is lenient)
				t.Errorf("Unexpected error: %v", err)
			}
		})
	}
}
