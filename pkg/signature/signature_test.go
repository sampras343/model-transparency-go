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

package signature

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"testing"

	protobundle "github.com/sigstore/protobuf-specs/gen/pb-go/bundle/v1"
	protocommon "github.com/sigstore/protobuf-specs/gen/pb-go/common/v1"
	protodsse "github.com/sigstore/protobuf-specs/gen/pb-go/dsse"
	"github.com/sigstore/sigstore-go/pkg/bundle"
)

// createTestBundle creates a minimal valid sigstore bundle for testing.
func createTestBundle(t *testing.T) *bundle.Bundle {
	t.Helper()

	// Create a minimal DSSE envelope with base64-encoded payload
	payload := base64.StdEncoding.EncodeToString([]byte(`{"test": "data"}`))
	signature := base64.StdEncoding.EncodeToString([]byte("test-signature"))

	protoBundle := &protobundle.Bundle{
		MediaType: "application/vnd.dev.sigstore.bundle.v0.3+json",
		// Add verification material (required by sigstore-go validation)
		VerificationMaterial: &protobundle.VerificationMaterial{
			Content: &protobundle.VerificationMaterial_PublicKey{
				PublicKey: &protocommon.PublicKeyIdentifier{
					Hint: "test-key-hint",
				},
			},
		},
		Content: &protobundle.Bundle_DsseEnvelope{
			DsseEnvelope: &protodsse.Envelope{
				PayloadType: "application/json",
				Payload:     []byte(payload),
				Signatures: []*protodsse.Signature{
					{
						Sig: []byte(signature),
					},
				},
			},
		},
	}

	b, err := bundle.NewBundle(protoBundle)
	if err != nil {
		t.Fatalf("Failed to create test bundle: %v", err)
	}

	return b
}

// TestNewSigstoreBundle tests bundle creation.
func TestNewSigstoreBundle(t *testing.T) {
	b := createTestBundle(t)

	sig := NewSigstoreBundle(b)
	if sig == nil {
		t.Fatal("NewSigstoreBundle() returned nil")
	}

	if sig.bundle != b {
		t.Error("NewSigstoreBundle() did not store the bundle correctly")
	}
}

// TestSigstoreBundle_Bundle tests Bundle() accessor.
func TestSigstoreBundle_Bundle(t *testing.T) {
	b := createTestBundle(t)
	sig := NewSigstoreBundle(b)

	retrieved := sig.Bundle()
	if retrieved != b {
		t.Error("Bundle() did not return the correct bundle")
	}
}

// TestSigstoreBundle_WriteAndRead tests round-trip serialization.
func TestSigstoreBundle_WriteAndRead(t *testing.T) {
	b := createTestBundle(t)
	sig := NewSigstoreBundle(b)

	// Write to temp file
	tmpFile := filepath.Join(t.TempDir(), "bundle.json")

	err := sig.Write(tmpFile)
	if err != nil {
		t.Fatalf("Write() error = %v", err)
	}

	// Verify file exists and is readable
	info, err := os.Stat(tmpFile)
	if err != nil {
		t.Fatalf("Failed to stat written file: %v", err)
	}
	if info.Size() == 0 {
		t.Error("Written file is empty")
	}

	// Read back
	reader := &SigstoreBundle{}
	readSig, err := reader.Read(tmpFile)
	if err != nil {
		t.Fatalf("Read() error = %v", err)
	}

	// Verify it's a SigstoreBundle
	readBundle, ok := readSig.(*SigstoreBundle)
	if !ok {
		t.Fatalf("Read() returned %T, want *SigstoreBundle", readSig)
	}

	// Verify the bundle content by comparing JSON
	origJSON, err := sig.Bundle().MarshalJSON()
	if err != nil {
		t.Fatalf("Failed to marshal original bundle: %v", err)
	}

	readJSON, err := readBundle.Bundle().MarshalJSON()
	if err != nil {
		t.Fatalf("Failed to marshal read bundle: %v", err)
	}

	if string(origJSON) != string(readJSON) {
		t.Error("Read bundle does not match written bundle")
	}
}

// TestSigstoreBundle_Write_Errors tests Write error handling.
func TestSigstoreBundle_Write_Errors(t *testing.T) {
	b := createTestBundle(t)
	sig := NewSigstoreBundle(b)

	// Try writing to a directory that doesn't exist
	err := sig.Write("/nonexistent/directory/bundle.json")
	if err == nil {
		t.Error("Expected error for nonexistent directory")
	}

	// Try writing to a read-only directory (skip when running as root).
	if os.Getuid() != 0 {
		tmpDir := t.TempDir()
		readOnlyDir := filepath.Join(tmpDir, "readonly")
		if err := os.MkdirAll(readOnlyDir, 0555); err != nil {
			t.Fatalf("Failed to create read-only directory: %v", err)
		}
		defer os.Chmod(readOnlyDir, 0755) // Cleanup

		err = sig.Write(filepath.Join(readOnlyDir, "bundle.json"))
		if err == nil {
			t.Error("Expected error for read-only directory")
		}
	}
}

// TestSigstoreBundle_Read_Errors tests Read error handling.
func TestSigstoreBundle_Read_Errors(t *testing.T) {
	reader := &SigstoreBundle{}

	t.Run("nonexistent file", func(t *testing.T) {
		_, err := reader.Read("/nonexistent/file.json")
		if err == nil {
			t.Error("Expected error for nonexistent file")
		}
	})

	t.Run("invalid JSON", func(t *testing.T) {
		tmpFile := filepath.Join(t.TempDir(), "invalid.json")
		os.WriteFile(tmpFile, []byte("not valid json"), 0644)

		_, err := reader.Read(tmpFile)
		if err == nil {
			t.Error("Expected error for invalid JSON")
		}
	})

	t.Run("empty file", func(t *testing.T) {
		tmpFile := filepath.Join(t.TempDir(), "empty.json")
		os.WriteFile(tmpFile, []byte{}, 0644)

		_, err := reader.Read(tmpFile)
		if err == nil {
			t.Error("Expected error for empty file")
		}
	})
}

// TestSigstoreBundle_FilePermissions tests that written files have correct permissions.
func TestSigstoreBundle_FilePermissions(t *testing.T) {
	b := createTestBundle(t)
	sig := NewSigstoreBundle(b)

	tmpFile := filepath.Join(t.TempDir(), "bundle.json")
	if err := sig.Write(tmpFile); err != nil {
		t.Fatalf("Write() error = %v", err)
	}

	info, err := os.Stat(tmpFile)
	if err != nil {
		t.Fatalf("Failed to stat file: %v", err)
	}

	// Check permissions - should be 0644 (world-readable)
	perms := info.Mode().Perm()
	if perms != 0644 {
		t.Errorf("File permissions = %o, want 0644", perms)
	}
}

// TestSigstoreBundle_NilBundle tests handling of nil bundle.
func TestSigstoreBundle_NilBundle(t *testing.T) {
	sig := &SigstoreBundle{bundle: nil}

	// Bundle() should return nil
	if sig.Bundle() != nil {
		t.Error("Bundle() should return nil for nil bundle")
	}
}

// TestSigstoreBundle_Interface tests interface compliance.
func TestSigstoreBundle_Interface(t *testing.T) {
	b := createTestBundle(t)
	sig := NewSigstoreBundle(b)

	// Verify SignatureBundle interface (has Write method)
	var _ interface {
		Write(path string) error
	} = sig

	// Just verify sig is not nil - interface compliance is enforced by var _ declarations in the main file
	if sig == nil {
		t.Error("Expected non-nil bundle")
	}
}
