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

package verify

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/digitorus/timestamp"
	"github.com/sigstore/model-signing/pkg/modelartifact"
	protobundle "github.com/sigstore/protobuf-specs/gen/pb-go/bundle/v1"
	protocommon "github.com/sigstore/protobuf-specs/gen/pb-go/common/v1"
	sigbundle "github.com/sigstore/sigstore-go/pkg/bundle"
)

func createTestModel(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "weights.bin"), []byte("model-weights-data"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(dir, "config"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "config", "params.json"), []byte(`{"layers": 12}`), 0644); err != nil {
		t.Fatal(err)
	}
	return dir
}

func signAndMarshal(t *testing.T, modelPath string, opts modelartifact.Options) []byte {
	t.Helper()
	m, err := modelartifact.Canonicalize(modelPath, opts)
	if err != nil {
		t.Fatalf("failed to canonicalize: %v", err)
	}
	payload, err := modelartifact.MarshalPayload(m)
	if err != nil {
		t.Fatalf("failed to marshal payload: %v", err)
	}
	return payload
}

func TestCompareModelWithBundle_SHA256RoundTrip(t *testing.T) {
	modelPath := createTestModel(t)
	payload := signAndMarshal(t, modelPath, modelartifact.Options{
		HashAlgorithm: "sha256",
	})

	err := CompareModelWithBundle(payload, modelPath, modelartifact.Options{}, false)
	if err != nil {
		t.Fatalf("sha256 round-trip failed: %v", err)
	}
}

func TestCompareModelWithBundle_Blake2bRoundTrip(t *testing.T) {
	modelPath := createTestModel(t)

	payload := signAndMarshal(t, modelPath, modelartifact.Options{
		HashAlgorithm: "blake2b",
	})

	// Verify with default opts (would use sha256 if bug is present)
	err := CompareModelWithBundle(payload, modelPath, modelartifact.Options{}, false)
	if err != nil {
		t.Fatalf("blake2b round-trip failed (verifier should use bundle's hash_type): %v", err)
	}
}

func TestCompareModelWithBundle_ShardRoundTrip(t *testing.T) {
	modelPath := createTestModel(t)

	payload := signAndMarshal(t, modelPath, modelartifact.Options{
		HashAlgorithm: "sha256",
		ShardSize:     16,
	})

	// Verify with default opts (would use file serialization if bug is present)
	err := CompareModelWithBundle(payload, modelPath, modelartifact.Options{}, false)
	if err != nil {
		t.Fatalf("shard round-trip failed (verifier should use bundle's shard_size): %v", err)
	}
}

func TestCompareModelWithBundle_Blake2bShardRoundTrip(t *testing.T) {
	modelPath := createTestModel(t)

	payload := signAndMarshal(t, modelPath, modelartifact.Options{
		HashAlgorithm: "blake2b",
		ShardSize:     32,
	})

	err := CompareModelWithBundle(payload, modelPath, modelartifact.Options{}, false)
	if err != nil {
		t.Fatalf("blake2b+shard round-trip failed: %v", err)
	}
}

func TestCompareModelWithBundle_MismatchDetected(t *testing.T) {
	modelPath := createTestModel(t)

	payload := signAndMarshal(t, modelPath, modelartifact.Options{
		HashAlgorithm: "sha256",
	})

	// Tamper with a file
	if err := os.WriteFile(filepath.Join(modelPath, "weights.bin"), []byte("tampered"), 0644); err != nil {
		t.Fatal(err)
	}

	err := CompareModelWithBundle(payload, modelPath, modelartifact.Options{}, false)
	if err == nil {
		t.Fatal("expected mismatch error after tampering")
	}
	if !strings.Contains(err.Error(), "mismatch") {
		t.Fatalf("expected mismatch in error, got: %v", err)
	}
}

func TestCompareModelWithBundle_IgnorePathsFromCaller(t *testing.T) {
	modelPath := createTestModel(t)

	// Sign without ignoring anything
	payload := signAndMarshal(t, modelPath, modelartifact.Options{
		HashAlgorithm: "sha256",
	})

	// Add a new file that wasn't signed
	if err := os.WriteFile(filepath.Join(modelPath, "signature.sig"), []byte("sig"), 0644); err != nil {
		t.Fatal(err)
	}

	// Without ignore: should detect extra file
	err := CompareModelWithBundle(payload, modelPath, modelartifact.Options{}, false)
	if err == nil {
		t.Fatal("expected error for extra unsigned file")
	}

	// With ignore of the signature file (relative to model root per spec §6.2.1)
	err = CompareModelWithBundle(payload, modelPath, modelartifact.Options{
		IgnorePaths: []string{"signature.sig"},
	}, false)
	if err != nil {
		t.Fatalf("should pass when ignoring the extra file: %v", err)
	}
}

func TestCompareModelWithBundle_SymlinkAddedAfterSigning(t *testing.T) {
	modelPath := createTestModel(t)

	// Sign without allow_symlinks (bundle records allow_symlinks=false)
	payload := signAndMarshal(t, modelPath, modelartifact.Options{
		HashAlgorithm: "sha256",
	})

	// Add a symlink after signing
	if err := os.Symlink(
		filepath.Join(modelPath, "weights.bin"),
		filepath.Join(modelPath, "link.bin"),
	); err != nil {
		t.Skip("symlinks not supported on this platform")
	}

	// Without AllowSymlinks: should fail (symlink rejected by verifier policy)
	err := CompareModelWithBundle(payload, modelPath, modelartifact.Options{}, false)
	if err == nil {
		t.Fatal("expected error when symlink present and allow_symlinks=false")
	}

	// With AllowSymlinks + ignoreUnsigned: verifier policy allows symlinks
	err = CompareModelWithBundle(payload, modelPath, modelartifact.Options{
		AllowSymlinks: true,
	}, true)
	if err != nil {
		t.Fatalf("should pass with AllowSymlinks + ignoreUnsigned: %v", err)
	}
}

func TestCompareModelWithBundle_VerifierPolicyOverridesBundle(t *testing.T) {
	modelPath := createTestModel(t)

	// Create a symlink before signing
	if err := os.Symlink(
		filepath.Join(modelPath, "weights.bin"),
		filepath.Join(modelPath, "link.bin"),
	); err != nil {
		t.Skip("symlinks not supported on this platform")
	}

	// Sign WITH allow_symlinks (bundle records allow_symlinks=true)
	payload := signAndMarshal(t, modelPath, modelartifact.Options{
		HashAlgorithm: "sha256",
		AllowSymlinks: true,
	})

	// Verify WITHOUT AllowSymlinks: verifier policy rejects symlinks
	// even though the bundle was signed with allow_symlinks=true
	err := CompareModelWithBundle(payload, modelPath, modelartifact.Options{}, false)
	if err == nil {
		t.Fatal("expected error: verifier policy should reject symlinks regardless of bundle")
	}

	// Verify WITH AllowSymlinks: should pass
	err = CompareModelWithBundle(payload, modelPath, modelartifact.Options{
		AllowSymlinks: true,
	}, false)
	if err != nil {
		t.Fatalf("should pass with AllowSymlinks: %v", err)
	}
}

// buildTestTimestampResponse creates a valid RFC 3161 timestamp response for testing.
func buildTestTimestampResponse(t *testing.T, genTime time.Time) []byte {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "Test TSA"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageTimeStamping},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("parse cert: %v", err)
	}

	ts := &timestamp.Timestamp{
		HashAlgorithm:     crypto.SHA256,
		HashedMessage:     make([]byte, 32),
		Time:              genTime,
		Policy:            asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 2},
		Nonce:             big.NewInt(42),
		AddTSACertificate: true,
	}

	respBytes, err := ts.CreateResponseWithOpts(cert, key, crypto.SHA256)
	if err != nil {
		t.Fatalf("create timestamp response: %v", err)
	}

	return respBytes
}

func bundleWithTimestamp(t *testing.T, tsBytes []byte) *sigbundle.Bundle {
	t.Helper()
	pb := &protobundle.Bundle{
		MediaType: "application/vnd.dev.sigstore.bundle.v0.3+json",
		VerificationMaterial: &protobundle.VerificationMaterial{
			TimestampVerificationData: &protobundle.TimestampVerificationData{
				Rfc3161Timestamps: []*protocommon.RFC3161SignedTimestamp{
					{SignedTimestamp: tsBytes},
				},
			},
		},
	}
	bndl := &sigbundle.Bundle{Bundle: pb}
	return bndl
}

func TestGetTimestampFromBundle_Valid(t *testing.T) {
	expectedTime := time.Date(2025, 6, 15, 12, 0, 0, 0, time.UTC)
	tsResp := buildTestTimestampResponse(t, expectedTime)
	bndl := bundleWithTimestamp(t, tsResp)

	got, ok := GetTimestampFromBundle(bndl)
	if !ok {
		t.Fatal("expected ok=true for valid timestamp")
	}
	if !got.Equal(expectedTime) {
		t.Errorf("timestamp: got %v, want %v", got, expectedTime)
	}
}

func TestGetTimestampFromBundle_NoTimestamp(t *testing.T) {
	pb := &protobundle.Bundle{
		MediaType:            "application/vnd.dev.sigstore.bundle.v0.3+json",
		VerificationMaterial: &protobundle.VerificationMaterial{},
	}
	bndl := &sigbundle.Bundle{Bundle: pb}

	_, ok := GetTimestampFromBundle(bndl)
	if ok {
		t.Fatal("expected ok=false when no timestamp present")
	}
}

func TestGetTimestampFromBundle_InvalidBytes(t *testing.T) {
	bndl := bundleWithTimestamp(t, []byte{0xff, 0xfe, 0xfd})

	_, ok := GetTimestampFromBundle(bndl)
	if ok {
		t.Fatal("expected ok=false for invalid timestamp bytes")
	}
}

func TestGetTimestampFromBundle_NilVerificationMaterial(t *testing.T) {
	pb := &protobundle.Bundle{
		MediaType: "application/vnd.dev.sigstore.bundle.v0.3+json",
	}
	bndl := &sigbundle.Bundle{Bundle: pb}

	_, ok := GetTimestampFromBundle(bndl)
	if ok {
		t.Fatal("expected ok=false for nil verification material")
	}
}
