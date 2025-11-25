//
// Copyright 2025 The Sigstore Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package memory

import (
	"testing"

	hashengines "github.com/sigstore/model-signing/pkg/hashing/engines"
	"golang.org/x/crypto/blake2b"
)

// Test that BLAKE2 implements StreamingHashEngine at compile time.
func TestBLAKE2_ImplementsStreamingHashEngine(t *testing.T) {
	var _ hashengines.StreamingHashEngine = (*BLAKE2)(nil)
}

// Known-value test
func TestBLAKE2_HashKnownValue(t *testing.T) {
	const expected = "3f1b20a13e94ef2a12c50f40de256e0eb444f274b8e2e04e5fb3f572242c858af600a06a0c350eef1645307a9bf2fa1fcb65445a0b3b2b44d0602ab95f4fb802"

	hasher, err := NewBLAKE2([]byte("Test string"))
	if err != nil {
		t.Fatalf("NewBLAKE2(initial) error = %v", err)
	}

	digest, err := hasher.Compute()
	if err != nil {
		t.Fatalf("Compute() error = %v", err)
	}

	got := digestHex(t, digest)
	if got != expected {
		t.Errorf("Compute() = %q, expected %q", got, expected)
	}
}

// Update twice is the same as updating with concatenation
func TestBLAKE2_UpdateTwiceSameAsConcat(t *testing.T) {
	str1 := []byte("Test ")
	str2 := []byte("string")

	// hasher1: update twice
	hasher1, err := NewBLAKE2(nil)
	if err != nil {
		t.Fatalf("NewBLAKE2(nil) error = %v", err)
	}
	hasher1.Update(str1)
	hasher1.Update(str2)
	digest1, err := hasher1.Compute()
	if err != nil {
		t.Fatalf("Compute() (hasher1) error = %v", err)
	}

	// hasher2: single update with concatenation
	hasher2, err := NewBLAKE2(nil)
	if err != nil {
		t.Fatalf("NewBLAKE2(nil) error = %v", err)
	}
	hasher2.Update(append(append([]byte{}, str1...), str2...))
	digest2, err := hasher2.Compute()
	if err != nil {
		t.Fatalf("Compute() (hasher2) error = %v", err)
	}

	got1 := digestHex(t, digest1)
	got2 := digestHex(t, digest2)
	if got1 != got2 {
		t.Errorf("digest mismatch: got1=%q got2=%q", got1, got2)
	}
}

// Updating with an empty slice should not change the digest
func TestBLAKE2_UpdateEmpty(t *testing.T) {
	hasher1, err := NewBLAKE2([]byte("Test string"))
	if err != nil {
		t.Fatalf("NewBLAKE2(initial) error = %v", err)
	}
	hasher1.Update([]byte{})
	digest1, err := hasher1.Compute()
	if err != nil {
		t.Fatalf("Compute() (hasher1) error = %v", err)
	}

	hasher2, err := NewBLAKE2([]byte("Test string"))
	if err != nil {
		t.Fatalf("NewBLAKE2(initial) error = %v", err)
	}
	digest2, err := hasher2.Compute()
	if err != nil {
		t.Fatalf("Compute() (hasher2) error = %v", err)
	}

	got1 := digestHex(t, digest1)
	got2 := digestHex(t, digest2)
	if got1 != got2 {
		t.Errorf("digest mismatch with empty update: got1=%q got2=%q", got1, got2)
	}
}

// Update after Reset gives the same result as a fresh hasher
func TestBLAKE2_UpdateAfterReset(t *testing.T) {
	hasher, err := NewBLAKE2([]byte("Test string"))
	if err != nil {
		t.Fatalf("NewBLAKE2(initial) error = %v", err)
	}

	// First digest with initial data
	digest1, err := hasher.Compute()
	if err != nil {
		t.Fatalf("Compute() (first) error = %v", err)
	}

	// Reset to empty state, then re-apply the same data
	hasher.Reset(nil)
	hasher.Update([]byte("Test string"))
	digest2, err := hasher.Compute()
	if err != nil {
		t.Fatalf("Compute() (second) error = %v", err)
	}

	got1 := digestHex(t, digest1)
	got2 := digestHex(t, digest2)
	if got1 != got2 {
		t.Errorf("digest mismatch after Reset: first=%q second=%q", got1, got2)
	}
}

// DigestSize matches BLAKE2b.Size and the produced digest length
func TestBLAKE2_DigestSize(t *testing.T) {
	h, err := NewBLAKE2([]byte("Test string"))
	if err != nil {
		t.Fatalf("NewBLAKE2(initial) error = %v", err)
	}

	if got := h.DigestSize(); got != blake2b.Size {
		t.Errorf("DigestSize() = %d, expected %d", got, blake2b.Size)
	}

	d, err := h.Compute()
	if err != nil {
		t.Fatalf("Compute() error = %v", err)
	}

	// derive size from hex representation to avoid depending on Digest internals
	hexStr := digestHex(t, d)
	gotSize := len(hexStr) / 2
	if gotSize != blake2b.Size {
		t.Errorf("digest size from hex = %d, expected %d", gotSize, blake2b.Size)
	}
}
