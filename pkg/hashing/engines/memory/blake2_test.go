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
)

// Test that BLAKE2 implements StreamingHashEngine at compile time.
func TestBLAKE2_ImplementsStreamingHashEngine(t *testing.T) {
	var _ hashengines.StreamingHashEngine = (*BLAKE2)(nil)
}

func TestBLAKE2_UpdateThenCompute(t *testing.T) {
	const want = "26bc14024d5d6818ad7c4dee519353c290e38b6535f16f62b6ce5c6ff346c354542496f89b84eacffa1da51f0ac5e643f965637cc24e0b3f819bdae05f3932b0"

	h, err := NewBLAKE2(nil)
	if err != nil {
		t.Fatalf("NewBLAKE2(nil) error = %v", err)
	}

	h.Update([]byte("abcd"))

	d, err := h.Compute()
	if err != nil {
		t.Fatalf("Compute() error = %v", err)
	}

	got := digestHex(t, d)
	if got != want {
		t.Errorf("Compute() = %q, want %q", got, want)
	}
}

func TestBLAKE2_InitialDataConstructor(t *testing.T) {
	const want = "26bc14024d5d6818ad7c4dee519353c290e38b6535f16f62b6ce5c6ff346c354542496f89b84eacffa1da51f0ac5e643f965637cc24e0b3f819bdae05f3932b0"

	h, err := NewBLAKE2([]byte("abcd"))
	if err != nil {
		t.Fatalf("NewBLAKE2(initial) error = %v", err)
	}

	d, err := h.Compute()
	if err != nil {
		t.Fatalf("Compute() error = %v", err)
	}

	got := digestHex(t, d)
	if got != want {
		t.Errorf("Compute() = %q, want %q", got, want)
	}
}

func TestBLAKE2_ResetAndRecompute(t *testing.T) {
	const want = "26bc14024d5d6818ad7c4dee519353c290e38b6535f16f62b6ce5c6ff346c354542496f89b84eacffa1da51f0ac5e643f965637cc24e0b3f819bdae05f3932b0"

	h, err := NewBLAKE2(nil)
	if err != nil {
		t.Fatalf("NewBLAKE2(nil) error = %v", err)
	}

	h.Update([]byte("junk"))
	h.Reset(nil)
	h.Update([]byte("abcd"))

	d, err := h.Compute()
	if err != nil {
		t.Fatalf("Compute() error = %v", err)
	}

	got := digestHex(t, d)
	if got != want {
		t.Errorf("Compute() after Reset() = %q, want %q", got, want)
	}
}
