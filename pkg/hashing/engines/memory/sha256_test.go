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

// Test that SHA256 implements StreamingHashEngine at compile time.
func TestSHA256_ImplementsStreamingHashEngine(t *testing.T) {
	var _ hashengines.StreamingHashEngine = (*SHA256Engine)(nil)
}

// helper to compute hex from a digests.Digest.
func digestHex(t *testing.T, d interface{ Hex() string }) string {
	t.Helper()
	return d.Hex()
}

func TestSHA256_UpdateThenCompute(t *testing.T) {
	const want = "88d4266fd4e6338d13b845fcf289579d209c897823b9217da3e161936f031589"

	h := NewSHA256Engine(nil)
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

func TestSHA256_InitialDataConstructor(t *testing.T) {
	const want = "88d4266fd4e6338d13b845fcf289579d209c897823b9217da3e161936f031589"

	h := NewSHA256Engine([]byte("abcd"))

	d, err := h.Compute()
	if err != nil {
		t.Fatalf("Compute() error = %v", err)
	}

	got := digestHex(t, d)
	if got != want {
		t.Errorf("Compute() = %q, want %q", got, want)
	}
}

func TestSHA256_ResetAndRecompute(t *testing.T) {
	const want = "88d4266fd4e6338d13b845fcf289579d209c897823b9217da3e161936f031589"

	h := NewSHA256Engine(nil)

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

func TestSHA256_ResetWithInitialData(t *testing.T) {
	const want = "88d4266fd4e6338d13b845fcf289579d209c897823b9217da3e161936f031589"

	h := NewSHA256Engine(nil)

	h.Reset([]byte("abcd"))

	d, err := h.Compute()
	if err != nil {
		t.Fatalf("Compute() error = %v", err)
	}

	got := digestHex(t, d)
	if got != want {
		t.Errorf("Compute() after Reset(initial) = %q, want %q", got, want)
	}
}
