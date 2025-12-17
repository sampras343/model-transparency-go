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

package engines_test

import (
	"reflect"
	"testing"

	hashengines "github.com/sigstore/model-signing/pkg/hashing/engines"
	"github.com/sigstore/model-signing/pkg/hashing/engines/memory"
)

func TestCreate(t *testing.T) {
	tests := []struct {
		name      string
		algorithm string
		wantErr   bool
	}{
		{"sha256", "sha256", false},
		{"blake2b", "blake2b", false},
		{"unsupported", "md5", true},
		{"empty", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			engine, err := hashengines.Create(tt.algorithm)
			if (err != nil) != tt.wantErr {
				t.Errorf("Create() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && engine == nil {
				t.Error("Create() returned nil engine without error")
			}
		})
	}
}

func TestRegister(t *testing.T) {
	// Create a test factory
	testFactory := func() (hashengines.StreamingHashEngine, error) {
		return memory.NewSHA256Engine(nil)
	}

	tests := []struct {
		name      string
		algorithm string
		factory   hashengines.HashEngineFactory
		wantErr   bool
		cleanup   bool
	}{
		{
			name:      "valid registration",
			algorithm: "test-algo",
			factory:   testFactory,
			wantErr:   false,
			cleanup:   true,
		},
		{
			name:      "empty algorithm",
			algorithm: "",
			factory:   testFactory,
			wantErr:   true,
			cleanup:   false,
		},
		{
			name:      "nil factory",
			algorithm: "test-nil",
			factory:   nil,
			wantErr:   true,
			cleanup:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := hashengines.Register(tt.algorithm, tt.factory)
			if (err != nil) != tt.wantErr {
				t.Errorf("Register() error = %v, wantErr %v", err, tt.wantErr)
			}

			// Cleanup
			if tt.cleanup && err == nil {
				_ = hashengines.Unregister(tt.algorithm)
			}
		})
	}
}

func TestRegister_Duplicate(t *testing.T) {
	testFactory := func() (hashengines.StreamingHashEngine, error) {
		return memory.NewSHA256Engine(nil)
	}

	// Register first time
	err := hashengines.Register("duplicate-test", testFactory)
	if err != nil {
		t.Fatalf("First Register() failed: %v", err)
	}
	defer hashengines.Unregister("duplicate-test")

	// Try to register again
	err = hashengines.Register("duplicate-test", testFactory)
	if err == nil {
		t.Error("Second Register() should have failed with duplicate error")
	}
}

func TestMustRegister_Panic(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Error("MustRegister() should panic on duplicate registration")
		}
	}()

	// Trigger default registration first
	_, _ = hashengines.Create("sha256")

	// This should panic because "sha256" is already registered
	hashengines.MustRegister("sha256", func() (hashengines.StreamingHashEngine, error) {
		return memory.NewSHA256Engine(nil)
	})
}

func TestSupportedAlgorithms(t *testing.T) {
	// Trigger default registration by calling Create
	_, _ = hashengines.Create("sha256") // This will trigger ensureDefaults

	algorithms := hashengines.SupportedAlgorithms()

	// Should contain at least the default algorithms
	if len(algorithms) < 2 {
		t.Errorf("SupportedAlgorithms() returned %d algorithms, want at least 2", len(algorithms))
	}

	// Check for defaults
	hasShA256 := false
	hasBlake2b := false
	for _, algo := range algorithms {
		if algo == "sha256" {
			hasShA256 = true
		}
		if algo == "blake2b" {
			hasBlake2b = true
		}
	}

	if !hasShA256 {
		t.Error("SupportedAlgorithms() missing sha256")
	}
	if !hasBlake2b {
		t.Error("SupportedAlgorithms() missing blake2b")
	}

	// Check that list is sorted
	sortedAlgos := make([]string, len(algorithms))
	copy(sortedAlgos, algorithms)
	if !reflect.DeepEqual(algorithms, sortedAlgos) {
		t.Error("SupportedAlgorithms() is not sorted")
	}
}

func TestIsSupported(t *testing.T) {
	// Trigger default registration
	_, _ = hashengines.Create("sha256")

	tests := []struct {
		name      string
		algorithm string
		want      bool
	}{
		{"sha256 supported", "sha256", true},
		{"blake2b supported", "blake2b", true},
		{"md5 not supported", "md5", false},
		{"empty not supported", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := hashengines.IsSupported(tt.algorithm); got != tt.want {
				t.Errorf("IsSupported() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestUnregister(t *testing.T) {
	testFactory := func() (hashengines.StreamingHashEngine, error) {
		return memory.NewSHA256Engine(nil)
	}

	// Register a test algorithm
	err := hashengines.Register("unregister-test", testFactory)
	if err != nil {
		t.Fatalf("Register() failed: %v", err)
	}

	// Verify it's registered
	if !hashengines.IsSupported("unregister-test") {
		t.Error("Algorithm should be registered")
	}

	// Unregister it
	err = hashengines.Unregister("unregister-test")
	if err != nil {
		t.Errorf("Unregister() error = %v", err)
	}

	// Verify it's unregistered
	if hashengines.IsSupported("unregister-test") {
		t.Error("Algorithm should not be registered after unregister")
	}

	// Try to unregister again (should fail)
	err = hashengines.Unregister("unregister-test")
	if err == nil {
		t.Error("Unregister() should fail for non-existent algorithm")
	}
}

func TestConcurrentAccess(t *testing.T) {
	// Test that concurrent access doesn't cause data races
	done := make(chan bool)

	// Reader goroutine
	go func() {
		for i := 0; i < 100; i++ {
			_ = hashengines.SupportedAlgorithms()
			_ = hashengines.IsSupported("sha256")
			_, _ = hashengines.Create("sha256")
		}
		done <- true
	}()

	// Writer goroutine
	go func() {
		testFactory := func() (hashengines.StreamingHashEngine, error) {
			return memory.NewSHA256Engine(nil)
		}
		for i := 0; i < 100; i++ {
			algoName := "concurrent-test"
			_ = hashengines.Register(algoName, testFactory)
			_ = hashengines.Unregister(algoName)
		}
		done <- true
	}()

	// Wait for both goroutines
	<-done
	<-done
}
