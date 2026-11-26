// Copyright 2026 The Sigstore Authors.
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

package engines_test

import (
	"crypto/fips140"
	"os"
	"os/exec"
	"slices"
	"strings"
	"testing"

	hashengines "github.com/sigstore/model-signing/pkg/hashing/engines"
)

func TestBLAKE2RegistrationFIPSModes(t *testing.T) {
	const modeEnv = "MODEL_SIGNING_TEST_FIPS_REGISTRY_MODE"
	if mode := os.Getenv(modeEnv); mode != "" {
		wantEnabled := mode != "off"
		if fips140.Enabled() != wantEnabled {
			t.Fatalf("FIPS enabled = %t, want %t for %s", fips140.Enabled(), wantEnabled, mode)
		}
		if hashengines.IsSupported("blake2b") == wantEnabled {
			t.Fatalf("BLAKE2b support = %t, want %t", hashengines.IsSupported("blake2b"), !wantEnabled)
		}
		if slices.Contains(hashengines.SupportedAlgorithms(), "blake2b") == wantEnabled {
			t.Fatalf("BLAKE2b algorithm listing does not match FIPS mode %s", mode)
		}
		engine, err := hashengines.Create("blake2b")
		if wantEnabled {
			if err == nil || engine != nil {
				t.Fatalf("Create(blake2b) = (%v, %v), want unsupported algorithm", engine, err)
			}
			if !strings.Contains(err.Error(), "unsupported hash algorithm: blake2b") {
				t.Fatalf("Create(blake2b) error = %v, want unsupported algorithm", err)
			}
		} else if err != nil || engine == nil {
			t.Fatalf("Create(blake2b) = (%v, %v), want an engine", engine, err)
		}
		return
	}

	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"off", "on", "only"} {
		t.Run(mode, func(t *testing.T) {
			cmd := exec.Command(executable, "-test.run=^TestBLAKE2RegistrationFIPSModes$")
			cmd.Env = append(os.Environ(), "GODEBUG=fips140="+mode, modeEnv+"="+mode)
			if output, err := cmd.CombinedOutput(); err != nil {
				t.Fatalf("FIPS mode %s: %v\n%s", mode, err, output)
			}
		})
	}
}
