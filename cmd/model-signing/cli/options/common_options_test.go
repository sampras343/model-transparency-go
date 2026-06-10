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

package options

import (
	"testing"

	"github.com/spf13/cobra"
)

func newTestCmd() *cobra.Command {
	return &cobra.Command{Use: "test"}
}

func TestModelPathFlags_AddFlags(t *testing.T) {
	cmd := newTestCmd()
	flags := &ModelPathFlags{}
	flags.AddFlags(cmd)

	for _, name := range []string{"ignore-paths", "ignore-git-paths", "allow-symlinks"} {
		if cmd.Flags().Lookup(name) == nil {
			t.Errorf("expected flag %q to be registered", name)
		}
	}
}

func TestModelPathFlags_Defaults(t *testing.T) {
	cmd := newTestCmd()
	flags := &ModelPathFlags{}
	flags.AddFlags(cmd)

	if flags.IgnoreGitPaths != true {
		t.Error("expected IgnoreGitPaths default to be true")
	}
	if flags.AllowSymlinks != false {
		t.Error("expected AllowSymlinks default to be false")
	}
}

func TestSignatureOutputFlags_AddFlags(t *testing.T) {
	cmd := newTestCmd()
	flags := &SignatureOutputFlags{}
	flags.AddFlags(cmd)

	f := cmd.Flags().Lookup("signature")
	if f == nil {
		t.Fatal("expected flag 'signature' to be registered")
	}
	if f.DefValue != "model.sig" {
		t.Errorf("expected default 'model.sig', got %q", f.DefValue)
	}
}

func TestSignatureInputFlags_AddFlags(t *testing.T) {
	cmd := newTestCmd()
	flags := &SignatureInputFlags{}
	flags.AddFlags(cmd)

	f := cmd.Flags().Lookup("signature")
	if f == nil {
		t.Fatal("expected flag 'signature' to be registered")
	}

	// Verify the flag is required by checking annotations
	if _, ok := f.Annotations[cobra.BashCompOneRequiredFlag]; !ok {
		t.Error("expected 'signature' flag to be marked as required")
	}
}

func TestSigstoreFlags_AddFlags(t *testing.T) {
	cmd := newTestCmd()
	flags := &SigstoreFlags{}
	flags.AddFlags(cmd)

	for _, name := range []string{"use-staging", "trust-config"} {
		if cmd.Flags().Lookup(name) == nil {
			t.Errorf("expected flag %q to be registered", name)
		}
	}
}

func TestIgnoreUnsignedFlags_AddFlags(t *testing.T) {
	cmd := newTestCmd()
	flags := &IgnoreUnsignedFlags{}
	flags.AddFlags(cmd)

	f := cmd.Flags().Lookup("ignore-unsigned-files")
	if f == nil {
		t.Fatal("expected flag 'ignore-unsigned-files' to be registered")
	}
	if f.DefValue != "false" {
		t.Errorf("expected default 'false', got %q", f.DefValue)
	}
}

func TestTSAFlags_AddFlags(t *testing.T) {
	cmd := newTestCmd()
	flags := &TSAFlags{}
	flags.AddFlags(cmd)

	f := cmd.Flags().Lookup("tsa-url")
	if f == nil {
		t.Fatal("expected flag 'tsa-url' to be registered")
	}
	if f.DefValue != "" {
		t.Errorf("expected empty default, got %q", f.DefValue)
	}
}

func TestTSAFlags_SetValue(t *testing.T) {
	cmd := newTestCmd()
	flags := &TSAFlags{}
	flags.AddFlags(cmd)

	if err := cmd.Flags().Set("tsa-url", "https://tsa.example.com"); err != nil {
		t.Fatalf("failed to set tsa-url: %v", err)
	}
	if flags.TSAUrl != "https://tsa.example.com" {
		t.Errorf("expected TSAUrl to be 'https://tsa.example.com', got %q", flags.TSAUrl)
	}
}

func TestAddAllFlags(t *testing.T) {
	cmd := newTestCmd()
	AddAllFlags(cmd, &ModelPathFlags{}, &SignatureOutputFlags{}, &TSAFlags{})

	expected := []string{"ignore-paths", "ignore-git-paths", "allow-symlinks", "signature", "tsa-url"}
	for _, name := range expected {
		if cmd.Flags().Lookup(name) == nil {
			t.Errorf("expected flag %q to be registered via AddAllFlags", name)
		}
	}
}
