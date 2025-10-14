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

package sigstore

import (
	"context"
	"fmt"
	"net/url"
	"path/filepath"
	modelsigning "github.com/sigstore/model-signing/internal/pkg/model-signing"
)

type SigstoreVerifier struct {
	SignaturePath    string
	IgnorePaths      []string
	IgnoreGitPaths   bool
	UseStaging       bool
	Identity         string
	IdentityProvider string
}

func (v *SigstoreVerifier) Verify(ctx context.Context, modelPath string) error {
	// Validate model path exists and is a folder
	exists, err := modelsigning.FolderExists(modelPath)
	if err != nil {
		return fmt.Errorf("checking model path %q: %w", modelPath, err)
	}
	if !exists {
		return fmt.Errorf("invalid model path %q: folder does not exist", modelPath)
	}

	// Validate signature path exists and is a file
	exists, err = modelsigning.FileExists(v.SignaturePath)
	if err != nil {
		return fmt.Errorf("checking --signature %q: %w", v.SignaturePath, err)
	}
	if !exists {
		return fmt.Errorf("invalid --signature %q: file does not exist", v.SignaturePath)
	}

	// Validate identity provider is a valid URL
	if _, err := url.ParseRequestURI(v.IdentityProvider); err != nil {
		return fmt.Errorf("invalid --identity_provider %q: %w", v.IdentityProvider, err)
	}

	// Validate each ignore path exists (file or directory)
	for _, p := range v.IgnorePaths {
		if p == "" {
			return fmt.Errorf("invalid --ignore-paths: contains empty path")
		}
		exists, err := modelsigning.FileExists(p)
		if err != nil {
			return fmt.Errorf("checking ignore path %q: %w", p, err)
		}
		if !exists {
			return fmt.Errorf("ignore path not found: %q", p)
		}
	}

	// TODO: integrate real Sigstore verification against the bundle & identities.
	fmt.Println("Sigstore verification")
	fmt.Printf("  MODEL_PATH:      %s\n", filepath.Clean(modelPath))
	fmt.Printf("  --signature:     %s\n", filepath.Clean(v.SignaturePath))
	fmt.Printf("  --ignore-paths:  %v\n", v.IgnorePaths)
	fmt.Printf("  --ignore-git-paths:    %v\n", v.IgnoreGitPaths)
	fmt.Printf("  --use-staging:   %v\n", v.UseStaging)
	fmt.Printf("  --identity:      %s\n", v.Identity)
	fmt.Printf("  --identity_provider: %s\n", v.IdentityProvider)

	return nil
}
