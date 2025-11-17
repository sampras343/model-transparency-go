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

	"github.com/sigstore/model-signing/pkg/utils"
	"github.com/sigstore/model-signing/pkg/verify"
)

type SigstoreVerifierOptions struct {
	ModelPath        string
	SignaturePath    string
	IgnorePaths      []string
	IgnoreGitPaths   bool
	UseStaging       bool
	Identity         string
	IdentityProvider string
}

type Verifier struct {
	opts SigstoreVerifierOptions
}

func New(opts SigstoreVerifierOptions) (*Verifier, error) {
	if opts.ModelPath == "" {
		return nil, fmt.Errorf("model path required")
	}
	// Validate model path exists and is a folder
	exists, err := utils.FolderExists(opts.ModelPath)
	if err != nil {
		return nil, fmt.Errorf("checking model path %q: %w", opts.ModelPath, err)
	}
	if !exists {
		return nil, fmt.Errorf("invalid model path %q: folder does not exist", opts.ModelPath)
	}

	// Validate signature path exists and is a file
	exists, err = utils.FileExists(opts.SignaturePath)
	if err != nil {
		return nil, fmt.Errorf("checking --signature %q: %w", opts.SignaturePath, err)
	}
	if !exists {
		return nil, fmt.Errorf("invalid --signature %q: file does not exist", opts.SignaturePath)
	}

	// Validate identity provider is a valid URL
	if _, err := url.ParseRequestURI(opts.IdentityProvider); err != nil {
		return nil, fmt.Errorf("invalid --identity_provider %q: %w", opts.IdentityProvider, err)
	}

	// Validate each ignore path exists (file or directory)
	for _, p := range opts.IgnorePaths {
		if p == "" {
			return nil, fmt.Errorf("invalid --ignore-paths: contains empty path")
		}
		exists, err := utils.FileExists(p)
		if err != nil {
			return nil, fmt.Errorf("checking ignore path %q: %w", p, err)
		}
		if !exists {
			return nil, fmt.Errorf("ignore path not found: %q", p)
		}
	}

	fmt.Println("Sigstore verification")
	fmt.Printf("  MODEL_PATH:      %s\n", filepath.Clean(opts.ModelPath))
	fmt.Printf("  --signature:     %s\n", filepath.Clean(opts.SignaturePath))
	fmt.Printf("  --ignore-paths:  %v\n", opts.IgnorePaths)
	fmt.Printf("  --ignore-git-paths:    %v\n", opts.IgnoreGitPaths)
	fmt.Printf("  --use-staging:   %v\n", opts.UseStaging)
	fmt.Printf("  --identity:      %s\n", opts.Identity)
	fmt.Printf("  --identity_provider: %s\n", opts.IdentityProvider)

	return &Verifier{opts: opts}, nil

}

func (v *Verifier) Verify(ctx context.Context) (verify.Result, error) {
	// TODO: integrate real Sigstore verification against the bundle & identities.
	return verify.Result{Verified: true}, nil
}
