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

	verifyEngine "github.com/sigstore/model-signing/pkg/verify/sigstore"
)

type SigstoreCommand struct {
	SignaturePath    string
	IgnorePaths      []string
	IgnoreGitPaths   bool
	UseStaging       bool
	Identity         string
	IdentityProvider string
}

func (c *SigstoreCommand) Exec(ctx context.Context, modelPath string) error {
	verifier := &verifyEngine.SigstoreVerifier{
		SignaturePath:    c.SignaturePath,
		IgnorePaths:      c.IgnorePaths,
		IgnoreGitPaths:   c.IgnoreGitPaths,
		UseStaging:       c.UseStaging,
		Identity:         c.Identity,
		IdentityProvider: c.IdentityProvider,
	}
	return verifier.Verify(ctx, modelPath)
}
