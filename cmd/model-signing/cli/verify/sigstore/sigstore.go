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
	"time"

	"github.com/spf13/cobra"
)

type options struct {
	SignaturePath    string   // --signature SIGNATURE_PATH (required)
	IgnorePaths      []string // --ignore-paths
	IgnoreGitPaths   bool     // --ignore-git-paths (default true; users can pass --ignore-git-paths=false)
	UseStaging       bool     // --use_staging
	Identity         string   // --identity (required)
	IdentityProvider string   // --identity_provider (required)
}

func New() *cobra.Command {
	o := &options{
		IgnoreGitPaths: true,
	}

	long := `Verify using Sigstore (DEFAULT verification method).

Verifies the integrity of model at MODEL_PATH, according to signature from
SIGNATURE_PATH (given via --signature option). Files in IGNORE_PATHS are ignored.

For Sigstore, we also need to provide an expected identity and identity
provider for the signature. If these don't match what is provided in the
signature, verification would fail.`

	cmd := &cobra.Command{
		Use:   "sigstore [OPTIONS]",
		Short: "Verify using Sigstore (DEFAULT verification method).",
		Long:  long,
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			v := &SigstoreCommand{
				SignaturePath:    o.SignaturePath,
				IgnorePaths:      o.IgnorePaths,
				IgnoreGitPaths:   o.IgnoreGitPaths,
				UseStaging:       o.UseStaging,
				Identity:         o.Identity,
				IdentityProvider: o.IdentityProvider,
			}

			ctx, cancel := context.WithTimeout(cmd.Context(), 2*time.Minute)
			defer cancel()

			return v.Exec(ctx, "")
		},
	}

	// Flags — only on this subcommand.
	cmd.Flags().StringVar(&o.SignaturePath, "signature", "", "Location of the signature file to verify.")
	_ = cmd.MarkFlagRequired("signature")

	cmd.Flags().StringSliceVar(&o.IgnorePaths, "ignore-paths", nil, "File paths to ignore when signing or verifying.")
	cmd.Flags().BoolVar(&o.IgnoreGitPaths, "ignore-git-paths", true, "Ignore git-related files when signing or verifying.")
	// Users can pass --ignore-git-paths=false. If you also want an explicit --no-ignore-git-paths alias:
	// cmd.Flags().Bool("no-ignore-git-paths", false, "Do not ignore git-related files (alias for --ignore-git-paths=false)")

	cmd.Flags().BoolVar(&o.UseStaging, "use_staging", false, "Use Sigstore's staging instance.")
	cmd.Flags().StringVar(&o.Identity, "identity", "", "The expected identity of the signer (e.g., name@example.com).")
	_ = cmd.MarkFlagRequired("identity")
	cmd.Flags().StringVar(&o.IdentityProvider, "identity_provider", "", "The expected identity provider (e.g., https://accounts.example.com).")
	_ = cmd.MarkFlagRequired("identity_provider")

	return cmd
}
