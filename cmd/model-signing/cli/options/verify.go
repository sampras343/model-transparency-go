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
	"github.com/spf13/cobra"
)

type SigstoreVerifyOptions struct {
	SignaturePath       string   // --signature SIGNATURE_PATH (required)
	IgnorePaths         []string // --ignore-paths
	IgnoreGitPaths      bool     // --ignore-git-paths (default true; users can pass --ignore-git-paths=false)
	AllowSymlinks       bool     // --allow-symlinks
	UseStaging          bool     // --use-staging
	Identity            string   // --identity (required)
	IdentityProvider    string   // --identity_provider (required)
	TrustConfigPath     string   // --trust-config
	IgnoreUnsignedFiles bool     // --ignore-unsigned-files
}

func (o *SigstoreVerifyOptions) AddFlags(cmd *cobra.Command) {
	cmd.Flags().StringVar(&o.SignaturePath, "signature", "", "Location of the signature file to verify.")
	_ = cmd.MarkFlagRequired("signature")

	cmd.Flags().StringSliceVar(&o.IgnorePaths, "ignore-paths", nil, "File paths to ignore when signing or verifying.")
	cmd.Flags().BoolVar(&o.IgnoreGitPaths, "ignore-git-paths", true, "Ignore git-related files when signing or verifying.")
	cmd.Flags().BoolVar(&o.AllowSymlinks, "allow-symlinks", false, "Allow following symbolic links in model directory.")

	cmd.Flags().BoolVar(&o.UseStaging, "use-staging", false, "Use Sigstore's staging instance.")
	cmd.Flags().StringVar(&o.Identity, "identity", "", "The expected identity of the signer (e.g., name@example.com).")
	_ = cmd.MarkFlagRequired("identity")
	cmd.Flags().StringVar(&o.IdentityProvider, "identity_provider", "", "The expected identity provider (e.g., https://accounts.example.com).")
	_ = cmd.MarkFlagRequired("identity_provider")

	cmd.Flags().StringVar(&o.TrustConfigPath, "trust-config", "", "Path to custom trust root JSON file.")
	cmd.Flags().BoolVar(&o.IgnoreUnsignedFiles, "ignore-unsigned-files", true, "Ignore files in model that are not in signature.")
}
