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

// CommonModelFlags contains flags shared by all signing and verification commands
type CommonModelFlags struct {
	SignaturePath  string   // --signature SIGNATURE_PATH (required)
	IgnorePaths    []string // --ignore-paths
	IgnoreGitPaths bool     // --ignore-git-paths (default true; users can pass --ignore-git-paths=false)
	AllowSymlinks  bool     // --allow-symlinks
}

// AddFlags adds common model flags to the cobra command
func (o *CommonModelFlags) AddFlags(cmd *cobra.Command, signatureFlagHelp string) {
	cmd.Flags().StringVar(&o.SignaturePath, "signature", "", signatureFlagHelp)
	_ = cmd.MarkFlagRequired("signature")
	cmd.Flags().StringSliceVar(&o.IgnorePaths, "ignore-paths", nil, "File paths to ignore when signing or verifying.")
	cmd.Flags().BoolVar(&o.IgnoreGitPaths, "ignore-git-paths", true, "Ignore git-related files when signing or verifying.")
	cmd.Flags().BoolVar(&o.AllowSymlinks, "allow-symlinks", false, "Allow following symbolic links in model directory.")
}

// CommonVerifyFlags contains flags shared by all verification commands
type CommonVerifyFlags struct {
	IgnoreUnsignedFiles bool // --ignore-unsigned-files
}

// AddFlags adds common verification flags to the cobra command
func (o *CommonVerifyFlags) AddFlags(cmd *cobra.Command) {
	cmd.Flags().BoolVar(&o.IgnoreUnsignedFiles, "ignore-unsigned-files", true, "Ignore files in model that are not in signature.")
}
