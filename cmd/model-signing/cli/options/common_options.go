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

// CommonModelFlags contains flags shared by all signing and verification commands.
// These flags control model path handling, signature location, and file filtering.
type CommonModelFlags struct {
	// SignaturePath specifies the location of the signature file.
	SignaturePath string
	// IgnorePaths lists file paths to exclude from signing or verification.
	IgnorePaths []string
	// IgnoreGitPaths controls whether git-related files are automatically excluded.
	IgnoreGitPaths bool
	// AllowSymlinks determines whether symbolic links should be followed.
	AllowSymlinks bool
}

// AddFlagsForSigning adds common model flags for signing commands.
// The signature flag defaults to "model.sig" and is not required.
func (o *CommonModelFlags) AddFlagsForSigning(cmd *cobra.Command) {
	cmd.Flags().StringVar(&o.SignaturePath, "signature", "model.sig", "Location of the signature file to generate. Defaults to model.sig")
	cmd.Flags().StringSliceVar(&o.IgnorePaths, "ignore-paths", nil, "File paths to ignore when signing or verifying.")
	cmd.Flags().BoolVar(&o.IgnoreGitPaths, "ignore-git-paths", true, "Ignore git-related files when signing or verifying. [default: true]")
	cmd.Flags().BoolVar(&o.AllowSymlinks, "allow-symlinks", false, "Whether to allow following symlinks when signing or verifying files.")
}

// AddFlagsForVerify adds common model flags for verification commands.
// The signature flag is required for verification operations.
func (o *CommonModelFlags) AddFlagsForVerify(cmd *cobra.Command) {
	cmd.Flags().StringVar(&o.SignaturePath, "signature", "", "Location of the signature file to verify. [required]")
	_ = cmd.MarkFlagRequired("signature")
	cmd.Flags().StringSliceVar(&o.IgnorePaths, "ignore-paths", nil, "File paths to ignore when signing or verifying.")
	cmd.Flags().BoolVar(&o.IgnoreGitPaths, "ignore-git-paths", true, "Ignore git-related files when signing or verifying. [default: true]")
	cmd.Flags().BoolVar(&o.AllowSymlinks, "allow-symlinks", false, "Whether to allow following symlinks when signing or verifying files.")
}

// CommonVerifyFlags contains flags shared by all verification commands.
// These flags control verification behavior for unsigned files.
type CommonVerifyFlags struct {
	// IgnoreUnsignedFiles determines whether files present in the model
	// but not in the signature should be ignored or cause verification to fail.
	IgnoreUnsignedFiles bool
}

// AddFlags adds common verification flags to the cobra command.
// This includes the flag for handling unsigned files during verification.
func (o *CommonVerifyFlags) AddFlags(cmd *cobra.Command) {
	cmd.Flags().BoolVar(&o.IgnoreUnsignedFiles, "ignore-unsigned-files", true, "Ignore files in model that are not in signature.")
}
