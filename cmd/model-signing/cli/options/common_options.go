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

// FlagAdder is implemented by any flag group that can register itself to a cobra command.
type FlagAdder interface {
	AddFlags(cmd *cobra.Command)
}

// ModelPathFlags contains flags for controlling which files are included in signing/verification.
// These flags are shared by all signing and verification commands.
type ModelPathFlags struct {
	// IgnorePaths lists file paths to exclude from signing or verification.
	IgnorePaths []string
	// IgnoreGitPaths controls whether git-related files are automatically excluded.
	IgnoreGitPaths bool
	// AllowSymlinks determines whether symbolic links should be followed.
	AllowSymlinks bool
}

// AddFlags adds model path flags to the cobra command.
func (o *ModelPathFlags) AddFlags(cmd *cobra.Command) {
	cmd.Flags().StringSliceVar(&o.IgnorePaths, "ignore-paths", nil, "File paths to ignore when signing or verifying.")
	cmd.Flags().BoolVar(&o.IgnoreGitPaths, "ignore-git-paths", true, "Ignore git-related files when signing or verifying. [default: true]")
	cmd.Flags().BoolVar(&o.AllowSymlinks, "allow-symlinks", false, "Whether to allow following symlinks when signing or verifying files.")
}

// SignatureOutputFlags contains the signature path flag for signing commands.
// The signature flag defaults to "model.sig" and is not required.
type SignatureOutputFlags struct {
	// SignaturePath specifies the location of the signature file to generate.
	SignaturePath string
}

// AddFlags adds signature output flags for signing commands.
func (o *SignatureOutputFlags) AddFlags(cmd *cobra.Command) {
	cmd.Flags().StringVar(&o.SignaturePath, "signature", "model.sig", "Location of the signature file to generate. Defaults to model.sig")
}

// SignatureInputFlags contains the signature path flag for verification commands.
// The signature flag is required for verification operations.
type SignatureInputFlags struct {
	// SignaturePath specifies the location of the signature file to verify.
	SignaturePath string
}

// AddFlags adds signature input flags for verification commands.
func (o *SignatureInputFlags) AddFlags(cmd *cobra.Command) {
	cmd.Flags().StringVar(&o.SignaturePath, "signature", "", "Location of the signature file to verify. [required]")
	_ = cmd.MarkFlagRequired("signature")
}

// SigstoreFlags contains flags shared between Sigstore signing and verification commands.
type SigstoreFlags struct {
	// UseStaging specifies whether to use Sigstore's staging environment.
	UseStaging bool
	// TrustConfigPath provides a path to a custom trust configuration file.
	TrustConfigPath string
}

// AddFlags adds Sigstore common flags to the cobra command.
func (o *SigstoreFlags) AddFlags(cmd *cobra.Command) {
	cmd.Flags().BoolVar(&o.UseStaging, "use-staging", false, "Use Sigstore's staging instance.")
	cmd.Flags().StringVar(&o.TrustConfigPath, "trust-config", "", "Path to trust configuration file.")
}

// IgnoreUnsignedFlags contains flags shared by all verification commands.
// These flags control verification behavior for unsigned files.
type IgnoreUnsignedFlags struct {
	// IgnoreUnsignedFiles determines whether files present in the model
	// but not in the signature should be ignored or cause verification to fail.
	IgnoreUnsignedFiles bool
}

// AddFlags adds common verification flags to the cobra command.
// This includes the flag for handling unsigned files during verification.
func (o *IgnoreUnsignedFlags) AddFlags(cmd *cobra.Command) {
	cmd.Flags().BoolVar(&o.IgnoreUnsignedFiles, "ignore-unsigned-files", true, "Ignore files in model that are not in signature.")
}

// AddAllFlags is a helper function to register multiple flag groups at once.
func AddAllFlags(cmd *cobra.Command, flagGroups ...FlagAdder) {
	for _, fg := range flagGroups {
		fg.AddFlags(cmd)
	}
}
