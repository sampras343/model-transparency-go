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

	key "github.com/sigstore/model-signing/pkg/verify/key"
	sigstore "github.com/sigstore/model-signing/pkg/verify/sigstore"
)

type SigstoreVerifyOptions struct {
	CommonModelFlags
	CommonVerifyFlags
	UseStaging       bool   // --use-staging
	Identity         string // --identity (required)
	IdentityProvider string // --identity-provider (required)
	TrustConfigPath  string // --trust-config
}

func (o *SigstoreVerifyOptions) AddFlags(cmd *cobra.Command) {
	o.CommonModelFlags.AddFlagsForVerify(cmd)
	o.CommonVerifyFlags.AddFlags(cmd)

	cmd.Flags().BoolVar(&o.UseStaging, "use-staging", false, "Use Sigstore's staging instance.")
	cmd.Flags().StringVar(&o.Identity, "identity", "", "The expected identity of the signer (e.g., name@example.com).")
	_ = cmd.MarkFlagRequired("identity")
	cmd.Flags().StringVar(&o.IdentityProvider, "identity-provider", "", "The expected identity provider (e.g., https://accounts.example.com).")
	_ = cmd.MarkFlagRequired("identity-provider")
	cmd.Flags().StringVar(&o.TrustConfigPath, "trust-config", "", "Path to custom trust root JSON file.")
}

type KeyVerifyOptions struct {
	CommonModelFlags
	CommonVerifyFlags
	PublicKeyPath string // --public-key PUBLIC_KEY (required)
}

func (o *KeyVerifyOptions) AddFlags(cmd *cobra.Command) {
	o.CommonModelFlags.AddFlagsForVerify(cmd)
	o.CommonVerifyFlags.AddFlags(cmd)

	cmd.Flags().StringVar(&o.PublicKeyPath, "public-key", "", "Location of the public key file to verify.")
	_ = cmd.MarkFlagRequired("public-key")
}

type CertificateVerifyOptions struct {
	CommonModelFlags
	CommonVerifyFlags
	CertificateChain []string // --certificate-chain
	LogFingerprints  bool     // --log-fingerprints
}

func (o *CertificateVerifyOptions) AddFlags(cmd *cobra.Command) {
	o.CommonModelFlags.AddFlagsForVerify(cmd)
	o.CommonVerifyFlags.AddFlags(cmd)

	cmd.Flags().BoolVar(&o.LogFingerprints, "log-fingerprints", true, "Ignore files in model that are not in signature.")
	cmd.Flags().StringSliceVar(&o.CertificateChain, "certificate-chain", nil, "File paths of certificate chain of trust")
}

// ToStandardOptions converts CLI options to library options for Sigstore verification
func (o *SigstoreVerifyOptions) ToStandardOptions(modelPath string) sigstore.SigstoreVerifierOptions {
	return sigstore.SigstoreVerifierOptions{
		ModelPath:           modelPath,
		SignaturePath:       o.SignaturePath,
		IgnorePaths:         o.IgnorePaths,
		IgnoreGitPaths:      o.IgnoreGitPaths,
		AllowSymlinks:       o.AllowSymlinks,
		UseStaging:          o.UseStaging,
		Identity:            o.Identity,
		IdentityProvider:    o.IdentityProvider,
		TrustConfigPath:     o.TrustConfigPath,
		IgnoreUnsignedFiles: o.IgnoreUnsignedFiles,
	}
}

// ToStandardOptions converts CLI options to library options for key-based verification
func (o *KeyVerifyOptions) ToStandardOptions(modelPath string) key.KeyVerifierOptions {
	return key.KeyVerifierOptions{
		ModelPath:           modelPath,
		SignaturePath:       o.SignaturePath,
		IgnorePaths:         o.IgnorePaths,
		IgnoreGitPaths:      o.IgnoreGitPaths,
		AllowSymlinks:       o.AllowSymlinks,
		PublicKeyPath:       o.PublicKeyPath,
		IgnoreUnsignedFiles: o.IgnoreUnsignedFiles,
	}
}
