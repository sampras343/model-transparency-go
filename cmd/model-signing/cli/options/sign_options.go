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

	key "github.com/sigstore/model-signing/pkg/signing/key"
	sigstore "github.com/sigstore/model-signing/pkg/signing/sigstore"
)

type SigstoreSignOptions struct {
	CommonModelFlags
	UseStaging            bool   // --use-staging
	OAuthForceOob         bool   // --oauth-force-oob
	UseAmbientCredentials bool   // --use-ambient-credentials
	IdentityToken         string // --identity-token
	ClientID              string // --client-id
	ClientSecret          string // --client-secret
	TrustConfigPath       string // --trust-config
}

func (o *SigstoreSignOptions) AddFlags(cmd *cobra.Command) {
	o.CommonModelFlags.AddFlags(cmd, "Location of the signature file to generate. Defaults to model.sig")

	cmd.Flags().BoolVar(&o.UseStaging, "use-staging", false, "Use Sigstore's staging instance.")
	cmd.Flags().BoolVar(&o.OAuthForceOob, "oauth-force-oob", false, "Force an out-of-band OAuth flow and do not automatically start the default web browser.")
	cmd.Flags().BoolVar(&o.UseAmbientCredentials, "use-ambient-credentials", false, "Use credentials from ambient environment.")
	cmd.Flags().StringVar(&o.IdentityToken, "identity-token", "", "Fixed OIDC identity token to use instead of obtaining credentials from OIDC flow or from the environment.")
	cmd.Flags().StringVar(&o.ClientID, "client-id", "", "The custom OpenID Connect client ID to use during OAuth2.")
	cmd.Flags().StringVar(&o.ClientSecret, "client-secret", "", "The custom OpenID Connect client secret to use during OAuth2.")
	cmd.Flags().StringVar(&o.TrustConfigPath, "trust-config", "", "The client trust configuration to use.")
}

type KeySignOptions struct {
	CommonModelFlags
	Password       string // --password
	PrivateKeyPath string // --private-key PRIVATE_KEY (required)
}

func (o *KeySignOptions) AddFlags(cmd *cobra.Command) {
	o.CommonModelFlags.AddFlags(cmd, "Location of the signature file to generate. Defaults to model.sig")

	cmd.Flags().StringVar(&o.PrivateKeyPath, "private-key", "", "Path to the private key, as a PEM-encoded file. [required]")
	_ = cmd.MarkFlagRequired("private-key")
	cmd.Flags().StringVar(&o.Password, "password", "", "Password for the key encryption, if any.")
}

// ToStandardOptions converts CLI options to library options for Sigstore signing
func (o *SigstoreSignOptions) ToStandardOptions(modelPath string) sigstore.SigstoreSignerOptions {
	return sigstore.SigstoreSignerOptions{
		ModelPath:             modelPath,
		SignaturePath:         o.SignaturePath,
		IgnorePaths:           o.IgnorePaths,
		IgnoreGitPaths:        o.IgnoreGitPaths,
		AllowSymlinks:         o.AllowSymlinks,
		UseStaging:            o.UseStaging,
		OAuthForceOob:         o.OAuthForceOob,
		UseAmbientCredentials: o.UseAmbientCredentials,
		IdentityToken:         o.IdentityToken,
		ClientID:              o.ClientID,
		ClientSecret:          o.ClientSecret,
		TrustConfigPath:       o.TrustConfigPath,
	}
}

// ToStandardOptions converts CLI options to library options for key-based signing
func (o *KeySignOptions) ToStandardOptions(modelPath string) key.KeySignerOptions {
	return key.KeySignerOptions{
		ModelPath:      modelPath,
		SignaturePath:  o.SignaturePath,
		IgnorePaths:    o.IgnorePaths,
		IgnoreGitPaths: o.IgnoreGitPaths,
		AllowSymlinks:  o.AllowSymlinks,
		PrivateKeyPath: o.PrivateKeyPath,
		Password:       o.Password,
	}
}
