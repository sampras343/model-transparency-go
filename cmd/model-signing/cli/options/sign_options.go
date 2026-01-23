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

// SigstoreSignOptions holds the command-line options for Sigstore-based signing.
// It embeds CommonModelFlags and adds Sigstore-specific configuration options.
type SigstoreSignOptions struct {
	CommonModelFlags
	// UseStaging specifies whether to use Sigstore's staging environment.
	UseStaging bool
	// OAuthForceOob forces an out-of-band OAuth flow without opening a browser.
	OAuthForceOob bool
	// UseAmbientCredentials enables using credentials from the ambient environment.
	UseAmbientCredentials bool
	// IdentityToken provides a fixed OIDC identity token instead of obtaining one via OIDC flow.
	IdentityToken string
	// ClientID specifies a custom OpenID Connect client ID for OAuth2.
	ClientID string
	// ClientSecret specifies a custom OpenID Connect client secret for OAuth2.
	ClientSecret string
	// TrustConfigPath provides a path to a custom client trust configuration file.
	TrustConfigPath string
}

// AddFlags adds Sigstore signing flags to the cobra command.
// This includes both common model flags and Sigstore-specific options.
func (o *SigstoreSignOptions) AddFlags(cmd *cobra.Command) {
	o.AddFlagsForSigning(cmd)

	cmd.Flags().BoolVar(&o.UseStaging, "use-staging", false, "Use Sigstore's staging instance.")
	cmd.Flags().BoolVar(&o.OAuthForceOob, "oauth-force-oob", false, "Force an out-of-band OAuth flow and do not automatically start the default web browser.")
	cmd.Flags().BoolVar(&o.UseAmbientCredentials, "use-ambient-credentials", false, "Use credentials from ambient environment.")
	cmd.Flags().StringVar(&o.IdentityToken, "identity-token", "", "Fixed OIDC identity token to use instead of obtaining credentials from OIDC flow or from the environment.")
	cmd.Flags().StringVar(&o.ClientID, "client-id", "", "The custom OpenID Connect client ID to use during OAuth2.")
	cmd.Flags().StringVar(&o.ClientSecret, "client-secret", "", "The custom OpenID Connect client secret to use during OAuth2.")
	cmd.Flags().StringVar(&o.TrustConfigPath, "trust-config", "", "The client trust configuration to use.")
}

// KeySignOptions holds the command-line options for key-based signing.
// It embeds CommonModelFlags and adds key-specific configuration options.
type KeySignOptions struct {
	CommonModelFlags
	// Password specifies the password for encrypted private keys.
	Password string
	// PrivateKeyPath provides the path to the PEM-encoded private key file.
	PrivateKeyPath string
}

// AddFlags adds key-based signing flags to the cobra command.
// This includes both common model flags and key-specific options.
// The private-key flag is marked as required.
func (o *KeySignOptions) AddFlags(cmd *cobra.Command) {
	o.AddFlagsForSigning(cmd)

	cmd.Flags().StringVar(&o.PrivateKeyPath, "private-key", "", "Path to the private key, as a PEM-encoded file. [required]")
	_ = cmd.MarkFlagRequired("private-key")
	cmd.Flags().StringVar(&o.Password, "password", "", "Password for the key encryption, if any.")
}

// ToStandardOptions converts CLI options to library options for Sigstore signing.
// It maps command-line flags to the standard SigstoreSignerOptions structure
// used by the signing library.
//
// The modelPath parameter specifies the path to the model to be signed.
// Returns a SigstoreSignerOptions struct with all fields populated from CLI flags.
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

// ToStandardOptions converts CLI options to library options for key-based signing.
// It maps command-line flags to the standard KeySignerOptions structure
// used by the signing library.
//
// The modelPath parameter specifies the path to the model to be signed.
// Returns a KeySignerOptions struct with all fields populated from CLI flags.
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
