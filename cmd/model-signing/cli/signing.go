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

package cli

import (
	"context"
	"fmt"
	"time"

	"github.com/spf13/cobra"

	"github.com/sigstore/model-signing/cmd/model-signing/cli/options"
	key "github.com/sigstore/model-signing/pkg/signing/key"
	sigstore "github.com/sigstore/model-signing/pkg/signing/sigstore"
)

func NewSigstoreSign() *cobra.Command {
	o := &options.SigstoreSignOptions{}

	long := `Sign using Sigstore (DEFAULT signing method).

Signs the of model at MODEL_PATH and stores the signature to
SIGNATURE_PATH (given via --signature option). Files in IGNORE_PATHS are ignored.

If using Sigstore, we need to provision an OIDC token. In general, this is
taken from an interactive OIDC flow, but ambient credentials could be used
to use workload identity tokens (e.g., when running in GitHub actions).
Alternatively, a constant identity token can be provided via
--identity-token.

Sigstore allows users to use a staging instance for test-only signatures.
Passing the --use-staging flag would use that instance instead of the
production one.`

	cmd := &cobra.Command{
		Use:   "sigstore [OPTIONS] MODEL_PATH",
		Short: "Sign using Sigstore (DEFAULT signing method).",
		Long:  long,
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			modelPath := args[0]

			opts := sigstore.SigstoreSignerOptions{
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

			signer, err := sigstore.NewSigstoreSigner(opts)
			if err != nil {
				return err
			}

			ctx, cancel := context.WithTimeout(cmd.Context(), 2*time.Minute)
			defer cancel()

			status, err := signer.Sign(ctx)
			fmt.Println("Signing Status: ", status)
			return err
		},
	}

	o.AddFlags(cmd)
	return cmd
}

func NewKeySigner() *cobra.Command {
	o := &options.KeySignOptions{}

	long := `Sign using a private key (paired with a public one).

    Signing the model at MODEL_PATH_OR_MANIFEST, produces the signature at
    SIGNATURE_PATH (as per --signature option). Files in IGNORE_PATHS are not
    part of the signature.

    Traditionally, signing could be achieved by using a public/private key pair.
    Pass the signing key using --private-key.

    Note that this method does not provide a way to tie to the identity of the
    signer, outside of pairing the keys. Also note that we don't offer key
    management protocols.`

	cmd := &cobra.Command{
		Use:   "key [OPTIONS] MODEL_PATH",
		Short: "Sign using Key.",
		Long:  long,
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			modelPath := args[0]

			opts := key.KeySignerOptions{
				ModelPath:      modelPath,
				SignaturePath:  o.SignaturePath,
				IgnorePaths:    o.IgnorePaths,
				IgnoreGitPaths: o.IgnoreGitPaths,
				AllowSymlinks:  o.AllowSymlinks,
				PrivateKeyPath: o.PrivateKeyPath,
				Password:       o.Password,
			}

			signer, err := key.NewKeySigner(opts)
			if err != nil {
				return err
			}

			ctx, cancel := context.WithTimeout(cmd.Context(), 2*time.Minute)
			defer cancel()

			status, err := signer.Sign(ctx)
			fmt.Println("Signing Status: ", status)
			return err
		},
	}

	o.AddFlags(cmd)
	return cmd
}

func NewCertificateSigner() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "certificate",
		Short: "Sign using a certificate (not yet implemented).",
		Long: `Sign model signatures using certificate-based verification.
For more information, see: https://github.com/sigstore/model-signing`,
		//nolint:revive
		RunE: func(cmd *cobra.Command, args []string) error {
			return fmt.Errorf("certificate verification is not yet implemented\n\nPlease use 'sigstore' verification instead")
		},
	}
	return cmd
}

func Sign() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "sign [OPTIONS] PKI_METHOD",
		Short: "Sign models.",
		Long: `Sign models.

    Signing the model at MODEL_PATH, produces the signature at SIGNATURE_PATH
    (as per --signature option). Files in IGNORE_PATHS are not part of the
    signature.

    If using Sigstore, we need to provision an OIDC token. In general, this is
    taken from an interactive OIDC flow, but ambient credentials could be used
    to use workload identity tokens (e.g., when running in GitHub actions).
    Alternatively, a constant identity token can be provided via
    --identity-token.

    Sigstore allows users to use a staging instance for test-only signatures.
    Passing the --use-staging flag would use that instance instead of the
    production one.

    Additionally, you can specify a custom trust configuration JSON file using
    the --trust-config flag. This allows you to fully customize the PKI
    (Private Key Infrastructure) used in the signing process. By providing a
    --trust-config, you can define your own transparency logs, certificate
    authorities, and other trust settings, enabling full control over the
    trust model, including which PKI to use for signature verification.
    If --trust-config is not provided, the default Sigstore instance is
    used, which is pre-configured with Sigstore’s own trusted transparency
    logs and certificate authorities. This provides a ready-to-use default
    trust model for most use cases but may not be suitable for custom or
    highly regulated environments.`,
		DisableFlagParsing: true,
		Args:               cobra.ArbitraryArgs,
		RunE: func(parent *cobra.Command, args []string) error {
			sigCmd := NewSigstoreSign()
			sigCmd.SilenceUsage = parent.SilenceUsage
			sigCmd.SilenceErrors = parent.SilenceErrors

			sigCmd.SetArgs(args)
			return sigCmd.ExecuteContext(parent.Context())
		},
	}

	// Add PKI subcommands. Each owns its own flags.
	cmd.AddCommand(NewSigstoreSign())    // full implementation
	cmd.AddCommand(NewKeySigner())         // full implementation
	cmd.AddCommand(NewCertificateSigner()) // stub for now

	return cmd
}
