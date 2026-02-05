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
	"github.com/sigstore/model-signing/pkg/logging"
	cert "github.com/sigstore/model-signing/pkg/signing/certificate"
	key "github.com/sigstore/model-signing/pkg/signing/key"
	sigstore "github.com/sigstore/model-signing/pkg/signing/sigstore"
)

// NewSigstoreSign creates the sigstore subcommand for model signing.
// This command signs models using Sigstore's keyless signing infrastructure
// with OIDC-based identity verification.
//
// Returns a *cobra.Command configured for Sigstore-based signing.
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

			// Convert CLI options to library options
			opts := o.ToStandardOptions(modelPath)
			// Pass logger from root options
			opts.Logger = ro.NewLogger()

			signer, err := sigstore.NewSigstoreSigner(opts)
			if err != nil {
				return err
			}

			ctx, cancel := context.WithTimeout(cmd.Context(), 2*time.Minute)
			defer cancel()

			status, err := signer.Sign(ctx)
			if ro.GetLogLevel() > logging.LevelDebug {
				fmt.Println(status.Message)
			}
			return err
		},
	}

	o.AddFlags(cmd)
	return cmd
}

// NewKeySigner creates the key subcommand for model signing.
// This command signs models using a traditional public/private key pair
// without identity verification or key management.
//
// Returns a *cobra.Command configured for key-based signing.
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

			// Convert CLI options to library options
			opts := o.ToStandardOptions(modelPath)
			// Pass logger from root options
			opts.Logger = ro.NewLogger()

			signer, err := key.NewKeySigner(opts)
			if err != nil {
				return err
			}

			ctx, cancel := context.WithTimeout(cmd.Context(), 2*time.Minute)
			defer cancel()

			status, err := signer.Sign(ctx)
			if ro.GetLogLevel() > logging.LevelDebug {
				fmt.Println(status.Message)
			}
			return err
		},
	}

	o.AddFlags(cmd)
	return cmd
}

// NewCertificateSigner creates the certificate subcommand for model signing.
// This command signs models using a certificate and private key pair,
// providing identity information through the certificate chain.
//
// Returns a *cobra.Command configured for certificate-based signing.
func NewCertificateSigner() *cobra.Command {
	o := &options.CertificateSignOptions{}

	long := `Sign using a certificate.

    Signing the model at MODEL_PATH_OR_MANIFEST, produces the signature at
    SIGNATURE_PATH (as per --signature option). Files in IGNORE_PATHS are not
    part of the signature.

    Traditionally, signing can be achieved by using keys from a certificate.
    The certificate can also provide the identity of the signer, making this
    method more informative than just using a public/private key pair for
    signing.  Pass the private signing key using --private-key and signing
    certificate via --signing-certificate. Optionally, pass a certificate
    chain via --certificate-chain to establish root of trust (this option can
    be repeated as needed, or all certificates could be placed in a single file).

    Note that we don't offer certificate and key management protocols.`

	cmd := &cobra.Command{
		Use:   "certificate [OPTIONS] MODEL_PATH",
		Short: "Sign using Certificate.",
		Long:  long,
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			modelPath := args[0]

			// Convert CLI options to library options
			opts := o.ToStandardOptions(modelPath)
			// Pass logger from root options
			opts.Logger = ro.NewLogger()

			signer, err := cert.NewCertificateSigner(opts)
			if err != nil {
				return err
			}

			ctx, cancel := context.WithTimeout(cmd.Context(), 2*time.Minute)
			defer cancel()

			status, err := signer.Sign(ctx)
			if ro.GetLogLevel() > logging.LevelDebug {
				fmt.Println(status.Message)
			}
			return err
		},
	}

	o.AddFlags(cmd)
	return cmd
}

// Sign creates the sign command with all PKI method subcommands.
// It serves as the parent command for different signing methods (sigstore, key, certificate)
// and defaults to Sigstore signing when no subcommand is specified.
//
// Returns a *cobra.Command with all signing subcommands registered.
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
		Args: cobra.ArbitraryArgs,
		RunE: func(parent *cobra.Command, args []string) error {
			sigCmd := NewSigstoreSign()
			sigCmd.SilenceUsage = parent.SilenceUsage
			sigCmd.SilenceErrors = parent.SilenceErrors

			sigCmd.SetArgs(args)
			return sigCmd.ExecuteContext(parent.Context())
		},
	}

	// Add PKI subcommands. Each owns its own flags.
	cmd.AddCommand(NewSigstoreSign())
	cmd.AddCommand(NewKeySigner())
	cmd.AddCommand(NewCertificateSigner())

	return cmd
}
