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
	pkcs11 "github.com/sigstore/model-signing/pkg/signing/pkcs11"
	sigstore "github.com/sigstore/model-signing/pkg/signing/sigstore"
	"github.com/sigstore/model-signing/pkg/tracing"
)

// runSigstoreSign performs Sigstore-based model signing with tracing.
// Shared by NewSigstoreSign (explicit subcommand) and Sign (default).
func runSigstoreSign(ctx context.Context, o *options.SigstoreSignOptions, modelPath string) error {
	opts := o.ToStandardOptions(modelPath)
	opts.Logger = ro.NewObservability().Logger
	attrs := map[string]interface{}{
		"model_signing.method":                  "sigstore",
		"model_signing.model_path":              modelPath,
		"model_signing.signature":               opts.SignaturePath,
		"model_signing.use_staging":             opts.UseStaging,
		"model_signing.use_ambient_credentials": opts.UseAmbientCredentials,
		"model_signing.allow_symlinks":          opts.AllowSymlinks,
		"model_signing.ignore_git_paths":        opts.IgnoreGitPaths,
	}
	return tracing.Run(ctx, "Sign", attrs, func(ctx context.Context) error {
		signer, err := sigstore.NewSigstoreSigner(opts)
		if err != nil {
			return err
		}
		ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
		defer cancel()
		status, err := signer.Sign(ctx)
		if ro.GetLogLevel() < logging.LevelSilent {
			fmt.Println(status.Message)
		}
		return err
	})
}

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
			return runSigstoreSign(cmd.Context(), o, args[0])
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
			opts := o.ToStandardOptions(modelPath)
			opts.Logger = ro.NewObservability().Logger
			attrs := map[string]interface{}{
				"model_signing.method":           "key",
				"model_signing.model_path":       modelPath,
				"model_signing.allow_symlinks":   opts.AllowSymlinks,
				"model_signing.ignore_git_paths": opts.IgnoreGitPaths,
			}
			return tracing.Run(cmd.Context(), "Sign", attrs, func(ctx context.Context) error {
				signer, err := key.NewKeySigner(opts)
				if err != nil {
					return err
				}
				ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
				defer cancel()
				status, err := signer.Sign(ctx)
				if ro.GetLogLevel() < logging.LevelSilent {
					fmt.Println(status.Message)
				}
				return err
			})
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
			opts := o.ToStandardOptions(modelPath)
			opts.Logger = ro.NewObservability().Logger
			attrs := map[string]interface{}{
				"model_signing.method":           "certificate",
				"model_signing.model_path":       modelPath,
				"model_signing.allow_symlinks":   opts.AllowSymlinks,
				"model_signing.ignore_git_paths": opts.IgnoreGitPaths,
			}
			return tracing.Run(cmd.Context(), "Sign", attrs, func(ctx context.Context) error {
				signer, err := cert.NewCertificateSigner(opts)
				if err != nil {
					return err
				}
				ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
				defer cancel()
				status, err := signer.Sign(ctx)
				if ro.GetLogLevel() < logging.LevelSilent {
					fmt.Println(status.Message)
				}
				return err
			})
		},
	}

	o.AddFlags(cmd)
	return cmd
}

// NewPkcs11KeySigner creates the pkcs11-key subcommand for model signing.
// This command signs models using a PKCS#11 private key.
//
// Returns a *cobra.Command configured for PKCS#11 key-based signing.
func NewPkcs11KeySigner() *cobra.Command {
	o := &options.Pkcs11SignOptions{}

	long := `Sign using a private key using a PKCS #11 URI.

    Signing the model at MODEL_PATH, produces the signature at SIGNATURE_PATH
    (as per --signature option). Files in IGNORE_PATHS are not part of the
    signature.

    Traditionally, signing could be achieved by using a public/private key pair.
    Pass the PKCS #11 URI of the signing key using --pkcs11-uri.

    The PKCS#11 URI format follows RFC 7512:
      pkcs11:token=TOKEN;object=KEY?module-name=MODULE&pin-value=PIN

    Note that this method does not provide a way to tie to the identity of the
    signer, outside of pairing the keys. Also note that we don't offer key
    management protocols.`

	cmd := &cobra.Command{
		Use:   "pkcs11-key [OPTIONS] MODEL_PATH",
		Short: "Sign using a private key using a PKCS #11 URI.",
		Long:  long,
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			modelPath := args[0]

			// Convert CLI options to library options
			opts := o.ToStandardOptions(modelPath)
			// Pass logger from root options
			opts.Logger = ro.NewLogger()

			// Ensure no certificate is provided for key-based signing
			if opts.SigningCertificatePath != "" {
				return fmt.Errorf("--signing-certificate should not be used with pkcs11-key, use pkcs11-certificate instead")
			}

			signer, err := pkcs11.NewPkcs11Signer(opts)
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

// NewPkcs11CertificateSigner creates the pkcs11-certificate subcommand for model signing.
// This command signs models using a certificate with PKCS#11.
//
// Returns a *cobra.Command configured for PKCS#11 certificate-based signing.
func NewPkcs11CertificateSigner() *cobra.Command {
	o := &options.Pkcs11SignOptions{}

	long := `Sign using a certificate.

    Signing the model at MODEL_PATH, produces the signature at SIGNATURE_PATH
    (as per --signature option). Files in IGNORE_PATHS are not part of the
    signature.

    Sign using a certificate with a PKCS #11 URI. This is similar to
    certificate-based signing, but the private key is accessed via PKCS #11.

    Pass the PKCS #11 URI of the signing key using --pkcs11-uri, the signing
    certificate using --signing-certificate, and optionally the certificate
    chain using --certificate-chain.

    The PKCS#11 URI format follows RFC 7512:
      pkcs11:token=TOKEN;object=KEY?module-name=MODULE&pin-value=PIN`

	cmd := &cobra.Command{
		Use:   "pkcs11-certificate [OPTIONS] MODEL_PATH",
		Short: "Sign using a certificate.",
		Long:  long,
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			modelPath := args[0]

			// Convert CLI options to library options
			opts := o.ToStandardOptions(modelPath)
			// Pass logger from root options
			opts.Logger = ro.NewLogger()

			// Require certificate for certificate-based signing
			if opts.SigningCertificatePath == "" {
				return fmt.Errorf("--signing-certificate is required for pkcs11-certificate")
			}

			signer, err := pkcs11.NewPkcs11Signer(opts)
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
	o := &options.SigstoreSignOptions{}

	cmd := &cobra.Command{
		Use:   "sign [OPTIONS] MODEL_PATH",
		Short: "Sign models.",
		Long: `Sign models.

    Signing the model at MODEL_PATH, produces the signature at SIGNATURE_PATH
    (as per --signature option). Files in IGNORE_PATHS are not part of the
    signature.

    By default, Sigstore is used. Specify a PKI method subcommand (sigstore,
    key, certificate) for other signing methods.

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
    used, which is pre-configured with Sigstore's own trusted transparency
    logs and certificate authorities. This provides a ready-to-use default
    trust model for most use cases but may not be suitable for custom or
    highly regulated environments.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runSigstoreSign(cmd.Context(), o, args[0])
		},
	}

	// Register Sigstore flags on the parent so that
	// `sign MODEL_PATH --ignore-paths ...` works without specifying
	// the sigstore subcommand explicitly.
	o.AddFlags(cmd)

	// Add PKI subcommands. Each owns its own flags.
	cmd.AddCommand(NewSigstoreSign())
	cmd.AddCommand(NewKeySigner())
	cmd.AddCommand(NewCertificateSigner())
	cmd.AddCommand(NewPkcs11KeySigner())
	cmd.AddCommand(NewPkcs11CertificateSigner())

	return cmd
}
