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
	"github.com/sigstore/model-signing/pkg/tracing"
	cert "github.com/sigstore/model-signing/pkg/verify/certificate"
	keyverify "github.com/sigstore/model-signing/pkg/verify/key"
	sigstore "github.com/sigstore/model-signing/pkg/verify/sigstore"
)

// runSigstoreVerify performs Sigstore-based model verification with tracing.
// Shared by NewSigstoreVerifier (explicit subcommand) and Verify (default).
func runSigstoreVerify(ctx context.Context, o *options.SigstoreVerifyOptions, modelPath string) error {
	opts := o.ToStandardOptions(modelPath)
	opts.Logger = ro.NewObservability().Logger
	attrs := map[string]interface{}{
		"model_signing.method":               "sigstore",
		"model_signing.model_path":           modelPath,
		"model_signing.signature":            opts.SignaturePath,
		"model_signing.identity":             opts.Identity,
		"model_signing.oidc_issuer":          opts.IdentityProvider,
		"model_signing.use_staging":          opts.UseStaging,
		"model_signing.allow_symlinks":       opts.AllowSymlinks,
		"model_signing.ignore_git_paths":     opts.IgnoreGitPaths,
		"model_signing.ignore_unsigned_files": opts.IgnoreUnsignedFiles,
		"model_signing.trust_config_path":    opts.TrustConfigPath,
	}
	return tracing.Run(ctx, "Verify", attrs, func(ctx context.Context) error {
		verifier, err := sigstore.NewSigstoreVerifier(opts)
		if err != nil {
			return err
		}
		ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
		defer cancel()
		status, err := verifier.Verify(ctx)
		if ro.GetLogLevel() < logging.LevelSilent {
			fmt.Println(status.Message)
		}
		return err
	})
}

// NewSigstoreVerifier creates the sigstore subcommand for model verification.
// This command verifies models using Sigstore with expected identity and
// identity provider validation.
//
// Returns a *cobra.Command configured for Sigstore-based verification.
func NewSigstoreVerifier() *cobra.Command {
	o := &options.SigstoreVerifyOptions{}

	long := `Verify using Sigstore (DEFAULT verification method).

Verifies the integrity of model at MODEL_PATH, according to signature from
SIGNATURE_PATH (given via --signature option). Files in IGNORE_PATHS are ignored.

For Sigstore, we also need to provide an expected identity and identity
provider for the signature. If these don't match what is provided in the
signature, verification would fail.`

	cmd := &cobra.Command{
		Use:   "sigstore [OPTIONS]",
		Short: "Verify using Sigstore (DEFAULT verification method).",
		Long:  long,
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runSigstoreVerify(cmd.Context(), o, args[0])
		},
	}

	o.AddFlags(cmd)
	return cmd
}

// NewKeyVerifier creates the key subcommand for model verification.
// This command verifies models using a public key that must be paired
// with the private key used during signing.
//
// Returns a *cobra.Command configured for key-based verification.
func NewKeyVerifier() *cobra.Command {
	o := &options.KeyVerifyOptions{}
	long := `Verify using a public key (paired with a private one).

Verifies the integrity of model at MODEL_PATH, according to signature from
SIGNATURE_PATH (given via --signature option). Files in IGNORE_PATHS are
ignored.

The public key provided via --public-key must have been paired with the
private key used when generating the signature.

Note that this method does not provide a way to tie to the identity of the
signer, outside of pairing the keys. Also note that we don't offer key
management protocols.`

	cmd := &cobra.Command{
		Use:   "key [OPTIONS] MODEL_PATH",
		Short: "Verify using a public key.",
		Long:  long,
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			modelPath := args[0]
			opts := o.ToStandardOptions(modelPath)
			opts.Logger = ro.NewObservability().Logger
			attrs := map[string]interface{}{
				"model_signing.method":               "key",
				"model_signing.model_path":           modelPath,
				"model_signing.signature":            opts.SignaturePath,
				"model_signing.allow_symlinks":       opts.AllowSymlinks,
				"model_signing.ignore_git_paths":     opts.IgnoreGitPaths,
				"model_signing.ignore_unsigned_files": opts.IgnoreUnsignedFiles,
			}
			return tracing.Run(cmd.Context(), "Verify", attrs, func(ctx context.Context) error {
				verifier, err := keyverify.NewKeyVerifier(opts)
				if err != nil {
					return err
				}
				ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
				defer cancel()
				status, err := verifier.Verify(ctx)
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

// NewCertificateVerifier creates the certificate subcommand for model verification.
// This command verifies models using a certificate chain of trust, with the signing
// certificate encoded in the signature bundle.
//
// Returns a *cobra.Command configured for certificate-based verification.
func NewCertificateVerifier() *cobra.Command {
	o := &options.CertificateVerifyOptions{}
	long := `Verify using a certificate.

    Verifies the integrity of model at MODEL_PATH, according to
    signature from SIGNATURE_PATH (given via --signature option). Files in
    IGNORE_PATHS are ignored.

    The signing certificate is encoded in the signature, as part of the Sigstore
    bundle. To verify the root of trust, pass additional certificates in the
    certificate chain, using --certificate-chain (this option can be repeated
    as needed, or all certificates could be placed in a single file).

    Note that we don't offer certificate and key management protocols.`

	cmd := &cobra.Command{
		Use:   "certificate [OPTIONS] MODEL_PATH",
		Short: "Verify using a certificate.",
		Long:  long,
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			modelPath := args[0]
			opts := o.ToStandardOptions(modelPath)
			opts.Logger = ro.NewObservability().Logger
			attrs := map[string]interface{}{
				"model_signing.method":               "certificate",
				"model_signing.model_path":           modelPath,
				"model_signing.signature":            opts.SignaturePath,
				"model_signing.allow_symlinks":       opts.AllowSymlinks,
				"model_signing.ignore_git_paths":     opts.IgnoreGitPaths,
				"model_signing.ignore_unsigned_files": opts.IgnoreUnsignedFiles,
				"model_signing.log_fingerprints":     opts.LogFingerprints,
			}
			return tracing.Run(cmd.Context(), "Verify", attrs, func(ctx context.Context) error {
				verifier, err := cert.NewCertificateVerifier(opts)
				if err != nil {
					return err
				}
				ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
				defer cancel()
				status, err := verifier.Verify(ctx)
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

// Verify creates the verify command with all PKI method subcommands.
// It serves as the parent command for different verification methods (sigstore, key, certificate)
// and defaults to Sigstore verification when no subcommand is specified.
//
// Returns a *cobra.Command with all verification subcommands registered.
func Verify() *cobra.Command {
	o := &options.SigstoreVerifyOptions{}

	cmd := &cobra.Command{
		Use:   "verify [OPTIONS] MODEL_PATH",
		Short: "Verify models.",
		Long: `Verify models.

Given a model and a cryptographic signature (in the form of a Sigstore bundle) for the model,
this call checks that the model matches the signature, that the model has not been tampered with.
We support any model format, either as a single file or as a directory.

By default, Sigstore is used. Specify a PKI method subcommand (sigstore, key, certificate) for
other verification methods.

Use each subcommand's --help option for details on each mode.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runSigstoreVerify(cmd.Context(), o, args[0])
		},
	}

	// Register Sigstore flags on the parent so that
	// `verify MODEL_PATH --signature ... --identity ...` works without
	// specifying the sigstore subcommand explicitly.
	o.AddFlags(cmd)

	// Add PKI subcommands. Each owns its own flags.
	cmd.AddCommand(NewSigstoreVerifier())
	cmd.AddCommand(NewKeyVerifier())
	cmd.AddCommand(NewCertificateVerifier())

	return cmd
}
