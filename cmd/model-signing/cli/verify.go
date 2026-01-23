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
	"github.com/sigstore/model-signing/pkg/utils"
	cert "github.com/sigstore/model-signing/pkg/verify/certificate"
	keyverify "github.com/sigstore/model-signing/pkg/verify/key"
	sigstore "github.com/sigstore/model-signing/pkg/verify/sigstore"
)

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
			modelPath := args[0]

			opts := o.ToStandardOptions(modelPath)
			opts.Logger = utils.NewLogger(ro.Verbose)

			verifier, err := sigstore.NewSigstoreVerifier(opts)
			if err != nil {
				return err
			}

			ctx, cancel := context.WithTimeout(cmd.Context(), 2*time.Minute)
			defer cancel()

			status, err := verifier.Verify(ctx)
			if !ro.Verbose {
				fmt.Println(status.Message)
			}
			return err
		},
	}

	o.AddFlags(cmd)
	return cmd
}

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
			opts.Logger = utils.NewLogger(ro.Verbose)

			verifier, err := keyverify.NewKeyVerifier(opts)
			if err != nil {
				return err
			}

			ctx, cancel := context.WithTimeout(cmd.Context(), 2*time.Minute)
			defer cancel()

			status, err := verifier.Verify(ctx)
			if !ro.Verbose {
				fmt.Println(status.Message)
			}
			return err
		},
	}

	o.AddFlags(cmd)
	return cmd
}

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
			opts.Logger = utils.NewLogger(ro.Verbose)

			verifier, err := cert.NewCertificateVerifier(opts)
			if err != nil {
				return err
			}

			ctx, cancel := context.WithTimeout(cmd.Context(), 2*time.Minute)
			defer cancel()

			status, err := verifier.Verify(ctx)
			if !ro.Verbose {
				fmt.Println(status.Message)
			}
			return err
		},
	}

	o.AddFlags(cmd)
	return cmd
}

func Verify() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "verify [OPTIONS] PKI_METHOD",
		Short: "Verify models.",
		Long: `Verify models.

Given a model and a cryptographic signature (in the form of a Sigstore bundle) for the model,
this call checks that the model matches the signature, that the model has not been tampered with.
We support any model format, either as a single file or as a directory.

We support multiple PKI methods, specified as subcommands. By default, the signature is assumed
to be generated via Sigstore (as if invoking 'sigstore' subcommand).

Use each subcommand's --help option for details on each mode.`,
		DisableFlagParsing: true,
		Args:               cobra.ArbitraryArgs,
		RunE: func(parent *cobra.Command, args []string) error {
			sigCmd := NewSigstoreVerifier()
			sigCmd.SilenceUsage = parent.SilenceUsage
			sigCmd.SilenceErrors = parent.SilenceErrors

			sigCmd.SetArgs(args)
			return sigCmd.ExecuteContext(parent.Context())
		},
	}

	// Add PKI subcommands. Each owns its own flags.
	cmd.AddCommand(NewSigstoreVerifier())
	cmd.AddCommand(NewKeyVerifier())
	cmd.AddCommand(NewCertificateVerifier())

	return cmd
}
