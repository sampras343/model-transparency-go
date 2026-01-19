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
	"github.com/sigstore/model-signing/cmd/model-signing/cli/sign"
	"github.com/spf13/cobra"
)

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
			sigCmd := sign.NewSigstore()
			sigCmd.SilenceUsage = parent.SilenceUsage
			sigCmd.SilenceErrors = parent.SilenceErrors

			sigCmd.SetArgs(args)
			return sigCmd.ExecuteContext(parent.Context())
		},
	}

	// Add PKI subcommands. Each owns its own flags.
	cmd.AddCommand(sign.NewSigstore())    // full implementation
	cmd.AddCommand(sign.NewKey())         // full implementation
	cmd.AddCommand(sign.NewCertificate()) // stub for now

	return cmd
}
