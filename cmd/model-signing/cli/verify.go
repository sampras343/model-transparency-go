//
// Copyright 2025 The Sigstore Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package cli

import (
	"github.com/sigstore/model-signing/cmd/model-signing/cli/verify"
	"github.com/spf13/cobra"
)

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
			sigCmd := verify.NewSigstore()
			sigCmd.SilenceUsage = parent.SilenceUsage
			sigCmd.SilenceErrors = parent.SilenceErrors

			sigCmd.SetArgs(args)
			return sigCmd.ExecuteContext(parent.Context())
		},
	}

	// Add PKI subcommands. Each owns its own flags.
	cmd.AddCommand(verify.NewSigstore())    // full implementation
	cmd.AddCommand(verify.NewKey())         // stub for now
	cmd.AddCommand(verify.NewCertificate()) // stub for now

	return cmd
}
