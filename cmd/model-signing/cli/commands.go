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

// Package cli provides the command-line interface for model signing and verification.
// It defines the root command structure and subcommands for various PKI methods.
package cli

import (
	"fmt"
	"os"
	"strings"

	"github.com/google/go-containerregistry/pkg/logs"
	"github.com/sigstore/model-signing/cmd/model-signing/cli/options"
	"github.com/sigstore/model-signing/cmd/model-signing/cli/templates"
	"github.com/sigstore/model-signing/pkg/logging"
	"github.com/spf13/cobra"
	flag "github.com/spf13/pflag"
	cobracompletefig "github.com/withfig/autocomplete-tools/integrations/cobra"
	"sigs.k8s.io/release-utils/version"
)

var (
	ro = &options.RootOptions{}
)

// New creates and returns the root cobra command for the model-signing CLI.
// It configures persistent flags, output redirection, and adds all subcommands
// including sign, verify, version, and completion commands.
//
// Returns a fully configured *cobra.Command ready for execution.
func New() *cobra.Command {
	var (
		out, stdout *os.File
	)

	cmd := &cobra.Command{
		Use:               "model-signing",
		Short:             "ML model signing and verification.",
		DisableAutoGenTag: true,
		SilenceUsage:      true,
		TraverseChildren:  true,
		PersistentPreRunE: func(cmd *cobra.Command, _ []string) error {
			if ro.OutputFile != "" {
				var err error
				out, err = os.Create(ro.OutputFile)
				if err != nil {
					return fmt.Errorf("error creating output file %s: %w", ro.OutputFile, err)
				}
				stdout = os.Stdout
				os.Stdout = out
				cmd.SetOut(out)
			}

			if ro.GetLogLevel() == logging.LevelDebug {
				logs.Debug.SetOutput(os.Stderr)
			}

			return nil
		},
		PersistentPostRun: func(_ *cobra.Command, _ []string) {
			if out != nil {
				_ = out.Close()
			}
			os.Stdout = stdout
		},
	}
	// Normalize flags so that underscores are treated as hyphens.
	// This ensures compatibility with the Python model_signing CLI
	cmd.SetGlobalNormalizationFunc(func(_ *flag.FlagSet, name string) flag.NormalizedName {
		return flag.NormalizedName(strings.ReplaceAll(name, "_", "-"))
	})

	ro.AddFlags(cmd)

	templates.SetCustomUsageFunc(cmd)

	// Add sub-commands.
	cmd.AddCommand(Sign())
	cmd.AddCommand(Verify())
	cmd.AddCommand(version.WithFont("starwars"))
	cmd.AddCommand(cobracompletefig.CreateCompletionSpecCommand())
	return cmd
}
