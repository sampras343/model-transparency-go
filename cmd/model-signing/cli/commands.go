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
	"fmt"
	"os"

	"github.com/google/go-containerregistry/pkg/logs"
	"github.com/sigstore/model-signing/cmd/model-signing/cli/options"
	"github.com/sigstore/model-signing/cmd/model-signing/cli/templates"
	"github.com/spf13/cobra"
	cobracompletefig "github.com/withfig/autocomplete-tools/integrations/cobra"
	"sigs.k8s.io/release-utils/version"
)

var (
	ro = &options.RootOptions{}
)

func New() *cobra.Command {
	var (
		out, stdout *os.File
	)

	cmd := &cobra.Command{
		Use:               "model-signing",
		Short:             "ML model signing and verification.",
		DisableAutoGenTag: true,
		SilenceUsage:      true,
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

			if ro.Verbose {
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
	ro.AddFlags(cmd)

	templates.SetCustomUsageFunc(cmd)

	// Add sub-commands.
	cmd.AddCommand(Verify())
	cmd.AddCommand(version.WithFont("starwars"))
	cmd.AddCommand(cobracompletefig.CreateCompletionSpecCommand())
	return cmd
}
