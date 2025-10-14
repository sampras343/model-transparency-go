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

package sigstore

import (
	"context"
	"time"

	"github.com/sigstore/model-signing/cmd/model-signing/cli/options"
	"github.com/spf13/cobra"
)

func New() *cobra.Command {
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
			v := &SigstoreCommand{
				SignaturePath:    o.SignaturePath,
				IgnorePaths:      o.IgnorePaths,
				IgnoreGitPaths:   o.IgnoreGitPaths,
				UseStaging:       o.UseStaging,
				Identity:         o.Identity,
				IdentityProvider: o.IdentityProvider,
			}

			ctx, cancel := context.WithTimeout(cmd.Context(), 2*time.Minute)
			defer cancel()

			return v.Exec(ctx, modelPath)
		},
	}

	o.AddFlags(cmd)
	return cmd
}
