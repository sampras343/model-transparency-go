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

package sign

import (
	"context"
	"fmt"
	"time"

	"github.com/sigstore/model-signing/cmd/model-signing/cli/options"
	sigstore_signer "github.com/sigstore/model-signing/pkg/signing/sigstore"
	"github.com/spf13/cobra"
)

func NewSigstore() *cobra.Command {
	o := &options.SigstoreSignOpetions{}

	long := `Sign using Sigstore (DEFAULT signing method).

Signs the of model at MODEL_PATH and stores the signature to
SIGNATURE_PATH (given via --signature option). Files in IGNORE_PATHS are ignored.

For Sigstore, we also need to provide an expected identity token for the signature. `

	cmd := &cobra.Command{
		Use:   "sigstore [OPTIONS]",
		Short: "Sign using Sigstore (DEFAULT signing method).",
		Long:  long,
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			modelPath := args[0]

			// Map CLI options directly to signer options
			opts := sigstore_signer.SigstoreSignerOptions{
				ModelPath:             modelPath,
				SignaturePath:         o.SignaturePath,
				IgnorePaths:           o.IgnorePaths,
				IgnoreGitPaths:        o.IgnoreGitPaths,
				AllowSymlinks:         o.AllowSymlinks,
				UseStaging:            o.UseStaging,
				OAuthForceOob:         o.OAuthForceOob,
				UseAmbientCredentials: o.UseAmbientCredentials,
				IdentityToken:         o.IdentityToken,
				ClientId:              o.ClientId,
				ClientSecret:          o.ClientSecret,
				TrustConfigPath:       o.TrustConfigPath,
			}

			signer, err := sigstore_signer.NewSigstoreSigner(opts)
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
