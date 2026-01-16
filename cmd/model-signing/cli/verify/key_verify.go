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

package verify

import (
	"context"
	"fmt"
	"time"

	"github.com/sigstore/model-signing/cmd/model-signing/cli/options"
	keyverify "github.com/sigstore/model-signing/pkg/verify/key"
	"github.com/spf13/cobra"
)

func NewKey() *cobra.Command {
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

			// Map CLI options to key verifier options
			opts := keyverify.KeyVerifierOptions{
				ModelPath:           modelPath,
				SignaturePath:       o.SignaturePath,
				IgnorePaths:         o.IgnorePaths,
				IgnoreGitPaths:      o.IgnoreGitPaths,
				AllowSymlinks:       o.AllowSymlinks,
				PublicKeyPath:       o.PublicKeyPath,
				IgnoreUnsignedFiles: o.IgnoreUnsignedFiles,
			}

			verifier, err := keyverify.NewKeyVerifier(opts)
			if err != nil {
				return err
			}

			ctx, cancel := context.WithTimeout(cmd.Context(), 2*time.Minute)
			defer cancel()

			status, err := verifier.Verify(ctx)
			fmt.Println("Verification Status: ", status)
			return err
		},
	}

	o.AddFlags(cmd)
	return cmd
}
