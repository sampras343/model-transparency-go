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
	key "github.com/sigstore/model-signing/pkg/signing/key"
	"github.com/spf13/cobra"
)

func NewKey() *cobra.Command {
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

			opts := key.KeySignerOptions{
				ModelPath:      modelPath,
				SignaturePath:  o.SignaturePath,
				IgnorePaths:    o.IgnorePaths,
				IgnoreGitPaths: o.IgnoreGitPaths,
				AllowSymlinks:  o.AllowSymlinks,
				PrivateKeyPath: o.PrivateKeyPath,
				Password:       o.Password,
			}

			signer, err := key.NewKeySigner(opts)
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
