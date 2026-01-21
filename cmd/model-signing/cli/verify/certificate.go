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
	"fmt"

	"github.com/spf13/cobra"
)

func NewCertificate() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "certificate",
		Short: "Verify using a certificate",
		Long: `Verify using a certificate.

    Verifies the integrity of model at MODEL_PATH, according to
    signature from SIGNATURE_PATH (given via --signature option). Files in
    IGNORE_PATHS are ignored.

    The signing certificate is encoded in the signature, as part of the Sigstore
    bundle. To verify the root of trust, pass additional certificates in the
    certificate chain, using --certificate-chain (this option can be repeated
    as needed, or all certificates could be placed in a single file).

    Note that we don't offer certificate and key management protocols.`,
		//nolint:revive
		RunE: func(cmd *cobra.Command, args []string) error {
			return fmt.Errorf("certificate verification is not yet implemented\n\nPlease use 'sigstore' verification instead")
		},
	}
	return cmd
}
