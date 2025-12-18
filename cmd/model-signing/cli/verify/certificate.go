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
		Short: "Verify using a certificate (not yet implemented).",
		Long: `Verify model signatures using certificate-based verification.

This verification method is not yet implemented. Please use 'sigstore'
verification instead:

  model-signing verify sigstore MODEL_PATH --signature SIGNATURE_PATH \
    --identity IDENTITY --identity_provider ISSUER_URL

For more information, see: https://github.com/sigstore/model-signing`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return fmt.Errorf("certificate verification is not yet implemented\n\nPlease use 'sigstore' verification instead")
		},
	}
	return cmd
}
