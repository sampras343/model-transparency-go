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
	"fmt"

	"github.com/spf13/cobra"
)

func NewKey() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "key",
		Short: "Sign using a public key (not yet implemented).",
		Long: `Sign model signatures using public key verification.
For more information, see: https://github.com/sigstore/model-signing`,
		//nolint:revive
		RunE: func(cmd *cobra.Command, args []string) error {
			return fmt.Errorf("key-based verification is not yet implemented\n\nPlease use 'sigstore' verification instead")
		},
	}
	return cmd
}
