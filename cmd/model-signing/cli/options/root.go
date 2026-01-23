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

// Package options defines the command-line options and flags for the model-signing CLI.
// It provides option structures for root commands, signing, and verification operations.
package options

import (
	"time"

	"github.com/spf13/cobra"
)

// EnvPrefix is the prefix used for environment variables that configure the CLI.
const EnvPrefix = "MODEL_SIGNING"

// RootOptions defines flags and options for the root CLI command.
// These options are available globally across all subcommands.
type RootOptions struct {
	// OutputFile specifies a file path to redirect output to instead of stdout.
	OutputFile string
	// Verbose enables debug-level logging output.
	Verbose bool
	// Timeout sets the maximum duration for command execution.
	Timeout time.Duration
}

// DefaultTimeout specifies the default timeout duration for commands.
const DefaultTimeout = 3 * time.Minute

var _ Interface = (*RootOptions)(nil)

// AddFlags implements the Interface by adding root-level flags to the cobra command.
// This includes flags for output file redirection, verbose logging, and command timeout.
func (o *RootOptions) AddFlags(cmd *cobra.Command) {
	cmd.PersistentFlags().StringVar(&o.OutputFile, "output-file", "",
		"log output to a file")
	_ = cmd.MarkFlagFilename("output-file", logExts...)

	cmd.PersistentFlags().BoolVarP(&o.Verbose, "verbose", "d", false,
		"log debug output")

	cmd.PersistentFlags().DurationVarP(&o.Timeout, "timeout", "t", DefaultTimeout,
		"timeout for commands")
}
