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

	"github.com/sigstore/model-signing/pkg/logging"
	"github.com/spf13/cobra"
)

// EnvPrefix is the prefix used for environment variables that configure the CLI.
const EnvPrefix = "MODEL_SIGNING"

// RootOptions defines flags and options for the root CLI command.
// These options are available globally across all subcommands.
type RootOptions struct {
	// OutputFile specifies a file path to redirect output to instead of stdout.
	OutputFile string
	// LogLevel sets the minimum log level (debug, info, warn, error, silent).
	LogLevel string
	// LogFormat sets the log output format (text, json).
	LogFormat string
	// Timeout sets the maximum duration for command execution.
	Timeout time.Duration
}

// DefaultTimeout specifies the default timeout duration for commands.
const DefaultTimeout = 3 * time.Minute

// ValidLogLevels lists the valid log level strings.
var ValidLogLevels = []string{"debug", "info", "warn", "error", "silent"}

// ValidLogFormats lists the valid log format strings.
var ValidLogFormats = []string{"text", "json"}

var _ Interface = (*RootOptions)(nil)

// AddFlags implements the Interface by adding root-level flags to the cobra command.
// This includes flags for output file redirection, log level/format, and command timeout.
func (o *RootOptions) AddFlags(cmd *cobra.Command) {
	cmd.PersistentFlags().StringVar(&o.OutputFile, "output-file", "",
		"log output to a file")
	_ = cmd.MarkFlagFilename("output-file", logExts...)

	cmd.PersistentFlags().StringVar(&o.LogLevel, "log-level", "info",
		"set the minimum log level (debug, info, warn, error, silent)")

	cmd.PersistentFlags().StringVar(&o.LogFormat, "log-format", "text",
		"set the log output format (text, json)")

	cmd.PersistentFlags().DurationVarP(&o.Timeout, "timeout", "t", DefaultTimeout,
		"timeout for commands")
}

// GetLogLevel returns the effective log level based on the options.
func (o *RootOptions) GetLogLevel() logging.LogLevel {
	return logging.ParseLogLevel(o.LogLevel)
}

// GetLogFormat returns the log format based on the options.
func (o *RootOptions) GetLogFormat() logging.LogFormat {
	return logging.ParseLogFormat(o.LogFormat)
}

// NewLogger creates a new logger based on the root options.
func (o *RootOptions) NewLogger() logging.Logger {
	return logging.NewLoggerWithOptions(logging.LoggerOptions{
		Level:  o.GetLogLevel(),
		Format: o.GetLogFormat(),
	})
}
