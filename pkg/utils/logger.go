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

package utils

import (
	"fmt"
	"io"
	"os"
)

// Logger provides a simple logging interface that respects verbose mode.
type Logger struct {
	verbose bool
	out     io.Writer
}

// NewLogger creates a new logger instance.
// If verbose is false, only Info messages are shown.
// If verbose is true, all messages (Info and Debug) are shown.
func NewLogger(verbose bool) *Logger {
	return &Logger{
		verbose: verbose,
		out:     os.Stdout,
	}
}

// Info prints an informational message (always shown).
func (l *Logger) Info(format string, args ...interface{}) {
	fmt.Fprintf(l.out, format+"\n", args...)
}

// Debug prints a debug message (only shown when verbose is enabled).
func (l *Logger) Debug(format string, args ...interface{}) {
	if l.verbose {
		fmt.Fprintf(l.out, format+"\n", args...)
	}
}

// Debugln prints a debug line (only shown when verbose is enabled).
func (l *Logger) Debugln(msg string) {
	if l.verbose {
		fmt.Fprintln(l.out, msg)
	}
}

// Silent returns true if not in verbose mode.
func (l *Logger) Silent() bool {
	return !l.verbose
}
