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
	"bytes"
	"os"
	"testing"
)

// TestNewLogger tests that NewLogger creates a logger with correct settings.
func TestNewLogger(t *testing.T) {
	tests := []struct {
		name           string
		verbose        bool
		expectedSilent bool
	}{
		{
			name:           "verbose mode",
			verbose:        true,
			expectedSilent: false,
		},
		{
			name:           "silent mode",
			verbose:        false,
			expectedSilent: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logger := NewLogger(tt.verbose)
			if logger == nil {
				t.Fatal("NewLogger() returned nil")
			}
			if logger.Silent() != tt.expectedSilent {
				t.Errorf("NewLogger(%v).Silent() = %v, want %v", tt.verbose, logger.Silent(), tt.expectedSilent)
			}
			if logger.out != os.Stdout {
				t.Error("NewLogger() should write to os.Stdout")
			}
		})
	}
}

// TestLoggerInfo tests that Info always prints messages.
func TestLoggerInfo(t *testing.T) {
	tests := []struct {
		name     string
		verbose  bool
		format   string
		args     []interface{}
		expected string
	}{
		{
			name:     "simple message verbose",
			verbose:  true,
			format:   "hello world",
			args:     nil,
			expected: "hello world\n",
		},
		{
			name:     "simple message silent",
			verbose:  false,
			format:   "hello world",
			args:     nil,
			expected: "hello world\n",
		},
		{
			name:     "formatted message",
			verbose:  false,
			format:   "value: %d, name: %s",
			args:     []interface{}{42, "test"},
			expected: "value: 42, name: test\n",
		},
		{
			name:     "empty message",
			verbose:  false,
			format:   "",
			args:     nil,
			expected: "\n",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			logger := &Logger{verbose: tt.verbose, out: &buf}
			logger.Info(tt.format, tt.args...)
			if buf.String() != tt.expected {
				t.Errorf("Info() output = %q, want %q", buf.String(), tt.expected)
			}
		})
	}
}

// TestLoggerDebug tests that Debug only prints when verbose is enabled.
func TestLoggerDebug(t *testing.T) {
	tests := []struct {
		name     string
		verbose  bool
		format   string
		args     []interface{}
		expected string
	}{
		{
			name:     "verbose mode prints message",
			verbose:  true,
			format:   "debug message",
			args:     nil,
			expected: "debug message\n",
		},
		{
			name:     "silent mode suppresses message",
			verbose:  false,
			format:   "debug message",
			args:     nil,
			expected: "",
		},
		{
			name:     "verbose with format args",
			verbose:  true,
			format:   "processing %s: %d items",
			args:     []interface{}{"files", 5},
			expected: "processing files: 5 items\n",
		},
		{
			name:     "silent with format args",
			verbose:  false,
			format:   "processing %s: %d items",
			args:     []interface{}{"files", 5},
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			logger := &Logger{verbose: tt.verbose, out: &buf}
			logger.Debug(tt.format, tt.args...)
			if buf.String() != tt.expected {
				t.Errorf("Debug() output = %q, want %q", buf.String(), tt.expected)
			}
		})
	}
}

// TestLoggerDebugln tests that Debugln only prints when verbose is enabled.
func TestLoggerDebugln(t *testing.T) {
	tests := []struct {
		name     string
		verbose  bool
		msg      string
		expected string
	}{
		{
			name:     "verbose mode prints message",
			verbose:  true,
			msg:      "debug line",
			expected: "debug line\n",
		},
		{
			name:     "silent mode suppresses message",
			verbose:  false,
			msg:      "debug line",
			expected: "",
		},
		{
			name:     "verbose with empty message",
			verbose:  true,
			msg:      "",
			expected: "\n",
		},
		{
			name:     "silent with empty message",
			verbose:  false,
			msg:      "",
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			logger := &Logger{verbose: tt.verbose, out: &buf}
			logger.Debugln(tt.msg)
			if buf.String() != tt.expected {
				t.Errorf("Debugln() output = %q, want %q", buf.String(), tt.expected)
			}
		})
	}
}

// TestLoggerSilent tests the Silent method.
func TestLoggerSilent(t *testing.T) {
	tests := []struct {
		name     string
		verbose  bool
		expected bool
	}{
		{
			name:     "verbose mode returns false",
			verbose:  true,
			expected: false,
		},
		{
			name:     "silent mode returns true",
			verbose:  false,
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logger := &Logger{verbose: tt.verbose}
			if logger.Silent() != tt.expected {
				t.Errorf("Silent() = %v, want %v", logger.Silent(), tt.expected)
			}
		})
	}
}

// TestLoggerMultipleMessages tests logging multiple messages in sequence.
func TestLoggerMultipleMessages(t *testing.T) {
	var buf bytes.Buffer
	logger := &Logger{verbose: true, out: &buf}

	logger.Info("info 1")
	logger.Debug("debug 1")
	logger.Info("info 2")
	logger.Debugln("debugln 1")

	expected := "info 1\ndebug 1\ninfo 2\ndebugln 1\n"
	if buf.String() != expected {
		t.Errorf("Multiple messages output = %q, want %q", buf.String(), expected)
	}
}

// TestLoggerMultipleMessagesSilent tests that debug messages are suppressed in silent mode.
func TestLoggerMultipleMessagesSilent(t *testing.T) {
	var buf bytes.Buffer
	logger := &Logger{verbose: false, out: &buf}

	logger.Info("info 1")
	logger.Debug("debug 1") // Should be suppressed
	logger.Info("info 2")
	logger.Debugln("debugln 1") // Should be suppressed

	expected := "info 1\ninfo 2\n"
	if buf.String() != expected {
		t.Errorf("Multiple messages (silent) output = %q, want %q", buf.String(), expected)
	}
}
