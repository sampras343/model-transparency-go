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

package logging

import (
	"bytes"
	"encoding/json"
	"os"
	"strings"
	"testing"
)

// TestNewLogger tests that NewLogger creates a logger with correct settings.
func TestNewLogger(t *testing.T) {
	tests := []struct {
		name           string
		verbose        bool
		expectedSilent bool
		expectedLevel  LogLevel
	}{
		{
			name:           "verbose mode",
			verbose:        true,
			expectedSilent: false,
			expectedLevel:  LevelDebug,
		},
		{
			name:           "silent mode",
			verbose:        false,
			expectedSilent: true,
			expectedLevel:  LevelInfo,
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
			if logger.GetLevel() != tt.expectedLevel {
				t.Errorf("NewLogger(%v).GetLevel() = %v, want %v", tt.verbose, logger.GetLevel(), tt.expectedLevel)
			}
			if logger.out != os.Stdout {
				t.Error("NewLogger() should write to os.Stdout")
			}
		})
	}
}

// TestNewLoggerWithOptions tests creating a logger with custom options.
func TestNewLoggerWithOptions(t *testing.T) {
	var buf bytes.Buffer
	opts := LoggerOptions{
		Level:     LevelWarn,
		Format:    FormatJSON,
		Output:    &buf,
		ShowLevel: true,
	}

	logger := NewLoggerWithOptions(opts)
	if logger == nil {
		t.Fatal("NewLoggerWithOptions() returned nil")
	}
	if logger.GetLevel() != LevelWarn {
		t.Errorf("GetLevel() = %v, want %v", logger.GetLevel(), LevelWarn)
	}
	if _, ok := logger.formatter.(*JSONFormatter); !ok {
		t.Errorf("Expected JSONFormatter, got %T", logger.formatter)
	}
}

// TestNewLoggerWithCustomFormatter tests that a custom formatter is used.
func TestNewLoggerWithCustomFormatter(t *testing.T) {
	var buf bytes.Buffer
	customFmt := &TextFormatter{ShowLevel: true, TimeFormat: "15:04:05"}
	opts := LoggerOptions{
		Level:     LevelDebug,
		Format:    FormatJSON, // Should be ignored when Formatter is set
		Formatter: customFmt,
		Output:    &buf,
	}

	logger := NewLoggerWithOptions(opts)
	logger.Info("test")

	output := buf.String()
	if !strings.Contains(output, "[INFO]") {
		t.Errorf("Custom formatter not used, got %q", output)
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
			logger := NewLoggerWithOptions(LoggerOptions{
				Level:  LevelInfo,
				Format: FormatText,
				Output: &buf,
			})
			if tt.verbose {
				logger.SetLevel(LevelDebug)
			}
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
			logger := NewLoggerWithOptions(LoggerOptions{
				Level:  LevelInfo,
				Format: FormatText,
				Output: &buf,
			})
			if tt.verbose {
				logger.SetLevel(LevelDebug)
			}
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
			logger := NewLoggerWithOptions(LoggerOptions{
				Level:  LevelInfo,
				Format: FormatText,
				Output: &buf,
			})
			if tt.verbose {
				logger.SetLevel(LevelDebug)
			}
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
			logger := NewLogger(tt.verbose)
			if logger.Silent() != tt.expected {
				t.Errorf("Silent() = %v, want %v", logger.Silent(), tt.expected)
			}
		})
	}
}

// TestLoggerMultipleMessages tests logging multiple messages in sequence.
func TestLoggerMultipleMessages(t *testing.T) {
	var buf bytes.Buffer
	logger := NewLoggerWithOptions(LoggerOptions{
		Level:  LevelDebug,
		Format: FormatText,
		Output: &buf,
	})

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
	logger := NewLoggerWithOptions(LoggerOptions{
		Level:  LevelInfo,
		Format: FormatText,
		Output: &buf,
	})

	logger.Info("info 1")
	logger.Debug("debug 1") // Should be suppressed
	logger.Info("info 2")
	logger.Debugln("debugln 1") // Should be suppressed

	expected := "info 1\ninfo 2\n"
	if buf.String() != expected {
		t.Errorf("Multiple messages (silent) output = %q, want %q", buf.String(), expected)
	}
}

// TestLogLevelString tests the String method for LogLevel.
func TestLogLevelString(t *testing.T) {
	tests := []struct {
		level    LogLevel
		expected string
	}{
		{LevelDebug, "debug"},
		{LevelInfo, "info"},
		{LevelWarn, "warn"},
		{LevelError, "error"},
		{LevelSilent, "silent"},
		{LogLevel(99), "unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			if got := tt.level.String(); got != tt.expected {
				t.Errorf("LogLevel.String() = %q, want %q", got, tt.expected)
			}
		})
	}
}

// TestParseLogLevel tests parsing log level strings.
func TestParseLogLevel(t *testing.T) {
	tests := []struct {
		input    string
		expected LogLevel
	}{
		{"debug", LevelDebug},
		{"DEBUG", LevelDebug},
		{"  debug  ", LevelDebug},
		{"info", LevelInfo},
		{"INFO", LevelInfo},
		{"warn", LevelWarn},
		{"warning", LevelWarn},
		{"WARN", LevelWarn},
		{"error", LevelError},
		{"ERROR", LevelError},
		{"silent", LevelSilent},
		{"none", LevelSilent},
		{"off", LevelSilent},
		{"invalid", LevelInfo}, // Default to info
		{"", LevelInfo},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			if got := ParseLogLevel(tt.input); got != tt.expected {
				t.Errorf("ParseLogLevel(%q) = %v, want %v", tt.input, got, tt.expected)
			}
		})
	}
}

// TestLogFormatString tests the String method for LogFormat.
func TestLogFormatString(t *testing.T) {
	tests := []struct {
		format   LogFormat
		expected string
	}{
		{FormatText, "text"},
		{FormatJSON, "json"},
		{LogFormat(99), "unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			if got := tt.format.String(); got != tt.expected {
				t.Errorf("LogFormat.String() = %q, want %q", got, tt.expected)
			}
		})
	}
}

// TestParseLogFormat tests parsing log format strings.
func TestParseLogFormat(t *testing.T) {
	tests := []struct {
		input    string
		expected LogFormat
	}{
		{"json", FormatJSON},
		{"JSON", FormatJSON},
		{"  json  ", FormatJSON},
		{"text", FormatText},
		{"TEXT", FormatText},
		{"plain", FormatText},
		{"invalid", FormatText}, // Default to text
		{"", FormatText},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			if got := ParseLogFormat(tt.input); got != tt.expected {
				t.Errorf("ParseLogFormat(%q) = %v, want %v", tt.input, got, tt.expected)
			}
		})
	}
}

// TestLoggerWarn tests the Warn method.
func TestLoggerWarn(t *testing.T) {
	tests := []struct {
		name     string
		level    LogLevel
		format   string
		args     []interface{}
		expected string
	}{
		{
			name:     "warn level shows message",
			level:    LevelWarn,
			format:   "warning message",
			args:     nil,
			expected: "warning message\n",
		},
		{
			name:     "info level shows warn",
			level:    LevelInfo,
			format:   "warning message",
			args:     nil,
			expected: "warning message\n",
		},
		{
			name:     "error level hides warn",
			level:    LevelError,
			format:   "warning message",
			args:     nil,
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			logger := NewLoggerWithOptions(LoggerOptions{
				Level:  tt.level,
				Format: FormatText,
				Output: &buf,
			})
			logger.Warn(tt.format, tt.args...)
			if buf.String() != tt.expected {
				t.Errorf("Warn() output = %q, want %q", buf.String(), tt.expected)
			}
		})
	}
}

// TestLoggerError tests the Error method.
func TestLoggerError(t *testing.T) {
	tests := []struct {
		name     string
		level    LogLevel
		format   string
		args     []interface{}
		expected string
	}{
		{
			name:     "error level shows message",
			level:    LevelError,
			format:   "error message",
			args:     nil,
			expected: "error message\n",
		},
		{
			name:     "info level shows error",
			level:    LevelInfo,
			format:   "error message",
			args:     nil,
			expected: "error message\n",
		},
		{
			name:     "silent level hides error",
			level:    LevelSilent,
			format:   "error message",
			args:     nil,
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			logger := NewLoggerWithOptions(LoggerOptions{
				Level:  tt.level,
				Format: FormatText,
				Output: &buf,
			})
			logger.Error(tt.format, tt.args...)
			if buf.String() != tt.expected {
				t.Errorf("Error() output = %q, want %q", buf.String(), tt.expected)
			}
		})
	}
}

// TestLoggerJSONFormat tests JSON format output.
func TestLoggerJSONFormat(t *testing.T) {
	var buf bytes.Buffer
	logger := NewLoggerWithOptions(LoggerOptions{
		Level:  LevelDebug,
		Format: FormatJSON,
		Output: &buf,
	})

	logger.Info("test message")

	var entry jsonEntry
	if err := json.Unmarshal(buf.Bytes(), &entry); err != nil {
		t.Fatalf("Failed to parse JSON output: %v", err)
	}

	if entry.Level != "info" {
		t.Errorf("JSON level = %q, want %q", entry.Level, "info")
	}
	if entry.Message != "test message" {
		t.Errorf("JSON message = %q, want %q", entry.Message, "test message")
	}
	if entry.Timestamp == "" {
		t.Error("JSON timestamp should not be empty")
	}
}

// TestLoggerWithFields tests structured logging with fields.
func TestLoggerWithFields(t *testing.T) {
	var buf bytes.Buffer
	logger := NewLoggerWithOptions(LoggerOptions{
		Level:  LevelDebug,
		Format: FormatJSON,
		Output: &buf,
	})

	loggerWithFields := logger.WithFields(map[string]interface{}{
		"key1": "value1",
		"key2": 42,
	})

	loggerWithFields.Info("test message")

	var entry jsonEntry
	if err := json.Unmarshal(buf.Bytes(), &entry); err != nil {
		t.Fatalf("Failed to parse JSON output: %v", err)
	}

	if entry.Fields == nil {
		t.Fatal("Expected fields to be present")
	}
	if entry.Fields["key1"] != "value1" {
		t.Errorf("Field key1 = %v, want %v", entry.Fields["key1"], "value1")
	}
	if entry.Fields["key2"] != float64(42) { // JSON numbers are float64
		t.Errorf("Field key2 = %v, want %v", entry.Fields["key2"], 42)
	}
}

// TestLoggerWithField tests adding a single field.
func TestLoggerWithField(t *testing.T) {
	var buf bytes.Buffer
	logger := NewLoggerWithOptions(LoggerOptions{
		Level:  LevelDebug,
		Format: FormatJSON,
		Output: &buf,
	})

	loggerWithField := logger.WithField("operation", "sign")
	loggerWithField.Info("started")

	var entry jsonEntry
	if err := json.Unmarshal(buf.Bytes(), &entry); err != nil {
		t.Fatalf("Failed to parse JSON output: %v", err)
	}

	if entry.Fields["operation"] != "sign" {
		t.Errorf("Field operation = %v, want %v", entry.Fields["operation"], "sign")
	}
}

// TestLoggerFieldsDoNotMutateOriginal tests that WithFields returns a new logger.
func TestLoggerFieldsDoNotMutateOriginal(t *testing.T) {
	var buf1, buf2 bytes.Buffer
	logger1 := NewLoggerWithOptions(LoggerOptions{
		Level:  LevelDebug,
		Format: FormatJSON,
		Output: &buf1,
	})

	logger2 := logger1.WithField("key", "value")
	logger2.(*DefaultLogger).SetOutput(&buf2)

	logger1.Info("message1")
	logger2.Info("message2")

	// Parse logger1 output
	var entry1 jsonEntry
	if err := json.Unmarshal(buf1.Bytes(), &entry1); err != nil {
		t.Fatalf("Failed to parse logger1 JSON output: %v", err)
	}
	if entry1.Fields != nil {
		t.Errorf("Original logger should not have fields, got %v", entry1.Fields)
	}

	// Parse logger2 output
	var entry2 jsonEntry
	if err := json.Unmarshal(buf2.Bytes(), &entry2); err != nil {
		t.Fatalf("Failed to parse logger2 JSON output: %v", err)
	}
	if entry2.Fields == nil || entry2.Fields["key"] != "value" {
		t.Errorf("New logger should have field key=value, got %v", entry2.Fields)
	}
}

// TestLoggerTextFormatWithLevel tests text format with level shown.
func TestLoggerTextFormatWithLevel(t *testing.T) {
	var buf bytes.Buffer
	logger := NewLoggerWithOptions(LoggerOptions{
		Level:     LevelDebug,
		Format:    FormatText,
		Output:    &buf,
		ShowLevel: true,
	})

	logger.Info("test message")

	output := buf.String()
	if !strings.Contains(output, "[INFO]") {
		t.Errorf("Expected output to contain [INFO], got %q", output)
	}
	if !strings.Contains(output, "test message") {
		t.Errorf("Expected output to contain message, got %q", output)
	}
}

// TestLoggerSetLevel tests changing the log level.
func TestLoggerSetLevel(t *testing.T) {
	var buf bytes.Buffer
	logger := NewLoggerWithOptions(LoggerOptions{
		Level:  LevelInfo,
		Format: FormatText,
		Output: &buf,
	})

	logger.Debug("should not appear")
	if buf.Len() > 0 {
		t.Errorf("Debug should be suppressed at info level, got %q", buf.String())
	}

	logger.SetLevel(LevelDebug)
	logger.Debug("should appear")
	if !strings.Contains(buf.String(), "should appear") {
		t.Errorf("Debug should appear after SetLevel, got %q", buf.String())
	}
}

// TestLoggerIsLevelEnabled tests the IsLevelEnabled method.
func TestLoggerIsLevelEnabled(t *testing.T) {
	logger := NewLoggerWithOptions(LoggerOptions{
		Level: LevelWarn,
	})

	tests := []struct {
		level    LogLevel
		expected bool
	}{
		{LevelDebug, false},
		{LevelInfo, false},
		{LevelWarn, true},
		{LevelError, true},
	}

	for _, tt := range tests {
		t.Run(tt.level.String(), func(t *testing.T) {
			if got := logger.IsLevelEnabled(tt.level); got != tt.expected {
				t.Errorf("IsLevelEnabled(%v) = %v, want %v", tt.level, got, tt.expected)
			}
		})
	}
}

// TestDefaultLoggerOptions tests the default options.
func TestDefaultLoggerOptions(t *testing.T) {
	opts := DefaultLoggerOptions()

	if opts.Level != LevelInfo {
		t.Errorf("Default level = %v, want %v", opts.Level, LevelInfo)
	}
	if opts.Format != FormatText {
		t.Errorf("Default format = %v, want %v", opts.Format, FormatText)
	}
	if opts.Output != os.Stdout {
		t.Error("Default output should be os.Stdout")
	}
}

// TestLoggerAllLevels tests all log level methods.
func TestLoggerAllLevels(t *testing.T) {
	var buf bytes.Buffer
	logger := NewLoggerWithOptions(LoggerOptions{
		Level:     LevelDebug,
		Format:    FormatText,
		Output:    &buf,
		ShowLevel: true,
	})

	logger.Debug("debug msg")
	logger.Info("info msg")
	logger.Warn("warn msg")
	logger.Error("error msg")

	output := buf.String()
	if !strings.Contains(output, "[DEBUG]") {
		t.Error("Expected [DEBUG] in output")
	}
	if !strings.Contains(output, "[INFO]") {
		t.Error("Expected [INFO] in output")
	}
	if !strings.Contains(output, "[WARN]") {
		t.Error("Expected [WARN] in output")
	}
	if !strings.Contains(output, "[ERROR]") {
		t.Error("Expected [ERROR] in output")
	}
}

// TestLoggerLnMethods tests the Infoln, Warnln, Errorln methods.
func TestLoggerLnMethods(t *testing.T) {
	var buf bytes.Buffer
	logger := NewLoggerWithOptions(LoggerOptions{
		Level:  LevelDebug,
		Format: FormatText,
		Output: &buf,
	})

	logger.Infoln("info line")
	logger.Warnln("warn line")
	logger.Errorln("error line")

	output := buf.String()
	if !strings.Contains(output, "info line\n") {
		t.Errorf("Expected 'info line' in output, got %q", output)
	}
	if !strings.Contains(output, "warn line\n") {
		t.Errorf("Expected 'warn line' in output, got %q", output)
	}
	if !strings.Contains(output, "error line\n") {
		t.Errorf("Expected 'error line' in output, got %q", output)
	}
}

// TestLoggerTextWithFields tests text format with fields.
func TestLoggerTextWithFields(t *testing.T) {
	var buf bytes.Buffer
	logger := NewLoggerWithOptions(LoggerOptions{
		Level:  LevelDebug,
		Format: FormatText,
		Output: &buf,
	})

	loggerWithFields := logger.WithField("key", "value")
	loggerWithFields.Info("test message")

	output := buf.String()
	if !strings.Contains(output, "test message") {
		t.Errorf("Expected message in output, got %q", output)
	}
	if !strings.Contains(output, "key=value") {
		t.Errorf("Expected field in output, got %q", output)
	}
}

// TestEnsureLogger tests the EnsureLogger helper.
func TestEnsureLogger(t *testing.T) {
	// nil returns a default
	l := EnsureLogger(nil)
	if l == nil {
		t.Fatal("EnsureLogger(nil) returned nil")
	}

	// non-nil returns same
	custom := NewLogger(true)
	l2 := EnsureLogger(custom)
	if l2 != custom {
		t.Error("EnsureLogger should return the provided logger when non-nil")
	}
}

// TestDefaultFunction tests the Default() helper.
func TestDefaultFunction(t *testing.T) {
	l := Default()
	if l == nil {
		t.Fatal("Default() returned nil")
	}
	if !l.Silent() {
		t.Error("Default() should return a non-verbose (silent) logger")
	}
}

// TestLoggerInterface tests that DefaultLogger satisfies the Logger interface.
func TestLoggerInterface(t *testing.T) {
	var l Logger = NewLogger(true)

	// Exercise all interface methods
	l.Debug("debug %s", "msg")
	l.Debugln("debugln")
	l.Info("info %s", "msg")
	l.Infoln("infoln")
	l.Warn("warn %s", "msg")
	l.Warnln("warnln")
	l.Error("error %s", "msg")
	l.Errorln("errorln")
	_ = l.GetLevel()
	_ = l.Silent()
	l2 := l.WithField("k", "v")
	_ = l2.WithFields(map[string]interface{}{"a": 1})
}

// TestFormatterInterface tests that formatters are properly pluggable.
func TestFormatterInterface(t *testing.T) {
	var buf bytes.Buffer

	// Use a custom formatter via LoggerOptions
	logger := NewLoggerWithOptions(LoggerOptions{
		Level:     LevelDebug,
		Formatter: &JSONFormatter{},
		Output:    &buf,
	})

	logger.Info("custom")

	var entry jsonEntry
	if err := json.Unmarshal(buf.Bytes(), &entry); err != nil {
		t.Fatalf("Custom formatter output not valid JSON: %v", err)
	}
	if entry.Message != "custom" {
		t.Errorf("Expected message 'custom', got %q", entry.Message)
	}
}
