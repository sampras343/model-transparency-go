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

// Package logging provides a structured, leveled logging interface for
// model-transparency-go. It defines a Logger interface that can be implemented
// by any logging backend (the built-in DefaultLogger, slog, zap, logr,
// OpenTelemetry, etc.) and a Formatter interface for extensible output formats.
package logging

import "strings"

// LogLevel represents the severity level of a log message.
type LogLevel int

const (
	// LevelDebug is the most verbose level, used for detailed debugging information.
	LevelDebug LogLevel = iota
	// LevelInfo is used for general informational messages.
	LevelInfo
	// LevelWarn is used for warning messages that indicate potential issues.
	LevelWarn
	// LevelError is used for error messages indicating failures.
	LevelError
	// LevelSilent disables all logging output.
	LevelSilent
)

// String returns the string representation of a log level.
func (l LogLevel) String() string {
	switch l {
	case LevelDebug:
		return "debug"
	case LevelInfo:
		return "info"
	case LevelWarn:
		return "warn"
	case LevelError:
		return "error"
	case LevelSilent:
		return "silent"
	default:
		return "unknown"
	}
}

// ParseLogLevel parses a string into a LogLevel.
// Returns LevelInfo if the string is not recognized.
func ParseLogLevel(s string) LogLevel {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "debug":
		return LevelDebug
	case "info":
		return LevelInfo
	case "warn", "warning":
		return LevelWarn
	case "error":
		return LevelError
	case "silent", "none", "off":
		return LevelSilent
	default:
		return LevelInfo
	}
}

// LogFormat represents the output format for log messages.
type LogFormat int

const (
	// FormatText outputs human-readable text logs.
	FormatText LogFormat = iota
	// FormatJSON outputs structured JSON logs.
	FormatJSON
)

// String returns the string representation of a log format.
func (f LogFormat) String() string {
	switch f {
	case FormatText:
		return "text"
	case FormatJSON:
		return "json"
	default:
		return "unknown"
	}
}

// ParseLogFormat parses a string into a LogFormat.
// Returns FormatText if the string is not recognized.
func ParseLogFormat(s string) LogFormat {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "json":
		return FormatJSON
	case "text", "plain":
		return FormatText
	default:
		return FormatText
	}
}

// Logger defines the interface for structured logging.
//
// This interface provides leveled logging (Debug, Info, Warn, Error) with
// both format-string and line-based variants, plus structured field support.
//
// Implementations include the built-in DefaultLogger (text and JSON output)
// and can be extended with adapters for slog, zap, logr, OpenTelemetry, or
// other backends.
type Logger interface {
	// Debug logs a message at debug level with printf-style formatting.
	Debug(format string, args ...interface{})
	// Debugln logs a message at debug level.
	Debugln(msg string)
	// Info logs a message at info level with printf-style formatting.
	Info(format string, args ...interface{})
	// Infoln logs a message at info level.
	Infoln(msg string)
	// Warn logs a message at warn level with printf-style formatting.
	Warn(format string, args ...interface{})
	// Warnln logs a message at warn level.
	Warnln(msg string)
	// Error logs a message at error level with printf-style formatting.
	Error(format string, args ...interface{})
	// Errorln logs a message at error level.
	Errorln(msg string)

	// GetLevel returns the current minimum log level.
	GetLevel() LogLevel
	// Silent returns true if the logger suppresses debug output.
	Silent() bool

	// WithField returns a new Logger with the given key-value pair added.
	WithField(key string, value interface{}) Logger
	// WithFields returns a new Logger with the given fields added.
	WithFields(fields map[string]interface{}) Logger
}

// Default returns a new Logger with info-level logging (non-verbose).
func Default() Logger {
	return NewLogger(false)
}

// EnsureLogger returns l if non-nil, otherwise returns a default logger.
// Use this to provide a fallback when no logger is configured.
func EnsureLogger(l Logger) Logger {
	if l == nil {
		return Default()
	}
	return l
}
