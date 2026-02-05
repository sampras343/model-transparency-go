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
	"fmt"
	"io"
	"os"
	"sync"
	"time"
)

// Verify DefaultLogger implements Logger at compile time.
var _ Logger = (*DefaultLogger)(nil)

// LoggerOptions configures a DefaultLogger instance.
type LoggerOptions struct {
	// Level sets the minimum log level to output.
	Level LogLevel
	// Format selects the output format (FormatText or FormatJSON).
	// Ignored if Formatter is set.
	Format LogFormat
	// Formatter sets a custom formatter for log output.
	// If nil, a formatter is derived from Format, TimeFormat, and ShowLevel.
	Formatter Formatter
	// Output sets the io.Writer for log output. Defaults to os.Stdout.
	Output io.Writer
	// TimeFormat sets the time format for text logs. Defaults to empty (no timestamp).
	// Only used when Formatter is nil.
	TimeFormat string
	// ShowLevel controls whether to show the log level in text output.
	// Only used when Formatter is nil.
	ShowLevel bool
}

// DefaultLoggerOptions returns the default logger options.
func DefaultLoggerOptions() LoggerOptions {
	return LoggerOptions{
		Level:      LevelInfo,
		Format:     FormatText,
		Output:     os.Stdout,
		TimeFormat: "",
		ShowLevel:  false,
	}
}

// DefaultLogger provides a structured logging implementation with configurable
// levels and pluggable formatters.
type DefaultLogger struct {
	mu        sync.Mutex
	level     LogLevel
	formatter Formatter
	out       io.Writer
	fields    map[string]interface{}
}

// NewLogger creates a new DefaultLogger with the specified verbosity.
// If verbose is true, the level is set to LevelDebug; otherwise LevelInfo.
// This function maintains backward compatibility with the previous API.
func NewLogger(verbose bool) *DefaultLogger {
	level := LevelInfo
	if verbose {
		level = LevelDebug
	}
	return &DefaultLogger{
		level:     level,
		formatter: &TextFormatter{},
		out:       os.Stdout,
	}
}

// NewLoggerWithOptions creates a new DefaultLogger with the specified options.
func NewLoggerWithOptions(opts LoggerOptions) *DefaultLogger {
	out := opts.Output
	if out == nil {
		out = os.Stdout
	}

	var formatter Formatter
	if opts.Formatter != nil {
		formatter = opts.Formatter
	} else {
		switch opts.Format {
		case FormatJSON:
			formatter = &JSONFormatter{TimeFormat: opts.TimeFormat}
		default:
			formatter = &TextFormatter{
				TimeFormat: opts.TimeFormat,
				ShowLevel:  opts.ShowLevel,
			}
		}
	}

	return &DefaultLogger{
		level:     opts.Level,
		formatter: formatter,
		out:       out,
	}
}

// WithFields returns a new Logger with the given fields added to all log entries.
// The original logger is not modified.
func (l *DefaultLogger) WithFields(fields map[string]interface{}) Logger {
	l.mu.Lock()
	defer l.mu.Unlock()

	merged := make(map[string]interface{})
	for k, v := range l.fields {
		merged[k] = v
	}
	for k, v := range fields {
		merged[k] = v
	}

	return &DefaultLogger{
		level:     l.level,
		formatter: l.formatter,
		out:       l.out,
		fields:    merged,
	}
}

// WithField returns a new Logger with the given field added to all log entries.
func (l *DefaultLogger) WithField(key string, value interface{}) Logger {
	return l.WithFields(map[string]interface{}{key: value})
}

// SetLevel sets the minimum log level.
func (l *DefaultLogger) SetLevel(level LogLevel) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.level = level
}

// GetLevel returns the current log level.
func (l *DefaultLogger) GetLevel() LogLevel {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.level
}

// SetFormatter sets a custom formatter.
func (l *DefaultLogger) SetFormatter(f Formatter) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.formatter = f
}

// GetFormatter returns the current formatter.
func (l *DefaultLogger) GetFormatter() Formatter {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.formatter
}

// SetOutput sets the output writer.
func (l *DefaultLogger) SetOutput(w io.Writer) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.out = w
}

// log writes a log message at the given level.
func (l *DefaultLogger) log(level LogLevel, format string, args ...interface{}) {
	l.mu.Lock()
	defer l.mu.Unlock()

	if level < l.level {
		return
	}

	entry := LogEntry{
		Timestamp: time.Now(),
		Level:     level,
		Message:   fmt.Sprintf(format, args...),
		Fields:    l.fields,
	}

	data, err := l.formatter.Format(entry)
	if err != nil {
		fmt.Fprintf(l.out, "logging error: %v\n", err)
		return
	}

	_, _ = l.out.Write(data)
}

// Debug logs a message at debug level.
func (l *DefaultLogger) Debug(format string, args ...interface{}) {
	l.log(LevelDebug, format, args...)
}

// Debugln logs a line at debug level.
func (l *DefaultLogger) Debugln(msg string) {
	l.log(LevelDebug, "%s", msg)
}

// Info logs a message at info level.
func (l *DefaultLogger) Info(format string, args ...interface{}) {
	l.log(LevelInfo, format, args...)
}

// Infoln logs a line at info level.
func (l *DefaultLogger) Infoln(msg string) {
	l.log(LevelInfo, "%s", msg)
}

// Warn logs a message at warn level.
func (l *DefaultLogger) Warn(format string, args ...interface{}) {
	l.log(LevelWarn, format, args...)
}

// Warnln logs a line at warn level.
func (l *DefaultLogger) Warnln(msg string) {
	l.log(LevelWarn, "%s", msg)
}

// Error logs a message at error level.
func (l *DefaultLogger) Error(format string, args ...interface{}) {
	l.log(LevelError, format, args...)
}

// Errorln logs a line at error level.
func (l *DefaultLogger) Errorln(msg string) {
	l.log(LevelError, "%s", msg)
}

// Silent returns true if the logger suppresses debug output (level > LevelDebug).
// Maintains backward compatibility with the previous API.
func (l *DefaultLogger) Silent() bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.level > LevelDebug
}

// IsLevelEnabled returns true if the given level would produce output.
func (l *DefaultLogger) IsLevelEnabled(level LogLevel) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	return level >= l.level
}
