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
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// LogEntry represents a structured log entry passed to formatters.
type LogEntry struct {
	// Timestamp is the time the log entry was created.
	Timestamp time.Time
	// Level is the severity level of the log entry.
	Level LogLevel
	// Message is the log message.
	Message string
	// Fields contains structured key-value pairs attached to the entry.
	Fields map[string]interface{}
}

// Formatter formats a LogEntry into bytes for output.
//
// Implementations control how log entries are rendered. Built-in formatters
// include TextFormatter and JSONFormatter. Custom formatters can be created
// for specialized output (e.g., logfmt, OpenTelemetry-compatible formats).
type Formatter interface {
	Format(entry LogEntry) ([]byte, error)
}

// TextFormatter outputs human-readable text logs.
type TextFormatter struct {
	// TimeFormat sets the time format string. Empty disables timestamps.
	TimeFormat string
	// ShowLevel controls whether to show the log level prefix (e.g., [INFO]).
	ShowLevel bool
}

// Format formats a log entry as human-readable text.
func (f *TextFormatter) Format(entry LogEntry) ([]byte, error) {
	var parts []string

	if f.TimeFormat != "" {
		parts = append(parts, entry.Timestamp.Format(f.TimeFormat))
	}

	if f.ShowLevel {
		parts = append(parts, fmt.Sprintf("[%s]", strings.ToUpper(entry.Level.String())))
	}

	parts = append(parts, entry.Message)

	if len(entry.Fields) > 0 {
		var fieldParts []string
		for k, v := range entry.Fields {
			fieldParts = append(fieldParts, fmt.Sprintf("%s=%v", k, v))
		}
		parts = append(parts, fmt.Sprintf("{%s}", strings.Join(fieldParts, ", ")))
	}

	return []byte(strings.Join(parts, " ") + "\n"), nil
}

// jsonEntry is the serialization format for JSON log output.
type jsonEntry struct {
	Timestamp string                 `json:"timestamp,omitempty"`
	Level     string                 `json:"level"`
	Message   string                 `json:"message"`
	Fields    map[string]interface{} `json:"fields,omitempty"`
}

// JSONFormatter outputs structured JSON logs.
type JSONFormatter struct {
	// TimeFormat sets the time format string. Defaults to time.RFC3339.
	TimeFormat string
}

// Format formats a log entry as a JSON object.
func (f *JSONFormatter) Format(entry LogEntry) ([]byte, error) {
	je := jsonEntry{
		Level:   entry.Level.String(),
		Message: entry.Message,
	}

	timeFmt := f.TimeFormat
	if timeFmt == "" {
		timeFmt = time.RFC3339
	}
	je.Timestamp = entry.Timestamp.Format(timeFmt)

	if len(entry.Fields) > 0 {
		je.Fields = entry.Fields
	}

	data, err := json.Marshal(je)
	if err != nil {
		fallback := fmt.Sprintf(`{"level":"%s","message":%q,"error":"json marshal failed"}`+"\n",
			entry.Level.String(), entry.Message)
		return []byte(fallback), nil
	}

	return append(data, '\n'), nil
}
