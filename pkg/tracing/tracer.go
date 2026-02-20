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

// Package tracing provides an abstraction for distributed tracing. By default
// a no-op tracer is used; when built with the "otel" build tag and
// OpenTelemetry is configured via environment variables, spans are exported
// via OTLP. This keeps the default build free of OpenTelemetry dependencies
// while allowing optional tracing.
//
// Tracing records spans: named, timed operations that form a trace (a tree of
// spans). Each span has a start/end time (so duration is visible in the
// backend), optional attributes (key-value metadata), and can have parent/child
// links. So tracing is not "just setting attributes along the way"—it is
// structured around spans; attributes are metadata on those spans. Use Run or
// Start to create spans and SetAttribute to add metadata.
package tracing

import "context"

// Span represents a single operation in a trace. Call End when the operation
// completes. SetAttribute can be used to add key-value attributes.
type Span interface {
	// SetAttribute sets a key-value attribute on the span.
	SetAttribute(key string, value interface{})
	// End marks the span as finished.
	End()
}

// Tracer creates spans for named operations. When OpenTelemetry is not
// available or not configured, a no-op implementation is used so callers
// can always use the same API.
type Tracer interface {
	// Start starts a new span with the given name. The returned context
	// should be used for downstream calls; the span must be ended with End().
	Start(ctx context.Context, name string) (context.Context, Span)
}

var globalTracer Tracer = NoopTracer{}

// SetTracer sets the global tracer used by Start. It is typically called
// once at startup after InitFromEnv. If nil is passed, the no-op tracer
// is used.
func SetTracer(t Tracer) {
	if t == nil {
		globalTracer = NoopTracer{}
		return
	}
	globalTracer = t
}

// Tracer returns the current global tracer (never nil).
func GetTracer() Tracer {
	return globalTracer
}

// Start starts a new span with the given name using the global tracer.
// Returns the context to pass to child operations and the span to end.
func Start(ctx context.Context, name string) (context.Context, Span) {
	return globalTracer.Start(ctx, name)
}

// Enabled returns true when a real (non-noop) tracer is configured.
// In the default build (without -tags=otel), this always returns false.
func Enabled() bool {
	_, noop := globalTracer.(NoopTracer)
	return !noop
}

// Run starts a span with the given name and attributes, runs fn with the
// span's context, ends the span, and returns the result of fn. This
// centralizes span lifecycle (start, set attributes, defer End) so callers
// do not scatter span logic. If attrs is nil, no attributes are set.
// When no real tracer is configured (default build), fn is called directly
// with no tracing overhead.
func Run(ctx context.Context, name string, attrs map[string]interface{}, fn func(context.Context) error) error {
	if !Enabled() {
		return fn(ctx)
	}
	ctx, span := globalTracer.Start(ctx, name)
	defer span.End()
	for k, v := range attrs {
		span.SetAttribute(k, v)
	}
	return fn(ctx)
}
