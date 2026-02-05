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

package tracing

import "context"

// NoopSpan is a span that does nothing. Used when OpenTelemetry is not
// configured or not built in.
type NoopSpan struct{}

// SetAttribute is a no-op.
func (NoopSpan) SetAttribute(string, interface{}) {}

// End is a no-op.
func (NoopSpan) End() {}

// NoopTracer is a tracer that creates no-op spans. The rest of the code
// can always call tracer.Start(...) and span.SetAttribute(...) whether
// or not OpenTelemetry is available.
type NoopTracer struct{}

// Start returns the same context and a no-op span.
func (NoopTracer) Start(ctx context.Context, name string) (context.Context, Span) {
	return ctx, NoopSpan{}
}
