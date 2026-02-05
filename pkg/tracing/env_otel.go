//go:build otel

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

// When built with -tags=otel, this file provides OpenTelemetry initialization
// from environment variables (e.g. OTEL_EXPORTER_OTLP_ENDPOINT,
// OTEL_SERVICE_NAME, OTEL_TRACES_EXPORTER).

package tracing

import (
	"context"
	"fmt"
	"os"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.24.0"
	"go.opentelemetry.io/otel/trace"
)

// Default OTLP HTTP endpoint when no endpoint env vars are set (e.g. local Jaeger).
const defaultOTLPEndpoint = "http://localhost:4318"

// InitFromEnv initializes OpenTelemetry when the binary is built with -tags=otel.
// If OTEL_TRACES_EXPORTER is "none", no tracer is configured. Otherwise the OTLP
// HTTP exporter is used: OTEL_EXPORTER_OTLP_ENDPOINT or
// OTEL_EXPORTER_OTLP_TRACES_ENDPOINT if set, else defaultOTLPEndpoint so local
// testing (e.g. Jaeger in Docker on 4318) works without env vars. If initialization
// fails, returns an error (caller should log and exit).
func InitFromEnv() error {
	if os.Getenv("OTEL_TRACES_EXPORTER") == "none" {
		return nil
	}

	// Ensure an endpoint is set so the exporter actually runs (otlptracehttp
	// reads OTEL_EXPORTER_OTLP_ENDPOINT; default is localhost:4318, but we only
	// init when we want to export, so set it explicitly if unset for local use).
	if os.Getenv("OTEL_EXPORTER_OTLP_ENDPOINT") == "" && os.Getenv("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT") == "" {
		_ = os.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", defaultOTLPEndpoint)
	}

	ctx := context.Background()
	opts := []otlptracehttp.Option{}
	if os.Getenv("OTEL_EXPORTER_OTLP_ENDPOINT") == defaultOTLPEndpoint {
		opts = append(opts, otlptracehttp.WithInsecure())
	}
	exp, err := otlptracehttp.New(ctx, opts...)
	if err != nil {
		return err
	}

	serviceName := os.Getenv("OTEL_SERVICE_NAME")
	if serviceName == "" {
		serviceName = "model-signing"
	}

	tp := sdktrace.NewTracerProvider(
		sdktrace.WithBatcher(exp),
		sdktrace.WithResource(resource.NewWithAttributes(
			semconv.SchemaURL,
			semconv.ServiceName(serviceName),
		)),
	)
	otelTracerProvider = tp
	otel.SetTracerProvider(tp)

	SetTracer(&otelTracer{tracer: tp.Tracer("github.com/sigstore/model-signing")})
	return nil
}

// otelTracerProvider is the SDK TracerProvider created when OTel is enabled.
// It is stored so Shutdown can flush and close it before process exit.
var otelTracerProvider *sdktrace.TracerProvider

// Shutdown flushes and shuts down the OTLP tracer provider so batched spans
// are sent to the backend before the process exits. Call this (e.g. via defer
// in main) when built with -tags=otel; otherwise it is a no-op. Use a context
// with timeout (e.g. 5–10 seconds) to avoid blocking forever.
func Shutdown(ctx context.Context) error {
	if otelTracerProvider == nil {
		return nil
	}
	tp := otelTracerProvider
	otelTracerProvider = nil
	return tp.Shutdown(ctx)
}

// otelTracer adapts go.opentelemetry.io/otel/trace.Tracer to our Tracer interface.
type otelTracer struct {
	tracer trace.Tracer
}

func (t *otelTracer) Start(ctx context.Context, name string) (context.Context, Span) {
	ctx, span := t.tracer.Start(ctx, name)
	return ctx, &otelSpan{span: span}
}

// otelSpan adapts an OpenTelemetry span to our Span interface.
type otelSpan struct {
	span trace.Span
}

func (s *otelSpan) SetAttribute(key string, value interface{}) {
	s.span.SetAttributes(toKeyValue(key, value))
}

func (s *otelSpan) End() {
	s.span.End()
}

func toKeyValue(key string, value interface{}) attribute.KeyValue {
	k := attribute.Key(key)
	switch v := value.(type) {
	case string:
		return k.String(v)
	case bool:
		return k.Bool(v)
	case int:
		return k.Int(v)
	case int64:
		return k.Int64(v)
	default:
		return k.String(stringify(v))
	}
}

func stringify(v interface{}) string {
	if v == nil {
		return ""
	}
	return fmt.Sprintf("%v", v)
}
