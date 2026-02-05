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

//go:build !otel

// This file provides the default InitFromEnv and Shutdown that do nothing.
// When the package is built with -tags=otel, env_otel.go is compiled instead.

package tracing

import "context"

// InitFromEnv initializes tracing from environment variables. In the default
// build (without the "otel" build tag), this is a no-op and returns nil.
func InitFromEnv() error {
	return nil
}

// Shutdown flushes and shuts down the tracer provider. In the default build
// (without the "otel" build tag), this is a no-op and returns nil.
func Shutdown(context.Context) error {
	return nil
}
