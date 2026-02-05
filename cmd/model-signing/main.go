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

// Package main provides the entry point for the model-signing CLI application.
// It handles command execution and error processing with appropriate exit codes.
package main

import (
	"context"
	"errors"
	"log"
	"os"
	"time"

	"github.com/sigstore/model-signing/cmd/model-signing/cli"
	"github.com/sigstore/model-signing/pkg/tracing"
)

// ExitCoder represents an error that carries a specific exit code.
// It extends the error interface to provide custom exit code information
// for different error conditions.
type ExitCoder interface {
	error
	// ExitCode returns the exit code that should be used when this error occurs.
	ExitCode() int
}

func main() {
	log.SetFlags(0)

	if err := tracing.InitFromEnv(); err != nil {
		log.Printf("tracing initialization failed: %v", err)
		os.Exit(1)
	}
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := tracing.Shutdown(ctx); err != nil {
			log.Printf("tracing shutdown: %v", err)
		}
	}()

	if err := cli.New().Execute(); err != nil {
		var ec ExitCoder
		if errors.As(err, &ec) {
			log.Printf("error during command execution: %v", err)
			os.Exit(ec.ExitCode()) // nolint:gocritic
		}

		log.Fatalf("error during command execution: %v", err)
	}
}
