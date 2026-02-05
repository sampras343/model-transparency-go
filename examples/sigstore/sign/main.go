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

// Example: Sign a model using Sigstore (keyless signing).
//
// This example demonstrates how to sign a model directory using Sigstore's
// keyless signing infrastructure. Sigstore uses OIDC for identity verification
// and records signatures in a transparency log.
//
// Authentication methods (in order of precedence):
//  1. SIGSTORE_ID_TOKEN environment variable (explicit OIDC token)
//  2. ACTIONS_ID_TOKEN_REQUEST_TOKEN (GitHub Actions ambient credentials)
//  3. Interactive OAuth flow (browser-based authentication)
//
// Usage:
//
//	go run ./examples/sigstore/sign/main.go \
//	    --model-path=/path/to/model \
//	    --signature-path=/path/to/model.sig
//
// With explicit OIDC token:
//
//	export SIGSTORE_ID_TOKEN='<your-oidc-token>'
//	go run ./examples/sigstore/sign/main.go \
//	    --model-path=/path/to/model \
//	    --signature-path=/path/to/model.sig \
//	    --use-ambient-credentials
//
// For testing (uses Sigstore staging infrastructure):
//
//	go run ./examples/sigstore/sign/main.go \
//	    --model-path=/path/to/model \
//	    --signature-path=/path/to/model.sig \
//	    --staging
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"

	"github.com/sigstore/model-signing/pkg/logging"
	sigstoreSigning "github.com/sigstore/model-signing/pkg/signing/sigstore"
)

func main() {
	// Define command-line flags
	modelPath := flag.String("model-path", "", "Path to the model directory to sign")
	signaturePath := flag.String("signature-path", "", "Path where the signature will be saved")
	useStaging := flag.Bool("staging", false, "Use Sigstore staging infrastructure (for testing)")
	useAmbientCredentials := flag.Bool("use-ambient-credentials", false, "Use ambient OIDC credentials (e.g., from SIGSTORE_ID_TOKEN)")
	ignoreGitPaths := flag.Bool("ignore-git-paths", true, "Ignore .git directories and .gitignore files")
	allowSymlinks := flag.Bool("allow-symlinks", false, "Allow following symlinks in the model directory")
	logLevel := flag.String("log-level", "debug", "Log level (debug, info, warn, error, silent)")
	flag.Parse()

	// Get values from flags or environment variables
	if *modelPath == "" {
		*modelPath = os.Getenv("MODEL_PATH")
	}
	if *signaturePath == "" {
		*signaturePath = os.Getenv("SIGNATURE_PATH")
	}

	// Demo mode: create a temporary model
	demoMode := *modelPath == ""
	if demoMode {
		fmt.Println("Running in demo mode...")

		// Create a temporary model directory
		tmpDir, err := os.MkdirTemp("", "model-signing-sigstore-example-*")
		if err != nil {
			log.Fatalf("Failed to create temp directory: %v", err)
		}

		// Create sample model files
		if err := os.WriteFile(filepath.Join(tmpDir, "model.bin"), []byte("sample model data\n"), 0644); err != nil {
			log.Fatalf("Failed to create model file: %v", err)
		}
		if err := os.WriteFile(filepath.Join(tmpDir, "config.json"), []byte(`{"version": "1.0"}`), 0644); err != nil {
			log.Fatalf("Failed to create config file: %v", err)
		}

		*modelPath = tmpDir
		*signaturePath = filepath.Join(tmpDir, "model.sig")
		*useStaging = true // Default to staging for demo mode

		defer func() {
			fmt.Printf("\nTo verify this signature, run:\n")
			fmt.Printf("  go run ./examples/sigstore/verify/main.go --model-path=%s --signature-path=%s --staging --identity=<your-email> --identity-provider=<oidc-provider>\n",
				tmpDir,
				filepath.Join(tmpDir, "model.sig"))
			fmt.Printf("\nNote: Replace <your-email> with the identity from your OIDC token\n")
			fmt.Printf("      Replace <oidc-provider> with your OIDC provider URL\n")
			fmt.Printf("      The demo model is at %s\n", tmpDir)
		}()
	}

	// Validate required parameters
	if *modelPath == "" {
		log.Fatal("--model-path is required")
	}
	if *signaturePath == "" {
		log.Fatal("--signature-path is required")
	}

	logger := logging.NewLoggerWithOptions(logging.LoggerOptions{
		Level: logging.ParseLogLevel(*logLevel),
	})

	// Create signer options
	opts := sigstoreSigning.SigstoreSignerOptions{
		ModelPath:             *modelPath,
		SignaturePath:         *signaturePath,
		UseStaging:            *useStaging,
		UseAmbientCredentials: *useAmbientCredentials,
		IgnorePaths:           nil,
		IgnoreGitPaths:        *ignoreGitPaths,
		AllowSymlinks:         *allowSymlinks,
		Logger:                logger,
	}

	// Create the signer
	signer, err := sigstoreSigning.NewSigstoreSigner(opts)
	if err != nil {
		log.Fatalf("Failed to create signer: %v", err)
	}

	// Sign the model
	ctx := context.Background()
	result, err := signer.Sign(ctx)
	if err != nil {
		log.Fatalf("Signing failed: %v\n\nHint: Set SIGSTORE_ID_TOKEN environment variable or run without --use-ambient-credentials for interactive OAuth", err)
	}

	fmt.Printf("\n%s\n", result.Message)
}
