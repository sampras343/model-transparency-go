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

// Example: Verify a model signature using a public key.
//
// This example demonstrates how to verify a signed model using an ECDSA, RSA,
// or Ed25519 public key. The signature must be in Sigstore bundle format.
//
// Usage:
//
//	go run ./examples/key/verify/main.go \
//	    --model-path=/path/to/model \
//	    --signature-path=/path/to/model.sig \
//	    --public-key=/path/to/public-key.pem
//
// Or using environment variables:
//
//	export MODEL_PATH=/path/to/model
//	export SIGNATURE_PATH=/path/to/model.sig
//	export PUBLIC_KEY=/path/to/public-key.pem
//	go run ./examples/key/verify/main.go
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/sigstore/model-signing/pkg/logging"
	keyVerify "github.com/sigstore/model-signing/pkg/verify/key"
)

func main() {
	// Define command-line flags
	modelPath := flag.String("model-path", "", "Path to the model directory to verify")
	signaturePath := flag.String("signature-path", "", "Path to the signature file")
	publicKeyPath := flag.String("public-key", "", "Path to the PEM-encoded public key")
	ignoreGitPaths := flag.Bool("ignore-git-paths", true, "Ignore .git directories and .gitignore files")
	allowSymlinks := flag.Bool("allow-symlinks", false, "Allow following symlinks in the model directory")
	ignoreUnsignedFiles := flag.Bool("ignore-unsigned-files", false, "Ignore files not present in the signature")
	logLevel := flag.String("log-level", "debug", "Log level (debug, info, warn, error, silent)")
	flag.Parse()

	// Get values from flags or environment variables
	if *modelPath == "" {
		*modelPath = os.Getenv("MODEL_PATH")
	}
	if *signaturePath == "" {
		*signaturePath = os.Getenv("SIGNATURE_PATH")
	}
	if *publicKeyPath == "" {
		*publicKeyPath = os.Getenv("PUBLIC_KEY")
	}

	// Validate required parameters
	if *modelPath == "" {
		log.Fatal("--model-path is required")
	}
	if *signaturePath == "" {
		log.Fatal("--signature-path is required")
	}
	if *publicKeyPath == "" {
		log.Fatal("--public-key is required")
	}

	logger := logging.NewLoggerWithOptions(logging.LoggerOptions{
		Level: logging.ParseLogLevel(*logLevel),
	})

	// Create verifier options
	opts := keyVerify.KeyVerifierOptions{
		ModelPath:           *modelPath,
		SignaturePath:       *signaturePath,
		PublicKeyPath:       *publicKeyPath,
		IgnorePaths:         nil,
		IgnoreGitPaths:      *ignoreGitPaths,
		AllowSymlinks:       *allowSymlinks,
		IgnoreUnsignedFiles: *ignoreUnsignedFiles,
		Logger:              logger,
	}

	// Create the verifier
	verifier, err := keyVerify.NewKeyVerifier(opts)
	if err != nil {
		log.Fatalf("Failed to create verifier: %v", err)
	}

	// Verify the model
	ctx := context.Background()
	result, err := verifier.Verify(ctx)
	if err != nil {
		log.Fatalf("Verification failed: %v", err)
	}

	fmt.Printf("\n%s\n", result.Message)
}
