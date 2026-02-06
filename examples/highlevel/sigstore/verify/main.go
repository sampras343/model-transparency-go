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

// Example: Verify a model signature using Sigstore.
//
// This example demonstrates how to verify a model signed with Sigstore's
// keyless signing infrastructure. Verification requires specifying the
// expected signer identity and OIDC identity provider.
//
// Usage:
//
//	go run ./examples/highlevel/sigstore/verify/main.go \
//	    --model-path=/path/to/model \
//	    --signature-path=/path/to/model.sig \
//	    --identity=signer@example.com \
//	    --identity-provider=https://accounts.google.com
//
// For signatures created with staging infrastructure:
//
//	go run ./examples/highlevel/sigstore/verify/main.go \
//	    --model-path=/path/to/model \
//	    --signature-path=/path/to/model.sig \
//	    --identity=signer@example.com \
//	    --identity-provider=https://accounts.google.com \
//	    --staging
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/sigstore/model-signing/pkg/logging"
	sigstoreVerify "github.com/sigstore/model-signing/pkg/verify/sigstore"
)

func main() {
	// Define command-line flags
	modelPath := flag.String("model-path", "", "Path to the model directory to verify")
	signaturePath := flag.String("signature-path", "", "Path to the signature file")
	identity := flag.String("identity", "", "Expected signer identity (e.g., email address)")
	identityProvider := flag.String("identity-provider", "", "Expected OIDC identity provider URL (e.g., https://accounts.google.com)")
	useStaging := flag.Bool("staging", false, "Use Sigstore staging infrastructure (for testing)")
	trustRootPath := flag.String("trust-root", "", "Path to custom trust root JSON file (optional)")
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
	if *identity == "" {
		*identity = os.Getenv("SIGNER_IDENTITY")
	}
	if *identityProvider == "" {
		*identityProvider = os.Getenv("IDENTITY_PROVIDER")
	}
	if *trustRootPath == "" {
		*trustRootPath = os.Getenv("TRUST_CONFIG")
	}

	// Validate required parameters
	if *modelPath == "" {
		log.Fatal("--model-path is required")
	}
	if *signaturePath == "" {
		log.Fatal("--signature-path is required")
	}
	if *identity == "" {
		log.Fatal("--identity is required (the expected signer identity, e.g., email)")
	}
	if *identityProvider == "" {
		log.Fatal("--identity-provider is required (the expected OIDC identity provider URL)")
	}

	logger := logging.NewLoggerWithOptions(logging.LoggerOptions{
		Level: logging.ParseLogLevel(*logLevel),
	})

	// Create verifier options
	opts := sigstoreVerify.SigstoreVerifierOptions{
		ModelPath:           *modelPath,
		SignaturePath:       *signaturePath,
		Identity:            *identity,
		IdentityProvider:    *identityProvider,
		UseStaging:          *useStaging,
		TrustConfigPath:     *trustRootPath,
		IgnorePaths:         nil,
		IgnoreGitPaths:      *ignoreGitPaths,
		AllowSymlinks:       *allowSymlinks,
		IgnoreUnsignedFiles: *ignoreUnsignedFiles,
		Logger:              logger,
	}

	// Create the verifier
	verifier, err := sigstoreVerify.NewSigstoreVerifier(opts)
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
