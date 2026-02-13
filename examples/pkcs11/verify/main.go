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

// Example: Verify a PKCS#11-signed model signature.
//
// This example demonstrates how to verify a model signed with a PKCS#11 private key.
// For key-based signatures, the public key must be exported from the PKCS#11 token.
// For certificate-based signatures, use the certificate verifier.
//
// Verify key-based PKCS#11 signature:
//
//	# First, export the public key from PKCS#11
//	./scripts/tests/softhsm_setup getpubkey > /tmp/pubkey.pem
//
//	# Then verify
//	go run ./examples/pkcs11/verify/main.go \
//	    --model-path=/path/to/model \
//	    --signature-path=/path/to/model.sig \
//	    --public-key=/tmp/pubkey.pem
//
// Verify certificate-based PKCS#11 signature:
//
//	go run ./examples/certificate/verify/main.go \
//	    --model-path=/path/to/model \
//	    --signature-path=/path/to/model.sig \
//	    --cert-chain=/path/to/intermediate.pem,/path/to/root.pem
//
// Or using environment variables:
//
//	export MODEL_PATH=/path/to/model
//	export SIGNATURE_PATH=/path/to/model.sig
//	export PUBLIC_KEY=/tmp/pubkey.pem
//	go run ./examples/pkcs11/verify/main.go
//
// Note: PKCS#11 verification does not require access to the HSM/token.
// The public key or certificate embedded in the signature is sufficient.
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
	publicKeyPath := flag.String("public-key", "", "Path to the PEM-encoded public key (exported from PKCS#11)")
	ignoreGitPaths := flag.Bool("ignore-git-paths", true, "Ignore .git directories and .gitignore files")
	allowSymlinks := flag.Bool("allow-symlinks", false, "Allow following symlinks in the model directory")
	ignoreUnsignedFiles := flag.Bool("ignore-unsigned-files", false, "Ignore files not present in the signature")
	verbose := flag.Bool("verbose", true, "Enable verbose output")
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
		fmt.Println("INFO: --public-key not provided")
		fmt.Println("\nFor PKCS#11-signed models, you need to export the public key:")
		fmt.Println("  ./scripts/tests/softhsm_setup getpubkey > /tmp/pubkey.pem")
		fmt.Println("\nThen verify with:")
		fmt.Println("  go run ./examples/pkcs11/verify/main.go \\")
		fmt.Println("      --model-path=<path> \\")
		fmt.Println("      --signature-path=<sig-path> \\")
		fmt.Println("      --public-key=/tmp/pubkey.pem")
		fmt.Println("\nFor certificate-based signatures, use:")
		fmt.Println("  go run ./examples/certificate/verify/main.go --cert-chain=<chain>")
		log.Fatal("\n--public-key is required")
	}

	logger := logging.NewLogger(*verbose)

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
	fmt.Println("\n✓ PKCS#11 signature verified successfully!")
}
