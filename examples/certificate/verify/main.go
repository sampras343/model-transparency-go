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

// Example: Verify a model signature using a certificate chain.
//
// This example demonstrates how to verify a signed model using a certificate
// chain. The signature must be in Sigstore bundle format with X509 certificate
// chain verification material.
//
// Usage:
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
//	export CERT_CHAIN=/path/to/intermediate.pem,/path/to/root.pem
//	go run ./examples/certificate/verify/main.go
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"strings"

	certVerify "github.com/sigstore/model-signing/pkg/verify/certificate"
	"github.com/sigstore/model-signing/pkg/utils"
)

func main() {
	// Define command-line flags
	modelPath := flag.String("model-path", "", "Path to the model directory to verify")
	signaturePath := flag.String("signature-path", "", "Path to the signature file")
	certChain := flag.String("cert-chain", "", "Comma-separated paths to certificate chain files (intermediate, root)")
	ignoreGitPaths := flag.Bool("ignore-git-paths", true, "Ignore .git directories and .gitignore files")
	allowSymlinks := flag.Bool("allow-symlinks", false, "Allow following symlinks in the model directory")
	ignoreUnsignedFiles := flag.Bool("ignore-unsigned-files", false, "Ignore files not present in the signature")
	logFingerprints := flag.Bool("log-fingerprints", false, "Log certificate fingerprints during verification")
	verbose := flag.Bool("verbose", true, "Enable verbose output")
	flag.Parse()

	// Get values from flags or environment variables
	if *modelPath == "" {
		*modelPath = os.Getenv("MODEL_PATH")
	}
	if *signaturePath == "" {
		*signaturePath = os.Getenv("SIGNATURE_PATH")
	}
	if *certChain == "" {
		*certChain = os.Getenv("CERT_CHAIN")
	}

	// Parse certificate chain
	var chainPaths []string
	if *certChain != "" {
		chainPaths = strings.Split(*certChain, ",")
		for i := range chainPaths {
			chainPaths[i] = strings.TrimSpace(chainPaths[i])
		}
	}

	// Validate required parameters
	if *modelPath == "" {
		log.Fatal("--model-path is required")
	}
	if *signaturePath == "" {
		log.Fatal("--signature-path is required")
	}
	if len(chainPaths) == 0 {
		log.Fatal("--cert-chain is required")
	}

	logger := utils.NewLogger(*verbose)

	// Create verifier options
	opts := certVerify.CertificateVerifierOptions{
		ModelPath:           *modelPath,
		SignaturePath:       *signaturePath,
		CertificateChain:    chainPaths,
		IgnorePaths:         nil,
		IgnoreGitPaths:      *ignoreGitPaths,
		AllowSymlinks:       *allowSymlinks,
		IgnoreUnsignedFiles: *ignoreUnsignedFiles,
		LogFingerprints:     *logFingerprints,
		Logger:              logger,
	}

	// Create the verifier
	verifier, err := certVerify.NewCertificateVerifier(opts)
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
