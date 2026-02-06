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

// Example: Sign a model using a certificate and private key.
//
// This example demonstrates how to sign a model directory using a private key
// along with a signing certificate and certificate chain. The signature includes
// the full certificate chain for verification.
//
// Usage:
//
//	go run ./examples/certificate/sign/main.go \
//	    --model-path=/path/to/model \
//	    --signature-path=/path/to/model.sig \
//	    --private-key=/path/to/private-key.pem \
//	    --signing-cert=/path/to/signing-cert.pem \
//	    --cert-chain=/path/to/intermediate.pem,/path/to/root.pem
//
// Or using environment variables:
//
//	export MODEL_PATH=/path/to/model
//	export SIGNATURE_PATH=/path/to/model.sig
//	export PRIVATE_KEY=/path/to/private-key.pem
//	export SIGNING_CERT=/path/to/signing-cert.pem
//	export CERT_CHAIN=/path/to/intermediate.pem,/path/to/root.pem
//	go run ./examples/certificate/sign/main.go
//
// Demo mode (uses test certificates from the repository):
//
//	go run ./examples/certificate/sign/main.go
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/sigstore/model-signing/pkg/logging"
	certSigning "github.com/sigstore/model-signing/pkg/signing/certificate"
)

func main() {
	// Define command-line flags
	modelPath := flag.String("model-path", "", "Path to the model directory to sign")
	signaturePath := flag.String("signature-path", "", "Path where the signature will be saved")
	privateKeyPath := flag.String("private-key", "", "Path to the PEM-encoded private key")
	signingCertPath := flag.String("signing-cert", "", "Path to the PEM-encoded signing certificate")
	certChain := flag.String("cert-chain", "", "Comma-separated paths to certificate chain files (intermediate, root)")
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
	if *privateKeyPath == "" {
		*privateKeyPath = os.Getenv("PRIVATE_KEY")
	}
	if *signingCertPath == "" {
		*signingCertPath = os.Getenv("SIGNING_CERT")
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

	// Demo mode: use test certificates and create a temporary model
	demoMode := *modelPath == "" && *privateKeyPath == ""
	if demoMode {
		fmt.Println("Running in demo mode with test certificates...")
		repoRoot := findRepoRoot()
		certDir := filepath.Join(repoRoot, "scripts", "tests", "keys", "certificate")
		*privateKeyPath = filepath.Join(certDir, "signing-key.pem")
		*signingCertPath = filepath.Join(certDir, "signing-key-cert.pem")
		chainPaths = []string{
			filepath.Join(certDir, "int-ca-cert.pem"),
			filepath.Join(certDir, "ca-cert.pem"),
		}

		// Create a temporary model directory
		tmpDir, err := os.MkdirTemp("", "model-signing-cert-example-*")
		if err != nil {
			log.Fatalf("Failed to create temp directory: %v", err)
		}
		defer func() {
			fmt.Printf("\nTo verify this signature, run:\n")
			fmt.Printf("  go run ./examples/highlevel/certificate/verify/main.go --model-path=%s --signature-path=%s --cert-chain=%s,%s\n",
				tmpDir,
				filepath.Join(tmpDir, "model.sig"),
				filepath.Join(certDir, "int-ca-cert.pem"),
				filepath.Join(certDir, "ca-cert.pem"))
			fmt.Printf("\nNote: The demo model is at %s\n", tmpDir)
		}()

		// Create sample model files
		if err := os.WriteFile(filepath.Join(tmpDir, "model.bin"), []byte("sample model data\n"), 0644); err != nil {
			log.Fatalf("Failed to create model file: %v", err)
		}
		if err := os.WriteFile(filepath.Join(tmpDir, "config.json"), []byte(`{"version": "1.0"}`), 0644); err != nil {
			log.Fatalf("Failed to create config file: %v", err)
		}

		*modelPath = tmpDir
		*signaturePath = filepath.Join(tmpDir, "model.sig")
	}

	// Validate required parameters
	if *modelPath == "" {
		log.Fatal("--model-path is required")
	}
	if *signaturePath == "" {
		log.Fatal("--signature-path is required")
	}
	if *privateKeyPath == "" {
		log.Fatal("--private-key is required")
	}
	if *signingCertPath == "" {
		log.Fatal("--signing-cert is required")
	}

	logger := logging.NewLoggerWithOptions(logging.LoggerOptions{
		Level: logging.ParseLogLevel(*logLevel),
	})

	// Create signer options
	opts := certSigning.CertificateSignerOptions{
		ModelPath:              *modelPath,
		SignaturePath:          *signaturePath,
		PrivateKeyPath:         *privateKeyPath,
		SigningCertificatePath: *signingCertPath,
		CertificateChain:       chainPaths,
		IgnorePaths:            nil,
		IgnoreGitPaths:         *ignoreGitPaths,
		AllowSymlinks:          *allowSymlinks,
		Logger:                 logger,
	}

	// Create the signer
	signer, err := certSigning.NewCertificateSigner(opts)
	if err != nil {
		log.Fatalf("Failed to create signer: %v", err)
	}

	// Sign the model
	ctx := context.Background()
	result, err := signer.Sign(ctx)
	if err != nil {
		log.Fatalf("Signing failed: %v", err)
	}

	fmt.Printf("\n%s\n", result.Message)
}

func findRepoRoot() string {
	dir, err := os.Getwd()
	if err != nil {
		return "."
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "."
		}
		dir = parent
	}
}
