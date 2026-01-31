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

// Example: Sign a model using a private key.
//
// This example demonstrates how to sign a model directory using an ECDSA, RSA,
// or Ed25519 private key. The signature is saved in Sigstore bundle format.
//
// Usage:
//
//	go run ./examples/key/sign/main.go \
//	    --model-path=/path/to/model \
//	    --signature-path=/path/to/model.sig \
//	    --private-key=/path/to/private-key.pem
//
// Or using environment variables:
//
//	export MODEL_PATH=/path/to/model
//	export SIGNATURE_PATH=/path/to/model.sig
//	export PRIVATE_KEY=/path/to/private-key.pem
//	go run ./examples/key/sign/main.go
//
// Demo mode (uses test keys from the repository):
//
//	go run ./examples/key/sign/main.go
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"

	keySigning "github.com/sigstore/model-signing/pkg/signing/key"
	"github.com/sigstore/model-signing/pkg/utils"
)

func main() {
	// Define command-line flags
	modelPath := flag.String("model-path", "", "Path to the model directory to sign")
	signaturePath := flag.String("signature-path", "", "Path where the signature will be saved")
	privateKeyPath := flag.String("private-key", "", "Path to the PEM-encoded private key")
	password := flag.String("password", "", "Password for encrypted private keys (optional)")
	ignoreGitPaths := flag.Bool("ignore-git-paths", true, "Ignore .git directories and .gitignore files")
	allowSymlinks := flag.Bool("allow-symlinks", false, "Allow following symlinks in the model directory")
	verbose := flag.Bool("verbose", true, "Enable verbose output")
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
	if *password == "" {
		*password = os.Getenv("KEY_PASSWORD")
	}

	// Demo mode: use test keys and create a temporary model
	demoMode := *modelPath == "" && *privateKeyPath == ""
	if demoMode {
		fmt.Println("Running in demo mode with test keys...")
		repoRoot := findRepoRoot()
		*privateKeyPath = filepath.Join(repoRoot, "scripts", "tests", "keys", "certificate", "signing-key.pem")

		// Create a temporary model directory
		tmpDir, err := os.MkdirTemp("", "model-signing-example-*")
		if err != nil {
			log.Fatalf("Failed to create temp directory: %v", err)
		}
		defer func() {
			fmt.Printf("\nTo verify this signature, run:\n")
			fmt.Printf("  go run ./examples/key/verify/main.go --model-path=%s --signature-path=%s --public-key=%s\n",
				tmpDir,
				filepath.Join(tmpDir, "model.sig"),
				filepath.Join(repoRoot, "scripts", "tests", "keys", "certificate", "signing-key-pub.pem"))
			fmt.Printf("\nNote: The demo model is at %s (will be cleaned up on exit in non-demo mode)\n", tmpDir)
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

	logger := utils.NewLogger(*verbose)

	// Create signer options
	opts := keySigning.KeySignerOptions{
		ModelPath:      *modelPath,
		SignaturePath:  *signaturePath,
		PrivateKeyPath: *privateKeyPath,
		Password:       *password,
		IgnorePaths:    nil,
		IgnoreGitPaths: *ignoreGitPaths,
		AllowSymlinks:  *allowSymlinks,
		Logger:         logger,
	}

	// Create the signer
	signer, err := keySigning.NewKeySigner(opts)
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
