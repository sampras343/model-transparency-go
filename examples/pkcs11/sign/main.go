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

// Example: Sign a model using PKCS#11 (Hardware Security Module or software token).
//
// This example demonstrates how to sign a model directory using a private key
// stored in a PKCS#11 token (such as a hardware HSM or SoftHSM2). The PKCS#11
// URI is used to identify the key and token.
//
// Usage with key-based signing:
//
//	go run ./examples/pkcs11/sign/main.go \
//	    --model-path=/path/to/model \
//	    --signature-path=/path/to/model.sig \
//	    --pkcs11-uri="pkcs11:token=mytoken;object=mykey?pin-value=1234"
//
// Usage with certificate-based signing:
//
//	go run ./examples/pkcs11/sign/main.go \
//	    --model-path=/path/to/model \
//	    --signature-path=/path/to/model.sig \
//	    --pkcs11-uri="pkcs11:token=mytoken;object=mykey?pin-value=1234" \
//	    --signing-cert=/path/to/signing-cert.pem \
//	    --cert-chain=/path/to/intermediate.pem,/path/to/root.pem
//
// Or using environment variables:
//
//	export MODEL_PATH=/path/to/model
//	export SIGNATURE_PATH=/path/to/model.sig
//	export PKCS11_URI="pkcs11:token=mytoken;object=mykey?pin-value=1234"
//	export SIGNING_CERT=/path/to/signing-cert.pem  # Optional
//	export CERT_CHAIN=/path/to/intermediate.pem,/path/to/root.pem  # Optional
//	go run ./examples/pkcs11/sign/main.go
//
// Setup SoftHSM2 for testing:
//
//	# Initialize SoftHSM2 (run once)
//	./scripts/tests/softhsm_setup setup
//
//	# The setup command will output the PKCS#11 URI to use
//	# Example: pkcs11:token=model-signing-test;object=mykey?pin-value=1234
//
// Demo mode (requires SoftHSM2 setup):
//
//	# First, setup SoftHSM2
//	./scripts/tests/softhsm_setup setup
//
//	# Then run the demo (it will prompt for PKCS11_URI if not set)
//	go run ./examples/pkcs11/sign/main.go
//
// PKCS#11 URI format (RFC 7512):
//
//	pkcs11:token=TOKEN;object=KEY?pin-value=PIN
//	pkcs11:token=TOKEN;id=%AB%CD;object=KEY?pin-value=PIN
//	pkcs11:token=TOKEN;object=KEY?pin-source=file:///path/to/pin.txt
//	pkcs11:slot-id=0;object=KEY?pin-value=PIN&module-path=/usr/lib/softhsm/libsofthsm2.so
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
	pkcs11Signing "github.com/sigstore/model-signing/pkg/signing/pkcs11"
)

func main() {
	// Define command-line flags
	modelPath := flag.String("model-path", "", "Path to the model directory to sign")
	signaturePath := flag.String("signature-path", "", "Path where the signature will be saved")
	pkcs11URI := flag.String("pkcs11-uri", "", "PKCS#11 URI identifying the private key (e.g., pkcs11:token=mytoken;object=mykey?pin-value=1234)")
	signingCertPath := flag.String("signing-cert", "", "Path to the PEM-encoded signing certificate (optional, for certificate-based signing)")
	certChain := flag.String("cert-chain", "", "Comma-separated paths to certificate chain files (optional)")
	modulePaths := flag.String("module-paths", "", "Comma-separated additional directories to search for PKCS#11 modules (optional)")
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
	if *pkcs11URI == "" {
		*pkcs11URI = os.Getenv("PKCS11_URI")
	}
	if *signingCertPath == "" {
		*signingCertPath = os.Getenv("SIGNING_CERT")
	}
	if *certChain == "" {
		*certChain = os.Getenv("CERT_CHAIN")
	}
	if *modulePaths == "" {
		*modulePaths = os.Getenv("MODULE_PATHS")
	}

	// Parse certificate chain
	var chainPaths []string
	if *certChain != "" {
		chainPaths = strings.Split(*certChain, ",")
		for i := range chainPaths {
			chainPaths[i] = strings.TrimSpace(chainPaths[i])
		}
	}

	// Parse module paths
	var modulePathsList []string
	if *modulePaths != "" {
		modulePathsList = strings.Split(*modulePaths, ",")
		for i := range modulePathsList {
			modulePathsList[i] = strings.TrimSpace(modulePathsList[i])
		}
	}

	// Demo mode: create a temporary model and prompt for PKCS#11 URI
	demoMode := *modelPath == "" && *pkcs11URI == ""
	if demoMode {
		fmt.Println("Running in demo mode...")
		fmt.Println("\nTo use this example, you need to:")
		fmt.Println("1. Setup SoftHSM2: ./scripts/tests/softhsm_setup setup")
		fmt.Println("2. Copy the PKCS#11 URI from the output")
		fmt.Println("3. Set it as PKCS11_URI environment variable or pass via --pkcs11-uri flag")
		fmt.Println("\nExample:")
		fmt.Println("  export PKCS11_URI='pkcs11:token=model-signing-test;object=mykey?pin-value=1234'")
		fmt.Println("  go run ./examples/pkcs11/sign/main.go")

		// Check if PKCS11_URI is set
		if *pkcs11URI == "" {
			log.Fatal("\nPKCS11_URI not set. Please setup SoftHSM2 and provide the URI.")
		}

		// Create a temporary model directory
		tmpDir, err := os.MkdirTemp("", "model-signing-pkcs11-example-*")
		if err != nil {
			log.Fatalf("Failed to create temp directory: %v", err)
		}
		defer func() {
			fmt.Printf("\nTo verify this signature, run:\n")
			if *signingCertPath != "" {
				fmt.Printf("  go run ./examples/pkcs11/verify/main.go --model-path=%s --signature-path=%s --cert-chain=%s\n",
					tmpDir,
					filepath.Join(tmpDir, "model.sig"),
					strings.Join(chainPaths, ","))
			} else {
				fmt.Printf("  # First, export the public key from PKCS#11:\n")
				fmt.Printf("  ./scripts/tests/softhsm_setup getpubkey > /tmp/pubkey.pem\n")
				fmt.Printf("  # Then verify:\n")
				fmt.Printf("  go run ./examples/key/verify/main.go --model-path=%s --signature-path=%s --public-key=/tmp/pubkey.pem\n",
					tmpDir,
					filepath.Join(tmpDir, "model.sig"))
			}
			fmt.Printf("\nNote: The demo model is at %s\n", tmpDir)
		}()

		// Create sample model files
		if err := os.WriteFile(filepath.Join(tmpDir, "model.bin"), []byte("sample model data from PKCS#11\n"), 0644); err != nil {
			log.Fatalf("Failed to create model file: %v", err)
		}
		if err := os.WriteFile(filepath.Join(tmpDir, "config.json"), []byte(`{"version": "1.0", "signer": "pkcs11"}`), 0644); err != nil {
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
	if *pkcs11URI == "" {
		log.Fatal("--pkcs11-uri is required. See --help for setup instructions.")
	}

	logger := logging.NewLogger(*verbose)

	// Create signer options
	opts := pkcs11Signing.Pkcs11SignerOptions{
		ModelPath:              *modelPath,
		SignaturePath:          *signaturePath,
		URI:                    *pkcs11URI,
		SigningCertificatePath: *signingCertPath,
		CertificateChain:       chainPaths,
		ModulePaths:            modulePathsList,
		IgnorePaths:            nil,
		IgnoreGitPaths:         *ignoreGitPaths,
		AllowSymlinks:          *allowSymlinks,
		Logger:                 logger,
	}

	// Create the signer
	signer, err := pkcs11Signing.NewPkcs11Signer(opts)
	if err != nil {
		log.Fatalf("Failed to create PKCS#11 signer: %v", err)
	}

	// Sign the model
	ctx := context.Background()
	result, err := signer.Sign(ctx)
	if err != nil {
		log.Fatalf("Signing failed: %v", err)
	}

	fmt.Printf("\n%s\n", result.Message)
}
