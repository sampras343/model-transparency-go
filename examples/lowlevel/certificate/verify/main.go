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

// Example: Verify a model signature using the low-level API with a certificate chain.
//
// This example uses BundleVerifier and config.Config (like the key low-level
// verify example) but with CertificateBundleVerifier so the signature is
// verified against a certificate chain.
//
// Usage (auto-detect hashing from signature):
//
//	go run ./examples/lowlevel/certificate/verify/main.go \
//	    --model-path=/path/to/model \
//	    --signature-path=/path/to/model.sig \
//	    --cert-chain=/path/to/intermediate.pem,/path/to/root.pem
//
// With explicit hashing config:
//
//	go run ./examples/lowlevel/certificate/verify/main.go \
//	    --model-path=/path/to/model \
//	    --signature-path=/path/to/model.sig \
//	    --cert-chain=/path/to/intermediate.pem,/path/to/root.pem \
//	    --hash-algorithm=sha256 \
//	    --shard-size=0 \
//	    --ignore-git-paths \
//	    --allow-symlinks=false
//
// Ignore extra files in the model directory:
//
//	go run ./examples/lowlevel/certificate/verify/main.go \
//	    --model-path=/path/to/model \
//	    --signature-path=/path/to/model.sig \
//	    --cert-chain=/path/to/intermediate.pem,/path/to/root.pem \
//	    --ignore-unsigned-files
//
// Signature-only (verify bundle and print manifest; no file hashing):
//
//	go run ./examples/lowlevel/certificate/verify/main.go \
//	    --signature-path=/path/to/model.sig \
//	    --cert-chain=/path/to/intermediate.pem,/path/to/root.pem \
//	    --signature-only
package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/sigstore/model-signing/pkg/config"
	certVerify "github.com/sigstore/model-signing/pkg/verify/certificate"
)

func main() {
	modelPath := flag.String("model-path", "", "Path to the model directory to verify")
	signaturePath := flag.String("signature-path", "", "Path to the signature file")
	certChain := flag.String("cert-chain", "", "Comma-separated paths to certificate chain files (intermediate, root)")
	logFingerprints := flag.Bool("log-fingerprints", false, "Log certificate fingerprints during verification")

	hashAlgorithm := flag.String("hash-algorithm", "", "Hash algorithm (e.g. sha256); empty = guess from signature")
	shardSize := flag.Int64("shard-size", -1, "Shard size in bytes; -1 = guess, 0 = file-based, >0 = shard size")
	ignorePathsStr := flag.String("ignore-paths", "", "Comma-separated paths to ignore (only used with explicit hashing)")
	ignoreGitPaths := flag.Bool("ignore-git-paths", true, "Ignore .git and related paths (only used with explicit hashing)")
	allowSymlinks := flag.Bool("allow-symlinks", false, "Allow following symlinks (only used with explicit hashing)")

	ignoreUnsignedFiles := flag.Bool("ignore-unsigned-files", false, "Ignore files not present in the signature")
	signatureOnly := flag.Bool("signature-only", false, "Only verify the bundle and print manifest; do not hash model or compare")
	flag.Parse()

	if *modelPath == "" {
		*modelPath = os.Getenv("MODEL_PATH")
	}
	if *signaturePath == "" {
		*signaturePath = os.Getenv("SIGNATURE_PATH")
	}
	if *certChain == "" {
		*certChain = os.Getenv("CERT_CHAIN")
	}

	var chainPaths []string
	if *certChain != "" {
		chainPaths = strings.Split(*certChain, ",")
		for i := range chainPaths {
			chainPaths[i] = strings.TrimSpace(chainPaths[i])
		}
	}

	var ignorePaths []string
	if *ignorePathsStr != "" {
		ignorePaths = strings.Split(*ignorePathsStr, ",")
		for i := range ignorePaths {
			ignorePaths[i] = strings.TrimSpace(ignorePaths[i])
		}
	}

	if *signaturePath == "" {
		log.Fatal("--signature-path is required")
	}
	if len(chainPaths) == 0 {
		log.Fatal("--cert-chain is required")
	}
	if !*signatureOnly && *modelPath == "" {
		log.Fatal("--model-path is required (unless --signature-only)")
	}

	// --- Step 1: Create bundle verifier (certificate-based) ---
	verifier, err := certVerify.NewCertificateBundleVerifier(certVerify.CertificateVerifierConfig{
		CertificateChainPaths: chainPaths,
		LogFingerprints:       *logFingerprints,
	})
	if err != nil {
		log.Fatalf("Failed to create verifier: %v", err)
	}

	if *signatureOnly {
		// --- Signature-only: read bundle, verify, print manifest (no hashing) ---
		// CertificateBundleVerifier implements BundleReader
		bundle, err := verifier.Read(*signaturePath)
		if err != nil {
			log.Fatalf("Failed to read signature: %v", err)
		}
		manifest, err := verifier.Verify(bundle)
		if err != nil {
			log.Fatalf("Signature verification failed: %v", err)
		}
		fmt.Printf("Signature is valid. Signed manifest for model %q:\n", manifest.ModelName())
		for _, rd := range manifest.ResourceDescriptors() {
			fmt.Printf("  %s  %s\n", rd.Digest.Hex(), rd.Identifier)
		}
		return
	}

	// --- Step 2: Build verification config (full verify: signature + hash + compare) ---
	verifyConfig := config.NewVerifierConfig().
		SetVerifier(verifier).
		SetIgnoreUnsignedFiles(*ignoreUnsignedFiles)

	if *hashAlgorithm != "" {
		hashingConfig := config.NewHashingConfig().
			SetIgnoredPaths(ignorePaths, *ignoreGitPaths).
			SetAllowSymlinks(*allowSymlinks)

		if *shardSize > 0 {
			hashingConfig.UseShardSerialization(*hashAlgorithm, *shardSize, *allowSymlinks, nil)
		} else {
			hashingConfig.UseFileSerialization(*hashAlgorithm, *allowSymlinks, nil)
		}
		verifyConfig.SetHashingConfig(hashingConfig)
		fmt.Printf("Using explicit hashing: algorithm=%s shard-size=%d\n", *hashAlgorithm, *shardSize)
	} else {
		fmt.Println("Hashing config will be inferred from the signature.")
	}

	// --- Step 3: Verify (signature + hash model + compare manifests) ---
	if err := verifyConfig.Verify(*modelPath, *signaturePath); err != nil {
		log.Fatalf("Verification failed: %v", err)
	}

	fmt.Printf("Verification succeeded for %s\n", filepath.Clean(*modelPath))
}
