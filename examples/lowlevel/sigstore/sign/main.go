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

// Example: Sign a model using the low-level API with Sigstore (keyless signing).
//
// This example uses BundleSigner, HashingConfig, and manual manifest/payload
// construction (like the key/certificate low-level examples) but with
// SigstoreBundleSigner for keyless signing via OIDC and Fulcio.
//
// Usage:
//
//	go run ./examples/lowlevel/sigstore/sign/main.go \
//	    --model-path=/path/to/model \
//	    --signature-path=/path/to/model.sig
//
// With explicit OIDC token:
//
//	export SIGSTORE_ID_TOKEN='<your-oidc-token>'
//	go run ./examples/lowlevel/sigstore/sign/main.go \
//	    --model-path=/path/to/model \
//	    --signature-path=/path/to/model.sig \
//	    --use-ambient-credentials
//
// For testing (uses Sigstore staging infrastructure):
//
//	go run ./examples/lowlevel/sigstore/sign/main.go \
//	    --model-path=/path/to/model \
//	    --signature-path=/path/to/model.sig \
//	    --staging
//
// Demo mode (creates a temporary model and uses staging):
//
//	go run ./examples/lowlevel/sigstore/sign/main.go
package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/sigstore/model-signing/pkg/config"
	"github.com/sigstore/model-signing/pkg/signing"
	sigstoreSigning "github.com/sigstore/model-signing/pkg/signing/sigstore"
	"github.com/sigstore/model-signing/pkg/utils"
)

func main() {
	modelPath := flag.String("model-path", "", "Path to the model directory to sign")
	signaturePath := flag.String("signature-path", "", "Path where the signature will be saved")
	useStaging := flag.Bool("staging", false, "Use Sigstore staging infrastructure (for testing)")
	useAmbientCredentials := flag.Bool("use-ambient-credentials", false, "Use ambient OIDC credentials (e.g., from SIGSTORE_ID_TOKEN)")
	hashAlgorithm := flag.String("hash-algorithm", utils.DefaultHashAlgorithm, "Hash algorithm (e.g. sha256, blake2b)")
	shardSize := flag.Int64("shard-size", 0, "Shard size in bytes; 0 = file-based serialization")
	ignorePathsStr := flag.String("ignore-paths", "", "Comma-separated paths to ignore (relative to model)")
	ignoreGitPaths := flag.Bool("ignore-git-paths", true, "Ignore .git and related paths")
	allowSymlinks := flag.Bool("allow-symlinks", false, "Allow following symlinks")
	chunkSize := flag.Int("chunk-size", 8192, "Chunk size for reading files (0 = read entire file)")
	flag.Parse()

	if *modelPath == "" {
		*modelPath = os.Getenv("MODEL_PATH")
	}
	if *signaturePath == "" {
		*signaturePath = os.Getenv("SIGNATURE_PATH")
	}

	var ignorePaths []string
	if *ignorePathsStr != "" {
		ignorePaths = strings.Split(*ignorePathsStr, ",")
		for i := range ignorePaths {
			ignorePaths[i] = strings.TrimSpace(ignorePaths[i])
		}
	}

	demoMode := *modelPath == ""
	if demoMode {
		fmt.Println("Running in demo mode...")
		tmpDir, err := os.MkdirTemp("", "model-signing-lowlevel-sigstore-*")
		if err != nil {
			log.Fatalf("Failed to create temp directory: %v", err)
		}
		defer func() {
			fmt.Printf("\nTo verify (low-level) run:\n")
			fmt.Printf("  go run ./examples/lowlevel/sigstore/verify/main.go --model-path=%s --signature-path=%s --staging --identity=<your-email> --identity-provider=<oidc-provider>\n",
				tmpDir,
				filepath.Join(tmpDir, "model.sig"))
			fmt.Printf("\nReplace <your-email> and <oidc-provider> with the identity from your OIDC token.\n")
			fmt.Printf("Demo model at %s\n", tmpDir)
		}()

		for _, pair := range []struct{ name, content string }{
			{"model.bin", "sample model data\n"},
			{"config.json", `{"version": "1.0"}`},
		} {
			if err := os.WriteFile(filepath.Join(tmpDir, pair.name), []byte(pair.content), 0644); err != nil {
				log.Fatalf("Failed to create %s: %v", pair.name, err)
			}
		}
		*modelPath = tmpDir
		*signaturePath = filepath.Join(tmpDir, "model.sig")
		*useStaging = true
	}

	if *modelPath == "" {
		log.Fatal("--model-path is required")
	}
	if *signaturePath == "" {
		log.Fatal("--signature-path is required")
	}

	// --- Step 1: Build hashing config with full control ---
	hashingConfig := config.NewHashingConfig().
		SetIgnoredPaths(ignorePaths, *ignoreGitPaths).
		SetAllowSymlinks(*allowSymlinks).
		SetChunkSize(*chunkSize)

	hashingConfig.AddIgnoredPaths(*modelPath, []string{*signaturePath})

	if *shardSize > 0 {
		hashingConfig.UseShardSerialization(*hashAlgorithm, *shardSize, *allowSymlinks, nil)
	} else {
		hashingConfig.UseFileSerialization(*hashAlgorithm, *allowSymlinks, nil)
	}

	// --- Step 2: Hash the model to produce a manifest ---
	manifest, err := hashingConfig.Hash(*modelPath, nil)
	if err != nil {
		log.Fatalf("Failed to hash model: %v", err)
	}
	fmt.Printf("Hashed %d resource(s) with %s (shard-size=%d)\n",
		len(manifest.ResourceDescriptors()), *hashAlgorithm, *shardSize)

	// --- Step 3: Create signing payload from manifest ---
	payload, err := signing.CreatePayload(manifest)
	if err != nil {
		log.Fatalf("Failed to create payload: %v", err)
	}

	// --- Step 4: Create Sigstore bundle signer and sign ---
	signerConfig := sigstoreSigning.SigstoreSignerConfig{
		TrustRootConfig:       config.TrustRootConfig{UseStaging: *useStaging},
		UseAmbientCredentials: *useAmbientCredentials,
		IdentityToken:         os.Getenv("SIGSTORE_ID_TOKEN"),
	}
	signer, err := sigstoreSigning.NewSigstoreBundleSigner(signerConfig)
	if err != nil {
		log.Fatalf("Failed to create signer: %v", err)
	}

	bundle, err := signing.SignAndWrite(signer, payload, *signaturePath)
	if err != nil {
		log.Fatalf("Signing failed: %v\n\nHint: Set SIGSTORE_ID_TOKEN or run without --use-ambient-credentials for interactive OAuth", err)
	}
	_ = bundle

	fmt.Printf("Signature written to %s\n", *signaturePath)
}
