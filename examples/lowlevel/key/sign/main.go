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

// Example: Sign a model using the low-level API with full control over hashing.
//
// This example uses BundleSigner, HashingConfig, and manual manifest/payload
// construction instead of the high-level ModelSigner. You control:
//   - Hash algorithm (e.g. sha256, blake2b)
//   - Serialization: whole-file or shard-based (shard size in bytes)
//   - Ignore paths and whether to ignore git-related paths
//   - Symlinks (allow or skip)
//   - Chunk size for file reading
//
// Usage (file-based hashing, default sha256):
//
//	go run ./examples/lowlevel/key/sign/main.go \
//	    --model-path=/path/to/model \
//	    --signature-path=/path/to/model.sig \
//	    --private-key=/path/to/private-key.pem
//
// With custom hash algorithm and ignore paths:
//
//	go run ./examples/lowlevel/key/sign/main.go \
//	    --model-path=/path/to/model \
//	    --signature-path=/path/to/model.sig \
//	    --private-key=/path/to/private-key.pem \
//	    --hash-algorithm=sha256 \
//	    --ignore-paths=tmp,logs \
//	    --ignore-git-paths
//
// With shard-based serialization (e.g. 4KB shards for large files):
//
//	go run ./examples/lowlevel/key/sign/main.go \
//	    --model-path=/path/to/model \
//	    --signature-path=/path/to/model.sig \
//	    --private-key=/path/to/private-key.pem \
//	    --shard-size=4096
//
// Demo mode (uses test key and creates a temporary model):
//
//	go run ./examples/lowlevel/key/sign/main.go
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
	keySigning "github.com/sigstore/model-signing/pkg/signing/key"
	"github.com/sigstore/model-signing/pkg/utils"
)

func main() {
	modelPath := flag.String("model-path", "", "Path to the model directory to sign")
	signaturePath := flag.String("signature-path", "", "Path where the signature will be saved")
	privateKeyPath := flag.String("private-key", "", "Path to the PEM-encoded private key")
	password := flag.String("password", "", "Password for encrypted private keys (optional)")
	hashAlgorithm := flag.String("hash-algorithm", utils.DefaultHashAlgorithm, "Hash algorithm (e.g. sha256, blake2b)")
	shardSize := flag.Int64("shard-size", 0, "Shard size in bytes; 0 = file-based serialization (hash whole files)")
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
	if *privateKeyPath == "" {
		*privateKeyPath = os.Getenv("PRIVATE_KEY")
	}
	if *password == "" {
		*password = os.Getenv("KEY_PASSWORD")
	}

	var ignorePaths []string
	if *ignorePathsStr != "" {
		ignorePaths = strings.Split(*ignorePathsStr, ",")
		for i := range ignorePaths {
			ignorePaths[i] = strings.TrimSpace(ignorePaths[i])
		}
	}

	demoMode := *modelPath == "" && *privateKeyPath == ""
	if demoMode {
		fmt.Println("Running in demo mode with test key...")
		repoRoot := findRepoRoot()
		*privateKeyPath = filepath.Join(repoRoot, "scripts", "tests", "keys", "certificate", "signing-key.pem")

		tmpDir, err := os.MkdirTemp("", "model-signing-lowlevel-*")
		if err != nil {
			log.Fatalf("Failed to create temp directory: %v", err)
		}
		defer func() {
			fmt.Printf("\nTo verify (low-level) run:\n")
			fmt.Printf("  go run ./examples/lowlevel/key/verify/main.go --model-path=%s --signature-path=%s --public-key=%s\n",
				tmpDir,
				filepath.Join(tmpDir, "model.sig"),
				filepath.Join(repoRoot, "scripts", "tests", "keys", "certificate", "signing-key-pub.pem"))
			fmt.Printf("\nDemo model at %s\n", tmpDir)
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
	}

	if *modelPath == "" {
		log.Fatal("--model-path is required")
	}
	if *signaturePath == "" {
		log.Fatal("--signature-path is required")
	}
	if *privateKeyPath == "" {
		log.Fatal("--private-key is required")
	}

	// --- Step 1: Build hashing config with full control ---
	hashingConfig := config.NewHashingConfig().
		SetIgnoredPaths(ignorePaths, *ignoreGitPaths).
		SetAllowSymlinks(*allowSymlinks).
		SetChunkSize(*chunkSize)

	// Add signature path so it is not hashed
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

	// --- Step 4: Create bundle signer and sign ---
	signerConfig := keySigning.KeySignerConfig{
		KeyConfig: config.KeyConfig{
			Path:     *privateKeyPath,
			Password: *password,
		},
	}
	signer, err := keySigning.NewKeyBundleSigner(signerConfig)
	if err != nil {
		log.Fatalf("Failed to create signer: %v", err)
	}

	bundle, err := signing.SignAndWrite(signer, payload, *signaturePath)
	if err != nil {
		log.Fatalf("Signing failed: %v", err)
	}
	_ = bundle

	fmt.Printf("Signature written to %s\n", *signaturePath)
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
