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

// Example: Verify a model signature using the low-level API with Sigstore.
//
// This example uses BundleVerifier and config.Config (like the key/certificate
// low-level verify examples) but with SigstoreBundleVerifier so the signature
// is verified against the expected signer identity and OIDC issuer.
//
// Usage:
//
//	go run ./examples/lowlevel/sigstore/verify/main.go \
//	    --model-path=/path/to/model \
//	    --signature-path=/path/to/model.sig \
//	    --identity=signer@example.com \
//	    --identity-provider=https://accounts.google.com
//
// For signatures created with staging infrastructure:
//
//	go run ./examples/lowlevel/sigstore/verify/main.go \
//	    --model-path=/path/to/model \
//	    --signature-path=/path/to/model.sig \
//	    --identity=signer@example.com \
//	    --identity-provider=https://accounts.google.com \
//	    --staging
//
// With explicit hashing config:
//
//	go run ./examples/lowlevel/sigstore/verify/main.go \
//	    --model-path=/path/to/model \
//	    --signature-path=/path/to/model.sig \
//	    --identity=signer@example.com \
//	    --identity-provider=https://accounts.google.com \
//	    --hash-algorithm=sha256 \
//	    --ignore-git-paths
//
// Signature-only (verify bundle and print manifest; no file hashing):
//
//	go run ./examples/lowlevel/sigstore/verify/main.go \
//	    --signature-path=/path/to/model.sig \
//	    --identity=signer@example.com \
//	    --identity-provider=https://accounts.google.com \
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
	sign "github.com/sigstore/model-signing/pkg/signature"
	sigstoreVerify "github.com/sigstore/model-signing/pkg/verify/sigstore"
)

func main() {
	modelPath := flag.String("model-path", "", "Path to the model directory to verify")
	signaturePath := flag.String("signature-path", "", "Path to the signature file")
	identity := flag.String("identity", "", "Expected signer identity (e.g., email address)")
	identityProvider := flag.String("identity-provider", "", "Expected OIDC identity provider URL (e.g., https://accounts.google.com)")
	useStaging := flag.Bool("staging", false, "Use Sigstore staging infrastructure (for testing)")
	trustRootPath := flag.String("trust-root", "", "Path to custom trust root JSON file (optional)")

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
	if *identity == "" {
		*identity = os.Getenv("SIGNER_IDENTITY")
	}
	if *identityProvider == "" {
		*identityProvider = os.Getenv("IDENTITY_PROVIDER")
	}
	if *trustRootPath == "" {
		*trustRootPath = os.Getenv("TRUST_CONFIG")
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
	if *identity == "" {
		log.Fatal("--identity is required (the expected signer identity, e.g., email)")
	}
	if *identityProvider == "" {
		log.Fatal("--identity-provider is required (the expected OIDC identity provider URL)")
	}
	if !*signatureOnly && *modelPath == "" {
		log.Fatal("--model-path is required (unless --signature-only)")
	}

	// --- Step 1: Create bundle verifier (Sigstore-based) ---
	verifierConfig := sigstoreVerify.SigstoreVerifierConfig{
		TrustRootConfig: config.TrustRootConfig{
			UseStaging:    *useStaging,
			TrustRootPath: *trustRootPath,
		},
		Identity:   *identity,
		OIDCIssuer: *identityProvider,
	}
	verifier, err := sigstoreVerify.NewSigstoreBundleVerifier(verifierConfig)
	if err != nil {
		log.Fatalf("Failed to create verifier: %v", err)
	}

	if *signatureOnly {
		// --- Signature-only: read bundle, verify, print manifest (no hashing) ---
		var reader sign.SigstoreBundle
		bundle, err := reader.Read(*signaturePath)
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
