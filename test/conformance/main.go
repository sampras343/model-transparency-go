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

// go-conformance — model-signing conformance adapter for Go.
//
// Translates the conformance protocol to the model-signing CLI binary.
// This binary is compiled and used as the --entrypoint for the
// model-signing-conformance test suite.
//
// Usage:
//
//	go-conformance sign-model --method key|certificate --model-path DIR \
//	               --output-bundle FILE [--private-key PEM] [--signing-cert PEM] \
//	               [--cert-chain PEM...] [--ignore-paths PATH...]
//	               [--hash-algorithm sha256|blake2b] [--shard-size BYTES]
//
//	go-conformance verify-model --method key|certificate --model-path DIR \
//	               --bundle FILE [--public-key PEM] [--cert-chain PEM...] \
//	               [--ignore-paths PATH...] [--ignore-unsigned-files]
//
//	go-conformance capabilities
//	               Prints a JSON object listing which optional benchmark flags
//	               this adapter supports. Used by the benchmark harness.
//
// The adapter calls the `model-signing` binary from PATH (or MODEL_SIGNING_BIN env var)
// for standard conformance operations. For benchmark-specific flags (--hash-algorithm,
// --shard-size), it calls the Go library directly to access options not exposed by the CLI.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/sigstore/model-signing/pkg/modelartifact"
	"github.com/sigstore/model-signing/pkg/signing"
	signingkey "github.com/sigstore/model-signing/pkg/signing/key"
	"github.com/sigstore/model-signing/pkg/utils"
	sigstoresign "github.com/sigstore/sigstore-go/pkg/sign"
)

func modelSigningBin() string {
	if bin := os.Getenv("MODEL_SIGNING_BIN"); bin != "" {
		return bin
	}
	return "model-signing"
}

// stringSlice is a flag.Value that collects repeated --flag values.
type stringSlice []string

func (s *stringSlice) String() string     { return strings.Join(*s, ",") }
func (s *stringSlice) Set(v string) error { *s = append(*s, v); return nil }

func run(args []string) int {
	if len(args) < 1 {
		fmt.Fprintln(os.Stderr, "Usage: go-conformance <sign-model|verify-model|capabilities> [flags]")
		return 2
	}

	switch args[0] {
	case "sign-model":
		return signModel(args[1:])
	case "verify-model":
		return verifyModel(args[1:])
	case "capabilities":
		return printCapabilities()
	default:
		fmt.Fprintf(os.Stderr, "Unknown command: %s\n", args[0])
		return 2
	}
}

// printCapabilities prints a JSON object listing the optional benchmark flags
// supported by this adapter. The benchmark harness calls this at startup to
// determine which parameter-sweep scenarios can run.
//
// --hash-algorithm and --shard-size are supported because the Go library
// exposes them via modelartifact.Options. The adapter calls the library
// directly (bypassing the CLI) when those flags are provided.
//
// --chunk-size and --max-workers are NOT in modelartifact.Options and cannot
// be controlled externally — they are not declared here.
func printCapabilities() int {
	caps := `{"flags":["--hash-algorithm","--shard-size"],"hash_algorithms":["sha256","blake2b"]}`
	fmt.Println(caps)
	return 0
}

func signModel(args []string) int {
	fs := flag.NewFlagSet("sign-model", flag.ContinueOnError)
	method := fs.String("method", "", "key|certificate|sigstore (required)")
	modelPath := fs.String("model-path", "", "Model directory path (required)")
	outputBundle := fs.String("output-bundle", "", "Output bundle path (required)")
	privateKey := fs.String("private-key", "", "Private key PEM path")
	signingCert := fs.String("signing-cert", "", "Signing certificate PEM path")
	identityToken := fs.String("identity-token", "", "OIDC identity token (for sigstore)")
	useStaging := fs.Bool("use-staging", false, "Use Sigstore staging")
	// Benchmark-only flags — not part of the base conformance protocol.
	// Declared here so the adapter accepts them without erroring; they route
	// to signModelLibrary() instead of the CLI when provided.
	hashAlgorithm := fs.String("hash-algorithm", "", "Hash algorithm: sha256|blake2b (benchmark only, optional)")
	shardSize := fs.Int64("shard-size", 0, "Shard size in bytes (benchmark only, 0 = no sharding)")
	var certChain stringSlice
	var ignorePaths stringSlice
	fs.Var(&certChain, "cert-chain", "Certificate chain PEM (repeat for multiple)")
	fs.Var(&ignorePaths, "ignore-paths", "Path to ignore (repeat for multiple)")

	if err := fs.Parse(args); err != nil {
		return 2
	}

	if *method == "" || *modelPath == "" || *outputBundle == "" {
		fmt.Fprintln(os.Stderr, "sign-model: --method, --model-path, and --output-bundle are required")
		return 2
	}

	// Benchmark flags are only valid with key-based signing (library direct path).
	// If either is set, bypass the CLI and call the library directly.
	if *hashAlgorithm != "" || *shardSize > 0 {
		if *method != "key" {
			fmt.Fprintln(os.Stderr, "sign-model: --hash-algorithm and --shard-size are only supported with --method key")
			return 2
		}
		if *privateKey == "" {
			fmt.Fprintln(os.Stderr, "sign-model key: --private-key is required")
			return 2
		}
		return signModelLibrary(*modelPath, *outputBundle, *privateKey, *hashAlgorithm, *shardSize, ignorePaths)
	}

	bin := modelSigningBin()
	var cmd []string

	switch *method {
	case "key":
		if *privateKey == "" {
			fmt.Fprintln(os.Stderr, "sign-model key: --private-key is required")
			return 2
		}
		cmd = []string{bin, "sign", "key",
			"--signature", *outputBundle,
			"--private-key", *privateKey,
		}

	case "certificate":
		if *privateKey == "" || *signingCert == "" {
			fmt.Fprintln(os.Stderr, "sign-model certificate: --private-key and --signing-cert are required")
			return 2
		}
		cmd = []string{bin, "sign", "certificate",
			"--signature", *outputBundle,
			"--private-key", *privateKey,
			"--signing-certificate", *signingCert,
		}
		for _, cert := range certChain {
			cmd = append(cmd, "--certificate-chain", cert)
		}

	case "sigstore":
		cmd = []string{bin, "sign", "sigstore", "--signature", *outputBundle}
		if *identityToken != "" {
			cmd = append(cmd, "--identity-token", *identityToken)
		}
		if *useStaging {
			cmd = append(cmd, "--use-staging")
		}

	default:
		fmt.Fprintf(os.Stderr, "Unknown method: %s\n", *method)
		return 2
	}

	// Go CLI requires ignore-paths to be absolute existing paths.
	// The conformance protocol passes them as absolute paths already.
	for _, p := range ignorePaths {
		absPath, err := resolveIgnorePath(p, *modelPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "WARNING: ignore path %q not resolved: %v\n", p, err)
			continue
		}
		cmd = append(cmd, "--ignore-paths", absPath)
	}

	cmd = append(cmd, *modelPath)
	return execCmd(cmd)
}

// signModelLibrary calls the Go library directly instead of the CLI binary.
// Used when benchmark flags (--hash-algorithm, --shard-size) are provided,
// since those options are not exposed by the model-signing CLI.
//
// Replicates the key-signing flow from pkg/signing/key/key_signer.go but
// passes HashAlgorithm and ShardSize through modelartifact.Options, which
// signing.PreparePayload intentionally does not thread through.
func signModelLibrary(modelPath, outputBundle, privateKey, hashAlgorithm string, shardSize int64, ignorePaths []string) int {
	ctx := context.Background()

	// Always exclude the output bundle from what gets hashed.
	allIgnore := append(append([]string{}, []string(ignorePaths)...), outputBundle)

	m, err := modelartifact.Canonicalize(modelPath, modelartifact.Options{
		HashAlgorithm: hashAlgorithm,
		ShardSize:     shardSize,
		IgnorePaths:   allIgnore,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "canonicalize error: %v\n", err)
		return 1
	}

	payload, err := modelartifact.MarshalPayload(m)
	if err != nil {
		fmt.Fprintf(os.Stderr, "marshal payload error: %v\n", err)
		return 1
	}

	keypair, err := signingkey.NewModelKeypair(privateKey, "")
	if err != nil {
		fmt.Fprintf(os.Stderr, "keypair error: %v\n", err)
		return 1
	}

	content := &sigstoresign.DSSEData{
		Data:        payload,
		PayloadType: utils.InTotoJSONPayloadType,
	}

	bundle, err := sigstoresign.Bundle(content, keypair, sigstoresign.BundleOptions{Context: ctx})
	if err != nil {
		fmt.Fprintf(os.Stderr, "sign error: %v\n", err)
		return 1
	}

	if err := signing.WriteBundle(bundle, outputBundle); err != nil {
		fmt.Fprintf(os.Stderr, "write bundle error: %v\n", err)
		return 1
	}

	return 0
}

func verifyModel(args []string) int {
	fs := flag.NewFlagSet("verify-model", flag.ContinueOnError)
	method := fs.String("method", "", "key|certificate|sigstore (required)")
	modelPath := fs.String("model-path", "", "Model directory path (required)")
	bundle := fs.String("bundle", "", "Bundle file path (required)")
	publicKey := fs.String("public-key", "", "Public key PEM path (for key method)")
	identity := fs.String("identity", "", "Expected signer identity (for sigstore)")
	identityProvider := fs.String("identity-provider", "", "Expected OIDC issuer (for sigstore)")
	ignoreUnsignedFiles := fs.Bool("ignore-unsigned-files", false, "Ignore unsigned files")
	useStaging := fs.Bool("use-staging", false, "Use Sigstore staging")
	var certChain stringSlice
	var ignorePaths stringSlice
	fs.Var(&certChain, "cert-chain", "Certificate chain PEM (repeat for multiple)")
	fs.Var(&ignorePaths, "ignore-paths", "Path to ignore (repeat for multiple)")

	if err := fs.Parse(args); err != nil {
		return 2
	}

	if *method == "" || *modelPath == "" || *bundle == "" {
		fmt.Fprintln(os.Stderr, "verify-model: --method, --model-path, and --bundle are required")
		return 2
	}

	bin := modelSigningBin()
	var cmd []string

	switch *method {
	case "key":
		if *publicKey == "" {
			fmt.Fprintln(os.Stderr, "verify-model key: --public-key is required")
			return 2
		}
		cmd = []string{bin, "verify", "key",
			"--signature", *bundle,
			"--public-key", *publicKey,
		}

	case "certificate":
		cmd = []string{bin, "verify", "certificate", "--signature", *bundle}
		for _, cert := range certChain {
			cmd = append(cmd, "--certificate-chain", cert)
		}

	case "sigstore":
		if *identity == "" || *identityProvider == "" {
			fmt.Fprintln(os.Stderr, "verify-model sigstore: --identity and --identity-provider are required")
			return 2
		}
		cmd = []string{bin, "verify", "sigstore",
			"--signature", *bundle,
			"--identity", *identity,
			"--identity-provider", *identityProvider,
		}
		if *useStaging {
			cmd = append(cmd, "--use-staging")
		}

	default:
		fmt.Fprintf(os.Stderr, "Unknown method: %s\n", *method)
		return 2
	}

	for _, p := range ignorePaths {
		absPath, err := resolveIgnorePath(p, *modelPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "WARNING: ignore path %q not resolved: %v\n", p, err)
			continue
		}
		cmd = append(cmd, "--ignore-paths", absPath)
	}

	if *ignoreUnsignedFiles {
		cmd = append(cmd, "--ignore-unsigned-files")
	}

	cmd = append(cmd, *modelPath)
	return execCmd(cmd)
}

// resolveIgnorePath converts an ignore path to an absolute path.
// The Go CLI requires absolute paths that exist on the filesystem.
// If path is already absolute, return it as-is.
// If it's relative, resolve it relative to modelPath.
func resolveIgnorePath(p, modelPath string) (string, error) {
	if filepath.IsAbs(p) {
		return p, nil
	}
	// Relative: resolve relative to model directory
	abs := filepath.Join(modelPath, p)
	if _, err := os.Stat(abs); err != nil {
		// Also try as-is from cwd
		if cwdAbs, err2 := filepath.Abs(p); err2 == nil {
			if _, err3 := os.Stat(cwdAbs); err3 == nil {
				return cwdAbs, nil
			}
		}
		return "", fmt.Errorf("path does not exist: %s", abs)
	}
	return abs, nil
}

func execCmd(args []string) int {
	bin, err := exec.LookPath(args[0])
	if err != nil {
		fmt.Fprintf(os.Stderr, "exec error: %v\n", err)
		return 1
	}
	c := exec.Command(bin, args[1:]...) //nolint:gosec // bin is resolved via LookPath
	c.Stdout = os.Stdout
	c.Stderr = os.Stderr
	if err := c.Run(); err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			return exitErr.ExitCode()
		}
		fmt.Fprintf(os.Stderr, "exec error: %v\n", err)
		return 1
	}
	return 0
}

func main() {
	os.Exit(run(os.Args[1:]))
}
