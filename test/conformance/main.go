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
//	go-conformance benchmark-model --operation hash|sign|verify [flags]
//
//	go-conformance capabilities
//
// The adapter calls the `model-signing` binary from PATH (or MODEL_SIGNING_BIN env var)
// for standard conformance operations. For benchmark-specific flags (--hash-algorithm,
// --shard-size), it calls the Go library directly to access options not exposed by the CLI.
package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/sigstore/model-signing/pkg/logging"
)

// stringSlice is a flag.Value that collects repeated --flag values.
type stringSlice []string

func (s *stringSlice) String() string     { return strings.Join(*s, ",") }
func (s *stringSlice) Set(v string) error { *s = append(*s, v); return nil }

func modelSigningBin() string {
	if bin := os.Getenv("MODEL_SIGNING_BIN"); bin != "" {
		return bin
	}
	return "model-signing"
}

func newStderrLogger() logging.Logger {
	return logging.NewLoggerWithOptions(logging.LoggerOptions{
		Level:  logging.LevelWarn,
		Output: os.Stderr,
	})
}

// resolveIgnorePath converts an ignore path to an absolute path.
// The Go CLI requires absolute paths that exist on the filesystem.
func resolveIgnorePath(p, modelPath string) (string, error) {
	if filepath.IsAbs(p) {
		return p, nil
	}
	abs := filepath.Join(modelPath, p)
	if _, err := os.Stat(abs); err != nil {
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

func run(args []string) int {
	if len(args) < 1 {
		fmt.Fprintln(os.Stderr, "Usage: go-conformance <sign-model|verify-model|benchmark-model|capabilities> [flags]")
		return 2
	}

	switch args[0] {
	case "sign-model":
		return signModel(args[1:])
	case "verify-model":
		return verifyModel(args[1:])
	case "benchmark-model":
		return benchmarkModel(args[1:])
	case "capabilities":
		return printCapabilities()
	default:
		fmt.Fprintf(os.Stderr, "Unknown command: %s\n", args[0])
		return 2
	}
}

func main() {
	os.Exit(run(os.Args[1:]))
}
