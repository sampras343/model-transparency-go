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

package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"time"
)

func benchmarkModel(args []string) int {
	fs := flag.NewFlagSet("benchmark-model", flag.ContinueOnError)
	operation := fs.String("operation", "", "sign|verify (required)")
	method := fs.String("method", "key", "key|certificate (ignored for operation:hash)")
	modelPath := fs.String("model-path", "", "Model directory (required)")
	privateKey := fs.String("private-key", "", "Private key PEM (sign, key and certificate methods)")
	publicKey := fs.String("public-key", "", "Public key PEM (verify, key method)")
	signingCert := fs.String("signing-cert", "", "Signing certificate PEM (sign, certificate method)")
	outputBundle := fs.String("output-bundle", "", "Output bundle path (sign)")
	bundle := fs.String("bundle", "", "Existing bundle path (verify)")
	repeat := fs.Int("repeat", 5, "Number of timed iterations")
	warmup := fs.Int("warmup", 1, "Number of warmup iterations before timed loop")
	hashAlgorithm := fs.String("hash-algorithm", "", "Hash algorithm: sha256|blake2b (sign and hash operations)")
	shardSize := fs.Int64("shard-size", 0, "Shard size in bytes for shard serialization (sign and hash operations; 0 = file serialization)")
	chunkSize := fs.Int("chunk-size", -1, "Read chunk size in bytes (hash operation; 0 = read file whole, -1 = library default 8KB)")
	maxWorkers := fs.Int("max-workers", 0, "Number of parallel hashing workers (hash operation; 0 = sequential)")
	var certChain stringSlice
	fs.Var(&certChain, "cert-chain", "Certificate chain PEM (verify, certificate method; repeat for multiple)")

	if err := fs.Parse(args); err != nil {
		return 2
	}

	if *operation == "" || *modelPath == "" {
		fmt.Fprintln(os.Stderr, "benchmark-model: --operation and --model-path are required")
		return 2
	}

	logger := newStderrLogger()
	var doOnce func() int

	if *operation == "hash" {
		doOnce = func() int {
			return hashModel(*modelPath, *hashAlgorithm, *shardSize, *chunkSize, *maxWorkers)
		}
	} else {
		switch *method {
		case "key":
			switch *operation {
			case "sign":
				if *privateKey == "" || *outputBundle == "" {
					fmt.Fprintln(os.Stderr, "benchmark-model key sign: --private-key and --output-bundle are required")
					return 2
				}
				doOnce = func() int {
					os.Remove(*outputBundle) //nolint:errcheck
					return signModelLibrary(*modelPath, *outputBundle, *privateKey, *hashAlgorithm, *shardSize, nil, logger)
				}
			case "verify":
				if *publicKey == "" || *bundle == "" {
					fmt.Fprintln(os.Stderr, "benchmark-model key verify: --public-key and --bundle are required")
					return 2
				}
				doOnce = func() int {
					return verifyModelLibrary(*modelPath, *bundle, *publicKey, logger)
				}
			default:
				fmt.Fprintf(os.Stderr, "benchmark-model: unknown operation %q\n", *operation)
				return 2
			}

		case "certificate":
			switch *operation {
			case "sign":
				if *privateKey == "" || *signingCert == "" || *outputBundle == "" {
					fmt.Fprintln(os.Stderr, "benchmark-model certificate sign: --private-key, --signing-cert, and --output-bundle are required")
					return 2
				}
				doOnce = func() int {
					os.Remove(*outputBundle) //nolint:errcheck
					return signModelCertLibrary(*modelPath, *outputBundle, *privateKey, *signingCert, certChain, *hashAlgorithm, *shardSize, logger)
				}
			case "verify":
				if *bundle == "" {
					fmt.Fprintln(os.Stderr, "benchmark-model certificate verify: --bundle is required")
					return 2
				}
				doOnce = func() int {
					return verifyModelCertLibrary(*modelPath, *bundle, certChain, logger)
				}
			default:
				fmt.Fprintf(os.Stderr, "benchmark-model: unknown operation %q\n", *operation)
				return 2
			}

		default:
			fmt.Fprintf(os.Stderr, "benchmark-model: unsupported method %q (supported: key, certificate)\n", *method)
			return 2
		}
	}

	for i := 0; i < *warmup; i++ {
		if rc := doOnce(); rc != 0 {
			errMsg := fmt.Sprintf("warmup iteration %d failed", i)
			fmt.Fprintln(os.Stderr, "benchmark-model: "+errMsg)
			out, _ := json.Marshal(map[string]any{"error": errMsg})
			fmt.Println(string(out))
			return 1
		}
	}

	var times []float64
	for i := 0; i < *repeat; i++ {
		t0 := time.Now()
		if rc := doOnce(); rc != 0 {
			errMsg := fmt.Sprintf("iteration %d failed", i)
			fmt.Fprintln(os.Stderr, "benchmark-model: "+errMsg)
			out, _ := json.Marshal(map[string]any{"error": errMsg, "iteration": i})
			fmt.Println(string(out))
			return 1
		}
		times = append(times, float64(time.Since(t0).Microseconds())/1000.0)
	}

	out, _ := json.Marshal(map[string]any{"times_ms": times})
	fmt.Println(string(out))
	return 0
}
