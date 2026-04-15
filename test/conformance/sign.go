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
	"context"
	"flag"
	"fmt"
	"os"

	"github.com/sigstore/model-signing/pkg/logging"
	"github.com/sigstore/model-signing/pkg/modelartifact"
	"github.com/sigstore/model-signing/pkg/signing"
	signcert "github.com/sigstore/model-signing/pkg/signing/certificate"
	signingkey "github.com/sigstore/model-signing/pkg/signing/key"
	"github.com/sigstore/model-signing/pkg/utils"
	sigstoresign "github.com/sigstore/sigstore-go/pkg/sign"
)

func signModel(args []string) int {
	fs := flag.NewFlagSet("sign-model", flag.ContinueOnError)
	method := fs.String("method", "", "key|certificate|sigstore (required)")
	modelPath := fs.String("model-path", "", "Model directory path (required)")
	outputBundle := fs.String("output-bundle", "", "Output bundle path (required)")
	privateKey := fs.String("private-key", "", "Private key PEM path")
	signingCert := fs.String("signing-cert", "", "Signing certificate PEM path")
	identityToken := fs.String("identity-token", "", "OIDC identity token (for sigstore)")
	useStaging := fs.Bool("use-staging", false, "Use Sigstore staging")
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

	if *hashAlgorithm != "" || *shardSize > 0 {
		logger := newStderrLogger()
		switch *method {
		case "key":
			if *privateKey == "" {
				fmt.Fprintln(os.Stderr, "sign-model key: --private-key is required")
				return 2
			}
			return signModelLibrary(*modelPath, *outputBundle, *privateKey, *hashAlgorithm, *shardSize, ignorePaths, logger)
		case "certificate":
			if *privateKey == "" || *signingCert == "" {
				fmt.Fprintln(os.Stderr, "sign-model certificate: --private-key and --signing-cert are required")
				return 2
			}
			return signModelCertLibrary(*modelPath, *outputBundle, *privateKey, *signingCert, certChain, *hashAlgorithm, *shardSize, logger)
		default:
			fmt.Fprintf(os.Stderr, "sign-model: --hash-algorithm and --shard-size are only supported with --method key or --method certificate\n")
			return 2
		}
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

func signModelLibrary(modelPath, outputBundle, privateKey, hashAlgorithm string, shardSize int64, ignorePaths []string, logger logging.Logger) int {
	ctx := context.Background()

	allIgnore := append(append([]string{}, ignorePaths...), outputBundle)

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

	_ = logger // available for future diagnostic use
	return 0
}

func signModelCertLibrary(modelPath, outputBundle, privateKey, signingCert string, certChain []string, hashAlgorithm string, shardSize int64, logger logging.Logger) int {
	ctx := context.Background()

	allIgnore := []string{outputBundle}

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

	certProvider, err := signcert.NewModelCertificateProvider(signingCert, keypair)
	if err != nil {
		fmt.Fprintf(os.Stderr, "certificate provider error: %v\n", err)
		return 1
	}

	content := &sigstoresign.DSSEData{
		Data:        payload,
		PayloadType: utils.InTotoJSONPayloadType,
	}

	bundle, err := sigstoresign.Bundle(content, keypair, sigstoresign.BundleOptions{
		CertificateProvider: certProvider,
		Context:             ctx,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "sign error: %v\n", err)
		return 1
	}

	if err := signing.WriteBundle(bundle, outputBundle); err != nil {
		fmt.Fprintf(os.Stderr, "write bundle error: %v\n", err)
		return 1
	}

	if len(certChain) > 0 {
		if err := signcert.EmbedCertChainInBundleFile(outputBundle, certChain); err != nil {
			fmt.Fprintf(os.Stderr, "embed cert chain error: %v\n", err)
			return 1
		}
	}

	_ = logger
	return 0
}
