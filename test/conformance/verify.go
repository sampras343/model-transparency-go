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
	verifycert "github.com/sigstore/model-signing/pkg/verify/certificate"
	verifykey "github.com/sigstore/model-signing/pkg/verify/key"
)

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

func verifyModelLibrary(modelPath, bundlePath, publicKeyPath string, logger logging.Logger) int {
	ctx := context.Background()
	v, err := verifykey.NewKeyVerifier(verifykey.KeyVerifierOptions{
		ModelPath:     modelPath,
		SignaturePath: bundlePath,
		PublicKeyPath: publicKeyPath,
		Logger:        logger,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "verifier error: %v\n", err)
		return 1
	}
	result, err := v.Verify(ctx)
	if err != nil || !result.Verified {
		fmt.Fprintf(os.Stderr, "verify error: %v\n", err)
		return 1
	}
	return 0
}

func verifyModelCertLibrary(modelPath, bundlePath string, certChain []string, logger logging.Logger) int {
	ctx := context.Background()
	v, err := verifycert.NewCertificateVerifier(verifycert.CertificateVerifierOptions{
		ModelPath:        modelPath,
		SignaturePath:    bundlePath,
		CertificateChain: certChain,
		Logger:           logger,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "certificate verifier error: %v\n", err)
		return 1
	}
	result, err := v.Verify(ctx)
	if err != nil || !result.Verified {
		fmt.Fprintf(os.Stderr, "verify error: %v\n", err)
		return 1
	}
	return 0
}
