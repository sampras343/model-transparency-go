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
//
//	go-conformance verify-model --method key|certificate --model-path DIR \
//	               --bundle FILE [--public-key PEM] [--cert-chain PEM...] \
//	               [--ignore-paths PATH...] [--ignore-unsigned-files]
//
// The adapter calls the `model-signing` binary from PATH (or MODEL_SIGNING_BIN env var).
package main

import (
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

func modelSigningBin() string {
	if bin := os.Getenv("MODEL_SIGNING_BIN"); bin != "" {
		return bin
	}
	return "model-signing"
}

// stringSlice is a flag.Value that collects repeated --flag values.
type stringSlice []string

func (s *stringSlice) String() string  { return strings.Join(*s, ",") }
func (s *stringSlice) Set(v string) error { *s = append(*s, v); return nil }

func run(args []string) int {
	if len(args) < 1 {
		fmt.Fprintln(os.Stderr, "Usage: go-conformance <sign-model|verify-model> [flags]")
		return 2
	}

	switch args[0] {
	case "sign-model":
		return signModel(args[1:])
	case "verify-model":
		return verifyModel(args[1:])
	default:
		fmt.Fprintf(os.Stderr, "Unknown command: %s\n", args[0])
		return 2
	}
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
	c := exec.Command(args[0], args[1:]...)
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
