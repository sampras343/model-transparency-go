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

package options

import (
	"github.com/spf13/cobra"

	cert "github.com/sigstore/model-signing/pkg/verify/certificate"
	key "github.com/sigstore/model-signing/pkg/verify/key"
	sigstore "github.com/sigstore/model-signing/pkg/verify/sigstore"
)

// SigstoreVerifyOptions holds the command-line options for Sigstore-based verification.
type SigstoreVerifyOptions struct {
	ModelPathFlags
	SignatureInputFlags
	SigstoreFlags
	IgnoreUnsignedFlags
	// Identity specifies the expected identity of the signer (e.g., email address).
	Identity string
	// IdentityProvider specifies the expected identity provider URL.
	IdentityProvider string
}

// AddFlags adds Sigstore verification flags to the cobra command.
func (o *SigstoreVerifyOptions) AddFlags(cmd *cobra.Command) {
	AddAllFlags(cmd, &o.ModelPathFlags, &o.SignatureInputFlags, &o.SigstoreFlags, &o.IgnoreUnsignedFlags)

	cmd.Flags().StringVar(&o.Identity, "identity", "", "The expected identity of the signer (e.g., name@example.com).")
	_ = cmd.MarkFlagRequired("identity")
	cmd.Flags().StringVar(&o.IdentityProvider, "identity-provider", "", "The expected identity provider (e.g., https://accounts.example.com).")
	_ = cmd.MarkFlagRequired("identity-provider")
}

// KeyVerifyOptions holds the command-line options for key-based verification.
type KeyVerifyOptions struct {
	ModelPathFlags
	SignatureInputFlags
	IgnoreUnsignedFlags
	// PublicKeyPath provides the path to the public key file for verification.
	PublicKeyPath string
}

// AddFlags adds key-based verification flags to the cobra command.
func (o *KeyVerifyOptions) AddFlags(cmd *cobra.Command) {
	AddAllFlags(cmd, &o.ModelPathFlags, &o.SignatureInputFlags, &o.IgnoreUnsignedFlags)

	cmd.Flags().StringVar(&o.PublicKeyPath, "public-key", "", "Location of the public key file to verify.")
	_ = cmd.MarkFlagRequired("public-key")
}

// CertificateVerifyOptions holds the command-line options for certificate-based verification.
type CertificateVerifyOptions struct {
	ModelPathFlags
	SignatureInputFlags
	IgnoreUnsignedFlags
	// CertificateChain provides file paths for the certificate chain of trust.
	CertificateChain []string
	// LogFingerprints enables logging of SHA256 fingerprints for all certificates.
	LogFingerprints bool
}

// AddFlags adds certificate-based verification flags to the cobra command.
func (o *CertificateVerifyOptions) AddFlags(cmd *cobra.Command) {
	AddAllFlags(cmd, &o.ModelPathFlags, &o.SignatureInputFlags, &o.IgnoreUnsignedFlags)

	cmd.Flags().StringSliceVar(&o.CertificateChain, "certificate-chain", nil, "File paths of certificate chain of trust (can be repeated or comma-separated)")
	cmd.Flags().BoolVar(&o.LogFingerprints, "log-fingerprints", false, "Log SHA256 fingerprints of all certificates")
}

// ToStandardOptions converts CLI options to library options for Sigstore verification.
// It maps command-line flags to the standard SigstoreVerifierOptions structure
// used by the verification library.
//
// The modelPath parameter specifies the path to the model to be verified.
// Returns a SigstoreVerifierOptions struct with all fields populated from CLI flags.
func (o *SigstoreVerifyOptions) ToStandardOptions(modelPath string) sigstore.SigstoreVerifierOptions {
	return sigstore.SigstoreVerifierOptions{
		ModelPath:           modelPath,
		SignaturePath:       o.SignatureInputFlags.SignaturePath,
		IgnorePaths:         o.ModelPathFlags.IgnorePaths,
		IgnoreGitPaths:      o.ModelPathFlags.IgnoreGitPaths,
		AllowSymlinks:       o.ModelPathFlags.AllowSymlinks,
		UseStaging:          o.SigstoreFlags.UseStaging,
		Identity:            o.Identity,
		IdentityProvider:    o.IdentityProvider,
		TrustConfigPath:     o.SigstoreFlags.TrustConfigPath,
		IgnoreUnsignedFiles: o.IgnoreUnsignedFlags.IgnoreUnsignedFiles,
	}
}

// ToStandardOptions converts CLI options to library options for key-based verification.
// It maps command-line flags to the standard KeyVerifierOptions structure
// used by the verification library.
//
// The modelPath parameter specifies the path to the model to be verified.
// Returns a KeyVerifierOptions struct with all fields populated from CLI flags.
func (o *KeyVerifyOptions) ToStandardOptions(modelPath string) key.KeyVerifierOptions {
	return key.KeyVerifierOptions{
		ModelPath:           modelPath,
		SignaturePath:       o.SignatureInputFlags.SignaturePath,
		IgnorePaths:         o.ModelPathFlags.IgnorePaths,
		IgnoreGitPaths:      o.ModelPathFlags.IgnoreGitPaths,
		AllowSymlinks:       o.ModelPathFlags.AllowSymlinks,
		PublicKeyPath:       o.PublicKeyPath,
		IgnoreUnsignedFiles: o.IgnoreUnsignedFlags.IgnoreUnsignedFiles,
	}
}

// ToStandardOptions converts CLI options to library options for certificate-based verification.
// It maps command-line flags to the standard CertificateVerifierOptions structure
// used by the verification library.
//
// The modelPath parameter specifies the path to the model to be verified.
// Returns a CertificateVerifierOptions struct with all fields populated from CLI flags.
func (o *CertificateVerifyOptions) ToStandardOptions(modelPath string) cert.CertificateVerifierOptions {
	return cert.CertificateVerifierOptions{
		ModelPath:           modelPath,
		SignaturePath:       o.SignatureInputFlags.SignaturePath,
		IgnorePaths:         o.ModelPathFlags.IgnorePaths,
		IgnoreGitPaths:      o.ModelPathFlags.IgnoreGitPaths,
		AllowSymlinks:       o.ModelPathFlags.AllowSymlinks,
		CertificateChain:    o.CertificateChain,
		IgnoreUnsignedFiles: o.IgnoreUnsignedFlags.IgnoreUnsignedFiles,
		LogFingerprints:     o.LogFingerprints,
	}
}
