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

	cert "github.com/sigstore/model-signing/pkg/signing/certificate"
	key "github.com/sigstore/model-signing/pkg/signing/key"
	pkcs11 "github.com/sigstore/model-signing/pkg/signing/pkcs11"
	sigstore "github.com/sigstore/model-signing/pkg/signing/sigstore"
)

// SigstoreSignOptions holds the command-line options for Sigstore-based signing.
type SigstoreSignOptions struct {
	ModelPathFlags
	SignatureOutputFlags
	SigstoreFlags
	// OAuthForceOob forces an out-of-band OAuth flow without opening a browser.
	OAuthForceOob bool
	// UseAmbientCredentials enables using credentials from the ambient environment.
	UseAmbientCredentials bool
	// IdentityToken provides a fixed OIDC identity token instead of obtaining one via OIDC flow.
	IdentityToken string
	// ClientID specifies a custom OpenID Connect client ID for OAuth2.
	ClientID string
	// ClientSecret specifies a custom OpenID Connect client secret for OAuth2.
	ClientSecret string
}

// AddFlags adds Sigstore signing flags to the cobra command.
func (o *SigstoreSignOptions) AddFlags(cmd *cobra.Command) {
	AddAllFlags(cmd, &o.ModelPathFlags, &o.SignatureOutputFlags, &o.SigstoreFlags)

	cmd.Flags().BoolVar(&o.OAuthForceOob, "oauth-force-oob", false, "Force an out-of-band OAuth flow and do not automatically start the default web browser.")
	cmd.Flags().BoolVar(&o.UseAmbientCredentials, "use-ambient-credentials", false, "Use credentials from ambient environment.")
	cmd.Flags().StringVar(&o.IdentityToken, "identity-token", "", "Fixed OIDC identity token to use instead of obtaining credentials from OIDC flow or from the environment.")
	cmd.Flags().StringVar(&o.ClientID, "client-id", "", "The custom OpenID Connect client ID to use during OAuth2.")
	cmd.Flags().StringVar(&o.ClientSecret, "client-secret", "", "The custom OpenID Connect client secret to use during OAuth2.")
}

// ToStandardOptions converts CLI options to library options for Sigstore signing.
// It maps command-line flags to the standard SigstoreSignerOptions structure
// used by the signing library.
//
// The modelPath parameter specifies the path to the model to be signed.
// Returns a SigstoreSignerOptions struct with all fields populated from CLI flags.
// nolint:staticcheck
func (o *SigstoreSignOptions) ToStandardOptions(modelPath string) sigstore.SigstoreSignerOptions {
	return sigstore.SigstoreSignerOptions{
		ModelPath:             modelPath,
		SignaturePath:         o.SignatureOutputFlags.SignaturePath,
		IgnorePaths:           o.ModelPathFlags.IgnorePaths,
		IgnoreGitPaths:        o.ModelPathFlags.IgnoreGitPaths,
		AllowSymlinks:         o.ModelPathFlags.AllowSymlinks,
		UseStaging:            o.SigstoreFlags.UseStaging,
		OAuthForceOob:         o.OAuthForceOob,
		UseAmbientCredentials: o.UseAmbientCredentials,
		IdentityToken:         o.IdentityToken,
		ClientID:              o.ClientID,
		ClientSecret:          o.ClientSecret,
		TrustConfigPath:       o.SigstoreFlags.TrustConfigPath,
	}
}

// KeySignOptions holds the command-line options for key-based signing.
// It embeds composable flag groups and adds key-specific configuration options.
type KeySignOptions struct {
	ModelPathFlags
	SignatureOutputFlags
	// Password specifies the password for encrypted private keys.
	Password string
	// PrivateKeyPath provides the path to the PEM-encoded private key file.
	PrivateKeyPath string
}

// AddFlags adds key-based signing flags to the cobra command.
// This includes model path flags, signature output flags, and key-specific options.
// The private-key flag is marked as required.
func (o *KeySignOptions) AddFlags(cmd *cobra.Command) {
	AddAllFlags(cmd, &o.ModelPathFlags, &o.SignatureOutputFlags)

	cmd.Flags().StringVar(&o.PrivateKeyPath, "private-key", "", "Path to the private key, as a PEM-encoded file. [required]")
	_ = cmd.MarkFlagRequired("private-key")
	cmd.Flags().StringVar(&o.Password, "password", "", "Password for the key encryption, if any.")
}

// ToStandardOptions converts CLI options to library options for key-based signing.
// It maps command-line flags to the standard KeySignerOptions structure
// used by the signing library.
//
// The modelPath parameter specifies the path to the model to be signed.
// Returns a KeySignerOptions struct with all fields populated from CLI flags.
// nolint:staticcheck
func (o *KeySignOptions) ToStandardOptions(modelPath string) key.KeySignerOptions {
	return key.KeySignerOptions{
		ModelPath:      modelPath,
		SignaturePath:  o.SignatureOutputFlags.SignaturePath,
		IgnorePaths:    o.ModelPathFlags.IgnorePaths,
		IgnoreGitPaths: o.ModelPathFlags.IgnoreGitPaths,
		AllowSymlinks:  o.ModelPathFlags.AllowSymlinks,
		PrivateKeyPath: o.PrivateKeyPath,
		Password:       o.Password,
	}
}

// CertificateSignOptions holds the command-line options for certificate-based signing.
// It embeds composable flag groups and adds cert-specific configuration options.
type CertificateSignOptions struct {
	ModelPathFlags
	SignatureOutputFlags
	// PrivateKeyPath provides the path to the PEM-encoded private key file.
	PrivateKeyPath string
	// SigningCertificatePath provides the path to the PEM-encoded signing certificate file.
	SigningCertificatePath string
	// CertificateChain provides file paths for the certificate chain of trust.
	CertificateChain []string
}

// AddFlags adds cert-based signing flags to the cobra command.
// The private-key flag is marked as required.
func (o *CertificateSignOptions) AddFlags(cmd *cobra.Command) {
	AddAllFlags(cmd, &o.ModelPathFlags, &o.SignatureOutputFlags)

	cmd.Flags().StringVar(&o.PrivateKeyPath, "private-key", "", "Path to the private key, as a PEM-encoded file. [required]")
	_ = cmd.MarkFlagRequired("private-key")

	cmd.Flags().StringVar(&o.SigningCertificatePath, "signing-certificate", "", "Path to the signing certificate, as a PEM-encoded file. [required]")
	_ = cmd.MarkFlagRequired("signing-certificate")

	cmd.Flags().StringSliceVar(&o.CertificateChain, "certificate-chain", nil, "File paths of certificate chain of trust (can be repeated or comma-separated)")
}

// ToStandardOptions converts CLI options to library options for cert-based signing.
// It maps command-line flags to the standard CertificateSignOptions structure
// used by the signing library.
//
// The modelPath parameter specifies the path to the model to be signed.
// Returns a CertificateSignOptions struct with all fields populated from CLI flags.
// nolint:staticcheck
func (o *CertificateSignOptions) ToStandardOptions(modelPath string) cert.CertificateSignerOptions {
	return cert.CertificateSignerOptions{
		ModelPath:              modelPath,
		SignaturePath:          o.SignatureOutputFlags.SignaturePath,
		IgnorePaths:            o.ModelPathFlags.IgnorePaths,
		IgnoreGitPaths:         o.ModelPathFlags.IgnoreGitPaths,
		AllowSymlinks:          o.ModelPathFlags.AllowSymlinks,
		PrivateKeyPath:         o.PrivateKeyPath,
		CertificateChain:       o.CertificateChain,
		SigningCertificatePath: o.SigningCertificatePath,
	}
}

// Pkcs11SignOptions holds the command-line options for PKCS#11-based signing.
// It embeds composable flag groups and adds PKCS#11-specific configuration options.
type Pkcs11SignOptions struct {
	ModelPathFlags
	SignatureOutputFlags
	// URI provides the PKCS#11 URI identifying the key and module.
	URI string
	// ModulePaths provides additional directories to search for PKCS#11 modules.
	ModulePaths []string
	// SigningCertificatePath provides the path to the PEM-encoded signing certificate file.
	// If provided, certificate-based signing will be used instead of key-based signing.
	SigningCertificatePath string
	// CertificateChain provides file paths for the certificate chain of trust.
	CertificateChain []string
}

// AddFlags adds the common PKCS#11 signing flags (key-only) to the cobra command.
// The pkcs11-uri flag is marked as required.
func (o *Pkcs11SignOptions) AddFlags(cmd *cobra.Command) {
	AddAllFlags(cmd, &o.ModelPathFlags, &o.SignatureOutputFlags)

	cmd.Flags().StringVar(&o.URI, "pkcs11-uri", "", "PKCS#11 URI identifying the key. Format: pkcs11:token=TOKEN;object=KEY?module-name=MODULE&pin-value=PIN [required]")
	_ = cmd.MarkFlagRequired("pkcs11-uri")

	cmd.Flags().StringSliceVar(&o.ModulePaths, "module-path", nil, "Additional directories to search for PKCS#11 modules.")
}

// AddCertificateFlags adds certificate-specific flags for PKCS#11 certificate-based signing.
func (o *Pkcs11SignOptions) AddCertificateFlags(cmd *cobra.Command) {
	cmd.Flags().StringVar(&o.SigningCertificatePath, "signing-certificate", "", "Path to the signing certificate, as a PEM-encoded file. [required]")
	_ = cmd.MarkFlagRequired("signing-certificate")
	cmd.Flags().StringSliceVar(&o.CertificateChain, "certificate-chain", nil, "File paths of certificate chain of trust (can be repeated or comma-separated).")
}

// ToStandardOptions converts CLI options to library options for PKCS#11-based signing.
// It maps command-line flags to the standard Pkcs11SignerOptions structure
// used by the signing library.
//
// The modelPath parameter specifies the path to the model to be signed.
// Returns a Pkcs11SignerOptions struct with all fields populated from CLI flags.
// nolint:staticcheck
func (o *Pkcs11SignOptions) ToStandardOptions(modelPath string) pkcs11.Pkcs11SignerOptions {
	return pkcs11.Pkcs11SignerOptions{
		ModelPath:              modelPath,
		SignaturePath:          o.SignatureOutputFlags.SignaturePath,
		IgnorePaths:            o.ModelPathFlags.IgnorePaths,
		IgnoreGitPaths:         o.ModelPathFlags.IgnoreGitPaths,
		AllowSymlinks:          o.ModelPathFlags.AllowSymlinks,
		URI:                    o.URI,
		ModulePaths:            o.ModulePaths,
		SigningCertificatePath: o.SigningCertificatePath,
		CertificateChain:       o.CertificateChain,
	}
}
