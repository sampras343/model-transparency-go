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

//go:build pkcs11

package cli

import (
	"context"
	"fmt"
	"time"

	"github.com/spf13/cobra"

	"github.com/sigstore/model-signing/cmd/model-signing/cli/options"
	"github.com/sigstore/model-signing/pkg/logging"
	pkcs11 "github.com/sigstore/model-signing/pkg/signing/pkcs11"
	"github.com/sigstore/model-signing/pkg/tracing"
)

func init() {
	additionalSignCommandRegistrations = append(additionalSignCommandRegistrations,
		NewPkcs11KeySigner(),
		NewPkcs11CertificateSigner(),
	)
}

// NewPkcs11KeySigner creates the pkcs11-key subcommand for model signing.
func NewPkcs11KeySigner() *cobra.Command {
	o := &options.Pkcs11SignOptions{}

	long := `Sign using a private key using a PKCS #11 URI.

    Signing the model at MODEL_PATH, produces the signature at SIGNATURE_PATH
    (as per --signature option). Files in IGNORE_PATHS are not part of the
    signature.

    Traditionally, signing could be achieved by using a public/private key pair.
    Pass the PKCS #11 URI of the signing key using --pkcs11-uri.

    The PKCS#11 URI format follows RFC 7512:
      pkcs11:token=TOKEN;object=KEY?module-name=MODULE&pin-value=PIN

    Note that this method does not provide a way to tie to the identity of the
    signer, outside of pairing the keys. Also note that we don't offer key
    management protocols.`

	cmd := &cobra.Command{
		Use:   "pkcs11-key [OPTIONS] MODEL_PATH",
		Short: "Sign using a private key using a PKCS #11 URI.",
		Long:  long,
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			modelPath := args[0]
			opts := o.ToStandardOptions(modelPath)
			opts.Logger = ro.NewObservability().Logger

			attrs := map[string]interface{}{
				"model_signing.method":           "pkcs11-key",
				"model_signing.model_path":       modelPath,
				"model_signing.allow_symlinks":   opts.AllowSymlinks,
				"model_signing.ignore_git_paths": opts.IgnoreGitPaths,
				"model_signing.pkcs11_uri":       pkcs11.SanitizeURI(opts.URI),
			}
			return tracing.Run(cmd.Context(), "Sign", attrs, func(ctx context.Context) error {
				signer, err := pkcs11.NewPkcs11Signer(opts)
				if err != nil {
					return err
				}
				ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
				defer cancel()
				status, err := signer.Sign(ctx)
				if ro.GetLogLevel() < logging.LevelSilent {
					fmt.Println(status.Message)
				}
				return err
			})
		},
	}

	o.AddFlags(cmd)
	return cmd
}

// NewPkcs11CertificateSigner creates the pkcs11-certificate subcommand for model signing.
func NewPkcs11CertificateSigner() *cobra.Command {
	o := &options.Pkcs11SignOptions{}

	long := `Sign using a certificate.

    Signing the model at MODEL_PATH, produces the signature at SIGNATURE_PATH
    (as per --signature option). Files in IGNORE_PATHS are not part of the
    signature.

    Sign using a certificate with a PKCS #11 URI. This is similar to
    certificate-based signing, but the private key is accessed via PKCS #11.

    Pass the PKCS #11 URI of the signing key using --pkcs11-uri, the signing
    certificate using --signing-certificate, and optionally the certificate
    chain using --certificate-chain.

    The PKCS#11 URI format follows RFC 7512:
      pkcs11:token=TOKEN;object=KEY?module-name=MODULE&pin-value=PIN`

	cmd := &cobra.Command{
		Use:   "pkcs11-certificate [OPTIONS] MODEL_PATH",
		Short: "Sign using a certificate.",
		Long:  long,
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			modelPath := args[0]
			opts := o.ToStandardOptions(modelPath)
			opts.Logger = ro.NewObservability().Logger

			attrs := map[string]interface{}{
				"model_signing.method":              "pkcs11-certificate",
				"model_signing.model_path":          modelPath,
				"model_signing.allow_symlinks":      opts.AllowSymlinks,
				"model_signing.ignore_git_paths":    opts.IgnoreGitPaths,
				"model_signing.pkcs11_uri":          pkcs11.SanitizeURI(opts.URI),
				"model_signing.signing_certificate": opts.SigningCertificatePath,
			}
			return tracing.Run(cmd.Context(), "Sign", attrs, func(ctx context.Context) error {
				signer, err := pkcs11.NewPkcs11Signer(opts)
				if err != nil {
					return err
				}
				ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
				defer cancel()
				status, err := signer.Sign(ctx)
				if ro.GetLogLevel() < logging.LevelSilent {
					fmt.Println(status.Message)
				}
				return err
			})
		},
	}

	o.AddFlags(cmd)
	o.AddCertificateFlags(cmd)
	return cmd
}
