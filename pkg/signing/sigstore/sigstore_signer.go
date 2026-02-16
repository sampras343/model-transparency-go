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

// Package sigstore provides Sigstore/Fulcio-based signing using sigstore-go.
package sigstore

import (
	"context"
	"fmt"
	"path/filepath"

	"github.com/sigstore/model-signing/pkg/config"
	"github.com/sigstore/model-signing/pkg/logging"
	"github.com/sigstore/model-signing/pkg/modelartifact"
	"github.com/sigstore/model-signing/pkg/signing"
	"github.com/sigstore/model-signing/pkg/utils"
	"github.com/sigstore/sigstore-go/pkg/root"
	sigstoresign "github.com/sigstore/sigstore-go/pkg/sign"
)

// Ensure SigstoreSigner implements signing.ModelSigner at compile time.
var _ signing.ModelSigner = (*SigstoreSigner)(nil)

// SigstoreSignerOptions configures a SigstoreSigner instance.
//
//nolint:revive
type SigstoreSignerOptions struct {
	ModelPath             string         // ModelPath is the path to the model directory or file to sign.
	SignaturePath         string         // SignaturePath is where the signature file will be written.
	IgnorePaths           []string       // IgnorePaths specifies paths to exclude from hashing.
	IgnoreGitPaths        bool           // IgnoreGitPaths indicates whether to exclude git-ignored files.
	AllowSymlinks         bool           // AllowSymlinks indicates whether to follow symbolic links.
	Logger                logging.Logger // Logger is used for debug and info output.
	UseStaging            bool           // UseStaging indicates whether to use Sigstore staging infrastructure.
	OAuthForceOob         bool           // OAuthForceOob forces out-of-band OAuth flow.
	UseAmbientCredentials bool           // UseAmbientCredentials uses ambient OIDC credentials instead of interactive OAuth.
	IdentityToken         string         // IdentityToken is a pre-obtained OIDC identity token.
	ClientID              string         // ClientID is the OAuth client ID.
	ClientSecret          string         // ClientSecret is the OAuth client secret.
	TrustConfigPath       string         // TrustConfigPath is an optional path to custom trust root configuration.
}

// SigstoreSigner implements ModelSigner using Sigstore/Fulcio signing.
//
// Uses sigstore-go's sign.Bundle() API with an ephemeral keypair, Fulcio for
// certificate issuance, and Rekor for transparency log entries.
//
//nolint:revive
type SigstoreSigner struct {
	opts          SigstoreSignerOptions
	logger        logging.Logger
	trustRoot     *root.TrustedRoot
	signingConfig *root.SigningConfig // May be nil if using default Sigstore infrastructure
}

// NewSigstoreSigner creates a new SigstoreSigner with the given options.
// Validates that required paths exist and loads the trust root.
// Returns an error if validation or trust root loading fails.
func NewSigstoreSigner(opts SigstoreSignerOptions) (*SigstoreSigner, error) {
	if err := signing.ValidateSignerPaths(opts.ModelPath, opts.IgnorePaths); err != nil {
		return nil, err
	}
	// Validate trust config path if provided
	if err := utils.ValidateOptionalFile("trust config", opts.TrustConfigPath); err != nil {
		return nil, err
	}

	// Load trust root
	trustRootConfig := config.TrustRootConfig{
		UseStaging:    opts.UseStaging,
		TrustRootPath: opts.TrustConfigPath,
	}

	var trustRoot *root.TrustedRoot
	var signingConfig *root.SigningConfig
	var err error

	// Only load SigningConfig when a custom trust-config file is provided
	if opts.TrustConfigPath != "" && !opts.UseStaging {
		trustRoot, signingConfig, err = trustRootConfig.LoadTrustMaterial()
		if err != nil {
			return nil, fmt.Errorf("failed to load trust material: %w", err)
		}
	} else {
		// Default workflow: only load TrustedRoot
		trustRoot, err = trustRootConfig.LoadTrustRoot()
		if err != nil {
			return nil, fmt.Errorf("failed to load trust root: %w", err)
		}
	}

	return &SigstoreSigner{
		opts:          opts,
		logger:        logging.EnsureLogger(opts.Logger),
		trustRoot:     trustRoot,
		signingConfig: signingConfig,
	}, nil
}

// Sign performs the complete signing flow.
//
// Orchestrates:
// 1. Canonicalizing the model to create a manifest (via modelartifact)
// 2. Marshaling the manifest to an in-toto payload (via modelartifact)
// 3. Generating an ephemeral keypair and obtaining an OIDC token
// 4. Signing via sigstore-go's sign.Bundle() with Fulcio + Rekor
// 5. Writing the signature bundle to disk
//
// Returns a Result with success status and message, or an error if any step fails.
func (s *SigstoreSigner) Sign(ctx context.Context) (signing.Result, error) {
	// Print signing configuration (debug only)
	s.logger.Debugln("Sigstore Signing")
	s.logger.Debug("  MODEL_PATH:                %s", filepath.Clean(s.opts.ModelPath))
	s.logger.Debug("  --signature:               %s", filepath.Clean(s.opts.SignaturePath))
	s.logger.Debug("  --ignore-paths:            %v", s.opts.IgnorePaths)
	s.logger.Debug("  --ignore-git-paths:        %v", s.opts.IgnoreGitPaths)
	s.logger.Debug("  --allow-symlinks:          %v", s.opts.AllowSymlinks)
	s.logger.Debug("  --use-staging:             %v", s.opts.UseStaging)
	s.logger.Debug("  --oauth-force-oob:         %v", s.opts.OAuthForceOob)
	s.logger.Debug("  --use-ambient-credentials: %v", s.opts.UseAmbientCredentials)
	s.logger.Debug("  --identity-token:          %v", utils.MaskToken(s.opts.IdentityToken))
	s.logger.Debug("  --client-id:               %v", s.opts.ClientID)
	s.logger.Debug("  --client-secret:           %v", utils.MaskToken(s.opts.ClientSecret))
	s.logger.Debug("  --trust-config:            %v", s.opts.TrustConfigPath)

	// Steps 1-2: Canonicalize the model and marshal payload
	_, payload, err := signing.PreparePayload(s.opts.ModelPath, s.opts.SignaturePath, modelartifact.Options{
		IgnorePaths:    s.opts.IgnorePaths,
		IgnoreGitPaths: s.opts.IgnoreGitPaths,
		AllowSymlinks:  s.opts.AllowSymlinks,
		Logger:         s.logger,
	}, s.logger)
	if err != nil {
		return signing.Result{
			Verified: false,
			Message:  fmt.Sprintf("Failed to prepare payload: %v", err),
		}, err
	}

	// Step 3: Sign with Sigstore (ephemeral keypair + Fulcio + Rekor)
	s.logger.Debugln("\nStep 3: Signing with Sigstore...")

	// Create DSSE content
	content := &sigstoresign.DSSEData{
		Data:        payload,
		PayloadType: utils.InTotoJSONPayloadType,
	}

	// Generate ephemeral keypair
	keypair, err := sigstoresign.NewEphemeralKeypair(nil)
	if err != nil {
		return signing.Result{
			Verified: false,
			Message:  fmt.Sprintf("Failed to generate keypair: %v", err),
		}, fmt.Errorf("failed to generate ephemeral keypair: %w", err)
	}

	// Get OIDC token
	idToken, err := s.getIDToken(ctx)
	if err != nil {
		return signing.Result{
			Verified: false,
			Message:  fmt.Sprintf("Failed to get identity token: %v", err),
		}, fmt.Errorf("failed to get identity token: %w", err)
	}

	// Configure Fulcio
	fulcioURL, err := s.getFulcioURL()
	if err != nil {
		return signing.Result{
			Verified: false,
			Message:  fmt.Sprintf("Failed to get Fulcio URL: %v", err),
		}, fmt.Errorf("failed to get Fulcio URL: %w", err)
	}
	fulcio := sigstoresign.NewFulcio(&sigstoresign.FulcioOptions{
		BaseURL: fulcioURL,
	})

	// Configure Rekor
	rekorURL, err := s.getRekorURL()
	if err != nil {
		return signing.Result{
			Verified: false,
			Message:  fmt.Sprintf("Failed to get Rekor URL: %v", err),
		}, fmt.Errorf("failed to get Rekor URL: %w", err)
	}
	rekor := sigstoresign.NewRekor(&sigstoresign.RekorOptions{
		BaseURL: rekorURL,
	})

	// Create bundle with all signing components
	bundle, err := sigstoresign.Bundle(content, keypair, sigstoresign.BundleOptions{
		CertificateProvider: fulcio,
		CertificateProviderOptions: &sigstoresign.CertificateProviderOptions{
			IDToken: idToken,
		},
		TransparencyLogs: []sigstoresign.Transparency{rekor},
		Context:          ctx,
		TrustedRoot:      s.trustRoot,
	})
	if err != nil {
		return signing.Result{
			Verified: false,
			Message:  fmt.Sprintf("Failed to sign: %v", err),
		}, fmt.Errorf("failed to create signature bundle: %w", err)
	}
	s.logger.Debugln("  Signing successful")

	// Step 4: Write bundle to disk
	s.logger.Debugln("\nStep 4: Writing signature...")
	if err := signing.WriteBundle(bundle, s.opts.SignaturePath); err != nil {
		return signing.Result{
			Verified: false,
			Message:  fmt.Sprintf("Failed to write signature: %v", err),
		}, err
	}

	s.logger.Debug("\nSignature written to: %s", s.opts.SignaturePath)

	return signing.Result{
		Verified: true,
		Message:  fmt.Sprintf("Successfully signed model and saved signature to %s", s.opts.SignaturePath),
	}, nil
}
