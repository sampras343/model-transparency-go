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

package sigstore

import (
	"context"
	"fmt"
	"os"

	"github.com/sigstore/model-signing/pkg/config"
	"github.com/sigstore/model-signing/pkg/interfaces"
	sign "github.com/sigstore/model-signing/pkg/signature"
	"github.com/sigstore/model-signing/pkg/utils"
	"github.com/sigstore/sigstore-go/pkg/bundle"
	"github.com/sigstore/sigstore-go/pkg/root"
	sigstoresign "github.com/sigstore/sigstore-go/pkg/sign"
	"github.com/sigstore/sigstore/pkg/oauthflow"
)

// Ensure LocalSigstoreSigner implements interfaces.Signer at compile time.
var _ interfaces.Signer = (*LocalSigstoreSigner)(nil)

// SigstoreSignerConfig holds configuration for creating a Sigstore signer.
//
//nolint:revive
type SigstoreSignerConfig struct {
	// Embedded trust root configuration for loading Sigstore trust roots
	config.TrustRootConfig

	UseAmbientCredentials bool
	IdentityToken         string
	OAuthForceOob         bool
	ClientID              string
	ClientSecret          string
}

// LocalSigstoreSigner signs model manifests using Sigstore.
type LocalSigstoreSigner struct {
	config    SigstoreSignerConfig
	trustRoot *root.TrustedRoot
}

func NewLocalSigstoreSigner(config SigstoreSignerConfig) (*LocalSigstoreSigner, error) {
	// Load trust root using shared configuration primitive
	trustRoot, err := config.TrustRootConfig.LoadTrustRoot()
	if err != nil {
		return nil, err
	}

	return &LocalSigstoreSigner{
		config:    config,
		trustRoot: trustRoot,
	}, nil
}

// Sign signs a payload and returns a Sigstore bundle signature.
//
// The signing flow:
// 1. Generate an ephemeral keypair
// 2. Obtain an OIDC token (from ambient credentials, provided token, or interactive flow)
// 3. Get a short-lived certificate from Fulcio
// 4. Create a DSSE envelope with the payload
// 5. Sign the envelope
// 6. Log the signature to Rekor for transparency
// 7. Return a bundle containing everything needed for verification
func (s *LocalSigstoreSigner) Sign(payload *interfaces.Payload) (interfaces.Signature, error) {
	ctx := context.Background()

	// Convert payload to JSON for DSSE
	payloadJSON, err := payload.ToJSON()
	if err != nil {
		return nil, fmt.Errorf("failed to serialize payload: %w", err)
	}

	// Create DSSE content
	dsseContent := &sigstoresign.DSSEData{
		Data:        payloadJSON,
		PayloadType: utils.InTotoJSONPayloadType,
	}

	// Generate ephemeral keypair
	keypair, err := sigstoresign.NewEphemeralKeypair(nil)
	if err != nil {
		return nil, fmt.Errorf("failed to generate ephemeral keypair: %w", err)
	}

	// Get OIDC token
	idToken, err := s.getIDToken(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get identity token: %w", err)
	}

	// Configure Fulcio for certificate issuance
	fulcioURL := utils.FulcioProdURL
	if s.config.UseStaging {
		fulcioURL = utils.FulcioStagingURL
	}

	fulcio := sigstoresign.NewFulcio(&sigstoresign.FulcioOptions{
		BaseURL: fulcioURL,
	})

	// Configure Rekor for transparency log
	rekorURL := utils.RekorProdURL
	if s.config.UseStaging {
		rekorURL = utils.RekorStagingURL
	}

	rekor := sigstoresign.NewRekor(&sigstoresign.RekorOptions{
		BaseURL: rekorURL,
	})

	// Create bundle with all signing components
	bundleOpts := sigstoresign.BundleOptions{
		CertificateProvider: fulcio,
		CertificateProviderOptions: &sigstoresign.CertificateProviderOptions{
			IDToken: idToken,
		},
		TransparencyLogs: []sigstoresign.Transparency{rekor},
		Context:          ctx,
		TrustedRoot:      s.trustRoot,
	}

	// Sign and create bundle
	protoBundle, err := sigstoresign.Bundle(dsseContent, keypair, bundleOpts)
	if err != nil {
		return nil, fmt.Errorf("failed to create signature bundle: %w", err)
	}

	// Convert protobuf bundle to sigstore-go bundle
	sigstoreBundle, err := bundle.NewBundle(protoBundle)
	if err != nil {
		return nil, fmt.Errorf("failed to create sigstore bundle: %w", err)
	}

	// Wrap in our signature type
	return sign.NewSignature(sigstoreBundle), nil
}

// getIDToken obtains an OIDC identity token based on configuration.
//
// Priority order:
// 1. Use provided identity token if available
// 2. Use ambient credentials if configured
// 3. Fall back to interactive OAuth flow
func (s *LocalSigstoreSigner) getIDToken(_ context.Context) (string, error) {
	// If a token is explicitly provided, use it
	if s.config.IdentityToken != "" {
		return s.config.IdentityToken, nil
	}

	// Determine OIDC issuer URL
	issuerURL := utils.IssuerProdURL
	if s.config.UseStaging {
		issuerURL = utils.IssuerStagingURL
	}

	// Check for ambient credentials (GitHub Actions, etc.)
	if s.config.UseAmbientCredentials {
		// Try common environment variables for OIDC tokens
		token := os.Getenv("SIGSTORE_ID_TOKEN")
		if token == "" {
			token = os.Getenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN")
		}
		if token != "" {
			return token, nil
		}
		return "", fmt.Errorf("ambient credentials requested but SIGSTORE_ID_TOKEN or ACTIONS_ID_TOKEN_REQUEST_TOKEN not found")
	}

	// Get ID token using OAuth flow
	clientID := s.config.ClientID
	if clientID == "" {
		clientID = utils.DefaultClientID
	}

	clientSecret := s.config.ClientSecret

	var token *oauthflow.OIDCIDToken
	var err error

	if s.config.OAuthForceOob {
		// Use device flow (no browser, no local server)
		// User manually enters verification code from provider
		fmt.Println("\nStarting device flow authentication...")
		fmt.Println("You will see a verification code to enter in your browser.")

		tokenGetter := oauthflow.NewDeviceFlowTokenGetterForIssuer(issuerURL)
		redirectURL := "" // Empty for device flow

		token, err = oauthflow.OIDConnect(issuerURL, clientID, clientSecret, redirectURL, tokenGetter)
	} else {
		// Use interactive flow with automatic browser and local callback server
		// Empty redirect URL tells oauthflow to start a local server on a random port
		redirectURL := ""
		tokenGetter := oauthflow.DefaultIDTokenGetter

		token, err = oauthflow.OIDConnect(issuerURL, clientID, clientSecret, redirectURL, tokenGetter)
	}

	if err != nil {
		return "", fmt.Errorf("failed to get ID token via OIDC flow: %w", err)
	}

	return token.RawString, nil
}
