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
	"errors"
	"fmt"
	"os"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/sigstore/model-signing/pkg/config"
	"github.com/sigstore/model-signing/pkg/interfaces"
	sign "github.com/sigstore/model-signing/pkg/signature"
	"github.com/sigstore/model-signing/pkg/utils"
	"github.com/sigstore/sigstore-go/pkg/bundle"
	"github.com/sigstore/sigstore-go/pkg/root"
	sigstoresign "github.com/sigstore/sigstore-go/pkg/sign"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
	"github.com/sigstore/sigstore/pkg/oauthflow"
	"golang.org/x/oauth2"
)

// Ensure LocalSigstoreSigner implements interfaces.Signer at compile time.
var _ interfaces.Signer = (*LocalSigstoreSigner)(nil)

// SigstoreSignerConfig holds configuration for creating a Sigstore signer.
//
//nolint:revive
type SigstoreSignerConfig struct {
	// TrustRootConfig provides Sigstore trust root loading functionality.
	config.TrustRootConfig

	UseAmbientCredentials bool   // UseAmbientCredentials uses OIDC tokens from environment variables.
	IdentityToken         string // IdentityToken is a pre-obtained OIDC token.
	OAuthForceOob         bool   // OAuthForceOob forces out-of-band OAuth flow (manual code entry).
	ClientID              string // ClientID is the OAuth client ID.
	ClientSecret          string // ClientSecret is the OAuth client secret.
}

// LocalSigstoreSigner signs model manifests using Sigstore/Fulcio.
// Implements the interfaces.Signer interface.
type LocalSigstoreSigner struct {
	config    SigstoreSignerConfig
	trustRoot *root.TrustedRoot
}

// NewLocalSigstoreSigner creates a new Sigstore signer with the given configuration.
// Loads the trust root for Sigstore verification.
// Returns an error if trust root loading fails.
func NewLocalSigstoreSigner(config SigstoreSignerConfig) (*LocalSigstoreSigner, error) {
	// Load trust root using shared configuration primitive
	trustRoot, err := config.LoadTrustRoot()
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
// Signing flow:
// 1. Generates an ephemeral keypair
// 2. Obtains an OIDC token (from ambient credentials, provided token, or interactive flow)
// 3. Gets a short-lived certificate from Fulcio
// 4. Creates a DSSE envelope with the payload
// 5. Signs the envelope
// 6. Logs the signature to Rekor for transparency
// 7. Returns a bundle containing everything needed for verification
//
// Returns an error if any step fails.
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

// oobIDTokenGetter implements the out-of-band OAuth flow.
// Displays the auth URL and prompts the user to manually enter the verification code.
type oobIDTokenGetter struct{}

// GetIDToken implements the OOB flow without attempting to open a browser.
// Returns the OIDC ID token or an error if authentication fails.
func (o *oobIDTokenGetter) GetIDToken(p *oidc.Provider, cfg oauth2.Config) (*oauthflow.OIDCIDToken, error) {
	// Use the OOB redirect URI which tells the OAuth provider to display the code in the browser
	cfg.RedirectURL = "urn:ietf:wg:oauth:2.0:oob"

	// PKCE is required for security
	pkce, err := oauthflow.NewPKCE(p)
	if err != nil {
		return nil, err
	}

	// Generate state and nonce
	state := randomString(128)
	nonce := randomString(128)

	// Build auth URL with PKCE
	opts := append(pkce.AuthURLOpts(), oauth2.AccessTypeOnline, oidc.Nonce(nonce))
	authURL := cfg.AuthCodeURL(state, opts...)

	// Display URL and prompt for code
	fmt.Println("Go to the following link in a browser:")
	fmt.Printf("\n\t%s\n", authURL)
	fmt.Print("Enter verification code: ")

	// Read code from stdin
	var code string
	_, err = fmt.Scanln(&code)
	if err != nil {
		return nil, fmt.Errorf("failed to read verification code: %w", err)
	}

	// Exchange code for token
	token, err := cfg.Exchange(context.Background(), code, append(pkce.TokenURLOpts(), oidc.Nonce(nonce))...)
	if err != nil {
		return nil, fmt.Errorf("failed to exchange code for token: %w", err)
	}

	// Extract and verify ID token
	idToken, ok := token.Extra("id_token").(string)
	if !ok {
		return nil, errors.New("id_token not present in token response")
	}

	// Verify the ID token
	verifier := p.Verifier(&oidc.Config{ClientID: cfg.ClientID})
	parsedIDToken, err := verifier.Verify(context.Background(), idToken)
	if err != nil {
		return nil, fmt.Errorf("failed to verify ID token: %w", err)
	}

	// Verify nonce
	if parsedIDToken.Nonce != nonce {
		return nil, errors.New("nonce mismatch")
	}

	// Verify access token hash if present
	if parsedIDToken.AccessTokenHash != "" {
		if err := parsedIDToken.VerifyAccessToken(token.AccessToken); err != nil {
			return nil, fmt.Errorf("failed to verify access token: %w", err)
		}
	}

	// Extract subject
	email, err := oauthflow.SubjectFromToken(parsedIDToken)
	if err != nil {
		return nil, err
	}

	return &oauthflow.OIDCIDToken{
		RawString: idToken,
		Subject:   email,
	}, nil
}

// randomString generates a cryptographically secure random URL-safe string.
// Used for OAuth state and nonce parameters.
func randomString(length int) string {
	return cryptoutils.GenerateRandomURLSafeString(uint(length))
}

// getIDToken obtains an OIDC identity token based on configuration.
//
// Priority order:
// 1. Uses provided identity token if available
// 2. Uses ambient credentials if configured
// 3. Falls back to interactive OAuth flow
//
// Returns the ID token string or an error if token acquisition fails.
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
		// Use out-of-band (OOB) OAuth flow
		// User opens browser manually, logs in, and copies verification code
		// This uses redirect_uri=urn:ietf:wg:oauth:2.0:oob
		tokenGetter := &oobIDTokenGetter{}

		token, err = oauthflow.OIDConnect(issuerURL, clientID, clientSecret, "", tokenGetter)
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
