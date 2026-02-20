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
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/sigstore/model-signing/pkg/utils"
	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
	"github.com/sigstore/sigstore/pkg/oauthflow"
	"golang.org/x/oauth2"
)

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
func (s *SigstoreSigner) getIDToken(_ context.Context) (string, error) {
	// If a token is explicitly provided, use it
	if s.opts.IdentityToken != "" {
		return s.opts.IdentityToken, nil
	}

	// Determine OIDC issuer URL
	issuerURL, err := s.getOIDCIssuerURL()
	if err != nil {
		return "", fmt.Errorf("failed to get OIDC issuer URL: %w", err)
	}

	// Check for ambient credentials (GitHub Actions, etc.)
	if s.opts.UseAmbientCredentials {
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
	clientID := s.opts.ClientID
	if clientID == "" {
		clientID = utils.DefaultClientID
	}

	clientSecret := s.opts.ClientSecret

	var token *oauthflow.OIDCIDToken

	if s.opts.OAuthForceOob {
		// Use out-of-band (OOB) OAuth flow
		tokenGetter := &oobIDTokenGetter{}
		token, err = oauthflow.OIDConnect(issuerURL, clientID, clientSecret, "", tokenGetter)
	} else {
		// Use interactive flow with automatic browser and local callback server
		redirectURL := ""
		tokenGetter := oauthflow.DefaultIDTokenGetter
		token, err = oauthflow.OIDConnect(issuerURL, clientID, clientSecret, redirectURL, tokenGetter)
	}

	if err != nil {
		return "", fmt.Errorf("failed to get ID token via OIDC flow: %w", err)
	}

	return token.RawString, nil
}

// getFulcioURL returns the Fulcio CA URL to use for certificate issuance.
// If a SigningConfig is available, it selects the appropriate service from it.
// Otherwise, falls back to default Sigstore URLs.
func (s *SigstoreSigner) getFulcioURL() (string, error) {
	// Use SigningConfig if available (custom trust-config was provided)
	if s.signingConfig != nil {
		services := s.signingConfig.FulcioCertificateAuthorityURLs()
		if len(services) > 0 {
			service, err := root.SelectService(services, []uint32{1}, time.Now())
			if err != nil {
				return "", fmt.Errorf("failed to select Fulcio service: %w", err)
			}
			return service.URL, nil
		}
	}

	// Fall back to default URLs
	if s.opts.UseStaging {
		return utils.FulcioStagingURL, nil
	}
	return utils.FulcioProdURL, nil
}

// getRekorURL returns the Rekor transparency log URL to use.
// If a SigningConfig is available, it selects the appropriate service from it.
// Otherwise, falls back to default Sigstore URLs.
func (s *SigstoreSigner) getRekorURL() (string, error) {
	// Use SigningConfig if available (custom trust-config was provided)
	if s.signingConfig != nil {
		services := s.signingConfig.RekorLogURLs()
		if len(services) > 0 {
			service, err := root.SelectService(services, []uint32{1}, time.Now())
			if err != nil {
				return "", fmt.Errorf("failed to select Rekor service: %w", err)
			}
			return service.URL, nil
		}
	}

	// Fall back to default URLs
	if s.opts.UseStaging {
		return utils.RekorStagingURL, nil
	}
	return utils.RekorProdURL, nil
}

// getOIDCIssuerURL returns the OIDC issuer URL to use for authentication.
// If a SigningConfig is available, it selects the appropriate service from it.
// Otherwise, falls back to default Sigstore URLs.
func (s *SigstoreSigner) getOIDCIssuerURL() (string, error) {
	// Use SigningConfig if available (custom trust-config was provided)
	if s.signingConfig != nil {
		services := s.signingConfig.OIDCProviderURLs()
		if len(services) > 0 {
			service, err := root.SelectService(services, []uint32{1}, time.Now())
			if err != nil {
				return "", fmt.Errorf("failed to select OIDC provider: %w", err)
			}
			return service.URL, nil
		}
	}

	// Fall back to default URLs
	if s.opts.UseStaging {
		return utils.IssuerStagingURL, nil
	}
	return utils.IssuerProdURL, nil
}
