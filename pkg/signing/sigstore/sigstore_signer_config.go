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
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
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

const (
	defaultAudience = "sigstore"
	//nolint:gosec // G101: not a credential, this is a well-known filesystem path
	filesystemTokenPath = "/var/run/sigstore/cosign/oidc-token"
	//nolint:gosec // G101: not a credential, this is an environment variable name
	ambientTokenEnvVar     = "SIGSTORE_ID_TOKEN"
	ghActionsRequestURLVar = "ACTIONS_ID_TOKEN_REQUEST_URL"
	ghActionsRequestTknVar = "ACTIONS_ID_TOKEN_REQUEST_TOKEN"
)

// getIDToken obtains an OIDC identity token based on configuration.
//
// Priority order:
// 1. Uses provided identity token if available
// 2. Uses ambient credentials if configured (SIGSTORE_ID_TOKEN, GitHub Actions, filesystem)
// 3. Falls back to interactive OAuth flow
//
// Returns the ID token string or an error if token acquisition fails.
func (s *SigstoreSigner) getIDToken(ctx context.Context) (string, error) {
	// If a token is explicitly provided, use it
	if s.opts.IdentityToken != "" {
		return s.opts.IdentityToken, nil
	}

	// Determine OIDC issuer URL
	issuerURL, err := s.getOIDCIssuerURL()
	if err != nil {
		return "", fmt.Errorf("failed to get OIDC issuer URL: %w", err)
	}

	if s.opts.UseAmbientCredentials {
		token, err := getAmbientToken(ctx)
		if err != nil {
			return "", fmt.Errorf("ambient credentials requested but no provider succeeded: %w", err)
		}
		return token, nil
	}

	// Get ID token using OAuth flow
	clientID := s.opts.ClientID
	if clientID == "" {
		clientID = utils.DefaultClientID
	}

	clientSecret := s.opts.ClientSecret

	var token *oauthflow.OIDCIDToken

	if s.opts.OAuthForceOob {
		tokenGetter := &oobIDTokenGetter{}
		token, err = oauthflow.OIDConnect(issuerURL, clientID, clientSecret, "", tokenGetter)
	} else {
		redirectURL := ""
		tokenGetter := oauthflow.DefaultIDTokenGetter
		token, err = oauthflow.OIDConnect(issuerURL, clientID, clientSecret, redirectURL, tokenGetter)
	}

	if err != nil {
		return "", fmt.Errorf("failed to get ID token via OIDC flow: %w", err)
	}

	return token.RawString, nil
}

// getAmbientToken tries each ambient OIDC provider in order:
//  1. SIGSTORE_ID_TOKEN environment variable
//  2. GitHub Actions OIDC token request
//  3. Filesystem token at /var/run/sigstore/cosign/oidc-token
func getAmbientToken(ctx context.Context) (string, error) {
	var errs []string

	// 1. Explicit env var
	if token := os.Getenv(ambientTokenEnvVar); token != "" {
		return token, nil
	}

	// 2. GitHub Actions
	token, err := fetchGitHubActionsToken(ctx, defaultAudience)
	if err == nil {
		return token, nil
	}
	errs = append(errs, fmt.Sprintf("github-actions: %v", err))

	// 3. Filesystem
	token, err = readFilesystemToken(filesystemTokenPath)
	if err == nil {
		return token, nil
	}
	errs = append(errs, fmt.Sprintf("filesystem: %v", err))

	return "", fmt.Errorf("%s not set; %s", ambientTokenEnvVar, strings.Join(errs, "; "))
}

// fetchGitHubActionsToken obtains an OIDC token from the GitHub Actions
// runtime. ACTIONS_ID_TOKEN_REQUEST_TOKEN is a bearer credential used to
// request the actual JWT from ACTIONS_ID_TOKEN_REQUEST_URL — it is not the
// OIDC token itself.
func fetchGitHubActionsToken(ctx context.Context, audience string) (string, error) {
	requestURL := os.Getenv(ghActionsRequestURLVar)
	requestToken := os.Getenv(ghActionsRequestTknVar)
	if requestURL == "" || requestToken == "" {
		return "", fmt.Errorf("%s and/or %s not set", ghActionsRequestURLVar, ghActionsRequestTknVar)
	}

	tokenURL := requestURL + "&audience=" + audience
	//nolint:gosec // G704: URL is from ACTIONS_ID_TOKEN_REQUEST_URL set by GitHub Actions runtime
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, tokenURL, nil)
	if err != nil {
		return "", fmt.Errorf("creating request: %w", err)
	}
	req.Header.Set("Authorization", "bearer "+requestToken)

	resp, err := http.DefaultClient.Do(req) //nolint:gosec // G704: see above
	if err != nil {
		return "", fmt.Errorf("requesting token: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("token endpoint returned %d: %s", resp.StatusCode, string(body))
	}

	var payload struct {
		Value string `json:"value"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return "", fmt.Errorf("decoding token response: %w", err)
	}
	if payload.Value == "" {
		return "", fmt.Errorf("token endpoint returned empty token")
	}

	return payload.Value, nil
}

// readFilesystemToken reads an OIDC token from a well-known filesystem path,
// used by providers that inject tokens as mounted files.
func readFilesystemToken(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	token := strings.TrimSpace(string(data))
	if token == "" {
		return "", fmt.Errorf("token file %s is empty", path)
	}
	return token, nil
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
