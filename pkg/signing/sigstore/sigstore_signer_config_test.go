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
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

// --- readFilesystemToken ---

func TestReadFilesystemToken_Valid(t *testing.T) {
	f := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(f, []byte("my-jwt-token"), 0600); err != nil {
		t.Fatal(err)
	}

	tok, err := readFilesystemToken(f)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if tok != "my-jwt-token" {
		t.Errorf("got %q, want %q", tok, "my-jwt-token")
	}
}

func TestReadFilesystemToken_TrimsWhitespace(t *testing.T) {
	f := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(f, []byte("  token-with-whitespace \n"), 0600); err != nil {
		t.Fatal(err)
	}

	tok, err := readFilesystemToken(f)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if tok != "token-with-whitespace" {
		t.Errorf("got %q, want %q", tok, "token-with-whitespace")
	}
}

func TestReadFilesystemToken_Missing(t *testing.T) {
	_, err := readFilesystemToken(filepath.Join(t.TempDir(), "nonexistent"))
	if err == nil {
		t.Fatal("expected error for missing file")
	}
}

func TestReadFilesystemToken_Empty(t *testing.T) {
	f := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(f, []byte(""), 0600); err != nil {
		t.Fatal(err)
	}

	_, err := readFilesystemToken(f)
	if err == nil {
		t.Fatal("expected error for empty file")
	}
}

func TestReadFilesystemToken_WhitespaceOnly(t *testing.T) {
	f := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(f, []byte("  \n\t  "), 0600); err != nil {
		t.Fatal(err)
	}

	_, err := readFilesystemToken(f)
	if err == nil {
		t.Fatal("expected error for whitespace-only file")
	}
}

// --- fetchGitHubActionsToken ---

func TestFetchGitHubActionsToken_Success(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "bearer test-bearer" {
			t.Errorf("Authorization header = %q, want %q", got, "bearer test-bearer")
		}
		if got := r.URL.Query().Get("audience"); got != "sigstore" {
			t.Errorf("audience = %q, want %q", got, "sigstore")
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"value": "the-oidc-jwt"})
	}))
	defer srv.Close()

	t.Setenv(ghActionsRequestURLVar, srv.URL+"?dummy=1")
	t.Setenv(ghActionsRequestTknVar, "test-bearer")

	tok, err := fetchGitHubActionsToken(context.Background(), "sigstore")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if tok != "the-oidc-jwt" {
		t.Errorf("got %q, want %q", tok, "the-oidc-jwt")
	}
}

func TestFetchGitHubActionsToken_MissingEnvVars(t *testing.T) {
	t.Setenv(ghActionsRequestURLVar, "")
	t.Setenv(ghActionsRequestTknVar, "")

	_, err := fetchGitHubActionsToken(context.Background(), "sigstore")
	if err == nil {
		t.Fatal("expected error when env vars are unset")
	}
}

func TestFetchGitHubActionsToken_OnlyURLSet(t *testing.T) {
	t.Setenv(ghActionsRequestURLVar, "https://example.com")
	t.Setenv(ghActionsRequestTknVar, "")

	_, err := fetchGitHubActionsToken(context.Background(), "sigstore")
	if err == nil {
		t.Fatal("expected error when only URL is set")
	}
}

func TestFetchGitHubActionsToken_Non200(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "forbidden", http.StatusForbidden)
	}))
	defer srv.Close()

	t.Setenv(ghActionsRequestURLVar, srv.URL+"?dummy=1")
	t.Setenv(ghActionsRequestTknVar, "bearer")

	_, err := fetchGitHubActionsToken(context.Background(), "sigstore")
	if err == nil {
		t.Fatal("expected error for non-200 response")
	}
}

func TestFetchGitHubActionsToken_EmptyValue(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"value": ""})
	}))
	defer srv.Close()

	t.Setenv(ghActionsRequestURLVar, srv.URL+"?dummy=1")
	t.Setenv(ghActionsRequestTknVar, "bearer")

	_, err := fetchGitHubActionsToken(context.Background(), "sigstore")
	if err == nil {
		t.Fatal("expected error for empty token value")
	}
}

func TestFetchGitHubActionsToken_InvalidJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte("not-json"))
	}))
	defer srv.Close()

	t.Setenv(ghActionsRequestURLVar, srv.URL+"?dummy=1")
	t.Setenv(ghActionsRequestTknVar, "bearer")

	_, err := fetchGitHubActionsToken(context.Background(), "sigstore")
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}

// --- getAmbientToken ---

func TestGetAmbientToken_PrefersEnvVar(t *testing.T) {
	t.Setenv(ambientTokenEnvVar, "env-token")
	t.Setenv(ghActionsRequestURLVar, "")
	t.Setenv(ghActionsRequestTknVar, "")

	tok, err := getAmbientToken(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if tok != "env-token" {
		t.Errorf("got %q, want %q", tok, "env-token")
	}
}

func TestGetAmbientToken_FallsBackToGitHubActions(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"value": "gha-token"})
	}))
	defer srv.Close()

	t.Setenv(ambientTokenEnvVar, "")
	t.Setenv(ghActionsRequestURLVar, srv.URL+"?dummy=1")
	t.Setenv(ghActionsRequestTknVar, "bearer")

	tok, err := getAmbientToken(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if tok != "gha-token" {
		t.Errorf("got %q, want %q", tok, "gha-token")
	}
}

func TestGetAmbientToken_AllProvidersFail(t *testing.T) {
	t.Setenv(ambientTokenEnvVar, "")
	t.Setenv(ghActionsRequestURLVar, "")
	t.Setenv(ghActionsRequestTknVar, "")

	_, err := getAmbientToken(context.Background())
	if err == nil {
		t.Fatal("expected error when all providers fail")
	}
}
