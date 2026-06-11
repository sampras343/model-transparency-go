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
	"testing"

	"github.com/spf13/cobra"
)

func TestKeySignOptions_AddFlags(t *testing.T) {
	cmd := &cobra.Command{Use: "test"}
	opts := &KeySignOptions{}
	opts.AddFlags(cmd)

	expected := []string{"private-key", "password", "signature", "tsa-url",
		"ignore-paths", "ignore-git-paths", "allow-symlinks"}
	for _, name := range expected {
		if cmd.Flags().Lookup(name) == nil {
			t.Errorf("KeySignOptions: expected flag %q to be registered", name)
		}
	}
}

func TestKeySignOptions_ToStandardOptions(t *testing.T) {
	opts := &KeySignOptions{}
	opts.PrivateKeyPath = "/path/to/key.pem"
	opts.Password = "secret"
	opts.SignaturePath = "model.sig"
	opts.IgnoreGitPaths = true
	opts.AllowSymlinks = false
	opts.IgnorePaths = []string{"ignored"}
	opts.TSAUrl = "https://tsa.example.com"

	std := opts.ToStandardOptions("/path/to/model")

	if std.ModelPath != "/path/to/model" {
		t.Errorf("ModelPath: got %q, want %q", std.ModelPath, "/path/to/model")
	}
	if std.PrivateKeyPath != "/path/to/key.pem" {
		t.Errorf("PrivateKeyPath: got %q, want %q", std.PrivateKeyPath, "/path/to/key.pem")
	}
	if std.Password != "secret" {
		t.Errorf("Password: got %q, want %q", std.Password, "secret")
	}
	if std.SignaturePath != "model.sig" {
		t.Errorf("SignaturePath: got %q, want %q", std.SignaturePath, "model.sig")
	}
	if std.TSAUrl != "https://tsa.example.com" {
		t.Errorf("TSAUrl: got %q, want %q", std.TSAUrl, "https://tsa.example.com")
	}
	if !std.IgnoreGitPaths {
		t.Error("IgnoreGitPaths not propagated")
	}
}

func TestKeySignOptions_ToStandardOptions_EmptyTSA(t *testing.T) {
	opts := &KeySignOptions{}
	std := opts.ToStandardOptions("/model")

	if std.TSAUrl != "" {
		t.Errorf("TSAUrl: expected empty, got %q", std.TSAUrl)
	}
}

func TestCertificateSignOptions_AddFlags(t *testing.T) {
	cmd := &cobra.Command{Use: "test"}
	opts := &CertificateSignOptions{}
	opts.AddFlags(cmd)

	expected := []string{"private-key", "signing-certificate", "certificate-chain",
		"signature", "tsa-url", "ignore-paths", "ignore-git-paths", "allow-symlinks"}
	for _, name := range expected {
		if cmd.Flags().Lookup(name) == nil {
			t.Errorf("CertificateSignOptions: expected flag %q to be registered", name)
		}
	}
}

func TestCertificateSignOptions_ToStandardOptions(t *testing.T) {
	opts := &CertificateSignOptions{}
	opts.PrivateKeyPath = "/path/to/key.pem"
	opts.SigningCertificatePath = "/path/to/cert.pem"
	opts.CertificateChain = []string{"/path/to/chain.pem"}
	opts.SignaturePath = "model.sig"
	opts.TSAUrl = "https://tsa.example.com"

	std := opts.ToStandardOptions("/path/to/model")

	if std.ModelPath != "/path/to/model" {
		t.Errorf("ModelPath: got %q, want %q", std.ModelPath, "/path/to/model")
	}
	if std.PrivateKeyPath != "/path/to/key.pem" {
		t.Errorf("PrivateKeyPath: got %q, want %q", std.PrivateKeyPath, "/path/to/key.pem")
	}
	if std.SigningCertificatePath != "/path/to/cert.pem" {
		t.Errorf("SigningCertificatePath: got %q, want %q", std.SigningCertificatePath, "/path/to/cert.pem")
	}
	if std.TSAUrl != "https://tsa.example.com" {
		t.Errorf("TSAUrl: got %q, want %q", std.TSAUrl, "https://tsa.example.com")
	}
}

func TestCertificateSignOptions_ToStandardOptions_EmptyTSA(t *testing.T) {
	opts := &CertificateSignOptions{}
	std := opts.ToStandardOptions("/model")

	if std.TSAUrl != "" {
		t.Errorf("TSAUrl: expected empty, got %q", std.TSAUrl)
	}
}

func TestPkcs11SignOptions_AddFlags(t *testing.T) {
	cmd := &cobra.Command{Use: "test"}
	opts := &Pkcs11SignOptions{}
	opts.AddFlags(cmd)

	expected := []string{"pkcs11-uri", "module-path", "signature", "tsa-url",
		"ignore-paths", "ignore-git-paths", "allow-symlinks"}
	for _, name := range expected {
		if cmd.Flags().Lookup(name) == nil {
			t.Errorf("Pkcs11SignOptions: expected flag %q to be registered", name)
		}
	}
}

func TestPkcs11SignOptions_AddCertificateFlags(t *testing.T) {
	cmd := &cobra.Command{Use: "test"}
	opts := &Pkcs11SignOptions{}
	opts.AddFlags(cmd)
	opts.AddCertificateFlags(cmd)

	expected := []string{"signing-certificate", "certificate-chain"}
	for _, name := range expected {
		if cmd.Flags().Lookup(name) == nil {
			t.Errorf("Pkcs11SignOptions: expected flag %q to be registered after AddCertificateFlags", name)
		}
	}
}

func TestPkcs11SignOptions_ToStandardOptions(t *testing.T) {
	opts := &Pkcs11SignOptions{}
	opts.URI = "pkcs11:token=test;object=key"
	opts.ModulePaths = []string{"/usr/lib/softhsm"}
	opts.SigningCertificatePath = "/path/to/cert.pem"
	opts.CertificateChain = []string{"/path/to/chain.pem"}
	opts.SignaturePath = "model.sig"
	opts.TSAUrl = "https://tsa.example.com"

	std := opts.ToStandardOptions("/path/to/model")

	if std.ModelPath != "/path/to/model" {
		t.Errorf("ModelPath: got %q, want %q", std.ModelPath, "/path/to/model")
	}
	if std.URI != "pkcs11:token=test;object=key" {
		t.Errorf("URI: got %q, want %q", std.URI, "pkcs11:token=test;object=key")
	}
	if std.TSAUrl != "https://tsa.example.com" {
		t.Errorf("TSAUrl: got %q, want %q", std.TSAUrl, "https://tsa.example.com")
	}
	if std.SigningCertificatePath != "/path/to/cert.pem" {
		t.Errorf("SigningCertificatePath: got %q", std.SigningCertificatePath)
	}
}

func TestPkcs11SignOptions_ToStandardOptions_EmptyTSA(t *testing.T) {
	opts := &Pkcs11SignOptions{}
	opts.URI = "pkcs11:token=test;object=key"
	std := opts.ToStandardOptions("/model")

	if std.TSAUrl != "" {
		t.Errorf("TSAUrl: expected empty, got %q", std.TSAUrl)
	}
}

func TestSigstoreSignOptions_AddFlags(t *testing.T) {
	cmd := &cobra.Command{Use: "test"}
	opts := &SigstoreSignOptions{}
	opts.AddFlags(cmd)

	expected := []string{"oauth-force-oob", "use-ambient-credentials", "identity-token",
		"client-id", "client-secret", "signature", "use-staging", "trust-config",
		"ignore-paths", "ignore-git-paths", "allow-symlinks"}
	for _, name := range expected {
		if cmd.Flags().Lookup(name) == nil {
			t.Errorf("SigstoreSignOptions: expected flag %q to be registered", name)
		}
	}

	// Sigstore signing should NOT have tsa-url
	if cmd.Flags().Lookup("tsa-url") != nil {
		t.Error("SigstoreSignOptions should not have tsa-url flag")
	}
}

func TestSigstoreSignOptions_ToStandardOptions(t *testing.T) {
	opts := &SigstoreSignOptions{}
	opts.OAuthForceOob = true
	opts.UseAmbientCredentials = true
	opts.IdentityToken = "test-token"
	opts.ClientID = "test-client"
	opts.ClientSecret = "test-secret"
	opts.UseStaging = true
	opts.TrustConfigPath = "/path/to/trust.json"
	opts.SignaturePath = "model.sig"

	std := opts.ToStandardOptions("/path/to/model")

	if std.ModelPath != "/path/to/model" {
		t.Errorf("ModelPath: got %q, want %q", std.ModelPath, "/path/to/model")
	}
	if !std.OAuthForceOob {
		t.Error("OAuthForceOob not propagated")
	}
	if !std.UseAmbientCredentials {
		t.Error("UseAmbientCredentials not propagated")
	}
	if std.IdentityToken != "test-token" {
		t.Errorf("IdentityToken: got %q", std.IdentityToken)
	}
	if !std.UseStaging {
		t.Error("UseStaging not propagated")
	}
	if std.TrustConfigPath != "/path/to/trust.json" {
		t.Errorf("TrustConfigPath: got %q", std.TrustConfigPath)
	}
}
