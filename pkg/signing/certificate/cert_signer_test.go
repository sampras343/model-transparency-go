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

package certificate

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func generateTestCertPEM(t *testing.T) (certPEM []byte, certDERBase64 string) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test-cert"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
	}

	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("failed to create certificate: %v", err)
	}

	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	return pemBytes, base64.StdEncoding.EncodeToString(der)
}

func TestEmbedCertChainInBundleFile_PreservesTSAData(t *testing.T) {
	tmpDir := t.TempDir()

	certPEM, certB64 := generateTestCertPEM(t)

	chainCertPath := filepath.Join(tmpDir, "chain.pem")
	if err := os.WriteFile(chainCertPath, certPEM, 0644); err != nil {
		t.Fatalf("failed to write chain cert: %v", err)
	}

	bundleJSON := map[string]interface{}{
		"mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json",
		"verificationMaterial": map[string]interface{}{
			"certificate": map[string]interface{}{
				"rawBytes": certB64,
			},
			"timestampVerificationData": map[string]interface{}{
				"rfc3161Timestamps": []interface{}{
					map[string]interface{}{
						"signedTimestamp": "dGVzdC10aW1lc3RhbXA=",
					},
				},
			},
		},
		"dsseEnvelope": map[string]interface{}{},
	}

	bundlePath := filepath.Join(tmpDir, "bundle.json")
	data, err := json.MarshalIndent(bundleJSON, "", "  ")
	if err != nil {
		t.Fatalf("failed to marshal test bundle: %v", err)
	}
	if err := os.WriteFile(bundlePath, data, 0644); err != nil {
		t.Fatalf("failed to write test bundle: %v", err)
	}

	if err := EmbedCertChainInBundleFile(bundlePath, []string{chainCertPath}); err != nil {
		t.Fatalf("EmbedCertChainInBundleFile failed: %v", err)
	}

	result, err := os.ReadFile(bundlePath)
	if err != nil {
		t.Fatalf("failed to read result bundle: %v", err)
	}

	var got map[string]interface{}
	if err := json.Unmarshal(result, &got); err != nil {
		t.Fatalf("failed to parse result bundle: %v", err)
	}

	vm, ok := got["verificationMaterial"].(map[string]interface{})
	if !ok {
		t.Fatal("missing verificationMaterial in result")
	}

	tvd, ok := vm["timestampVerificationData"].(map[string]interface{})
	if !ok {
		t.Fatal("timestampVerificationData was stripped by EmbedCertChainInBundleFile")
	}

	timestamps, ok := tvd["rfc3161Timestamps"].([]interface{})
	if !ok || len(timestamps) == 0 {
		t.Fatal("rfc3161Timestamps was stripped or empty after EmbedCertChainInBundleFile")
	}

	ts, ok := timestamps[0].(map[string]interface{})
	if !ok {
		t.Fatal("timestamp entry is not a map")
	}
	if ts["signedTimestamp"] != "dGVzdC10aW1lc3RhbXA=" {
		t.Errorf("timestamp content changed: got %v", ts["signedTimestamp"])
	}

	if _, ok := vm["certificate"]; ok {
		t.Error("certificate field should have been removed")
	}
	if _, ok := vm["x509CertificateChain"]; !ok {
		t.Error("x509CertificateChain should have been added")
	}
}
