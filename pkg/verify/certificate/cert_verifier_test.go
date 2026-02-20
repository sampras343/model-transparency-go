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
	"context"
	"testing"

	"github.com/sigstore/model-signing/pkg/logging"
)

// TestNewCertificateVerifier tests the creation of a certificate verifier.
func TestNewCertificateVerifier(t *testing.T) {
	tests := []struct {
		name    string
		opts    CertificateVerifierOptions
		wantErr bool
	}{
		{
			name: "missing model path",
			opts: CertificateVerifierOptions{
				ModelPath:     "",
				SignaturePath: "/tmp/signature.sig",
			},
			wantErr: true,
		},
		{
			name: "missing signature path",
			opts: CertificateVerifierOptions{
				ModelPath:     "/tmp/model",
				SignaturePath: "",
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NewCertificateVerifier(tt.opts)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewCertificateVerifier() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// TestCertificateVerifier_Verify tests the Verify method.
// Note: Full integration tests require actual certificates and signatures.
func TestCertificateVerifier_Verify(t *testing.T) {
	// This is a placeholder for integration tests
	// Actual tests would require setting up test certificates and signatures
	t.Skip("Integration test - requires test certificates and signatures")

	verifier := &CertificateVerifier{
		opts: CertificateVerifierOptions{
			ModelPath:        "/path/to/test/model",
			SignaturePath:    "/path/to/test/signature.sig",
			CertificateChain: []string{"/path/to/test/cert.pem"},
			LogFingerprints:  false,
		},
		logger: logging.NewLogger(false),
	}

	_, err := verifier.Verify(context.Background())
	if err != nil {
		t.Errorf("Verify() error = %v", err)
	}
}
