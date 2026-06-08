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

package verify

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"testing"
)

func TestCreateSignatureVerifier(t *testing.T) {
	tests := []struct {
		name      string
		keyFunc   func() (interface{}, error)
		wantError bool
	}{
		{
			name: "ECDSA P-256",
			keyFunc: func() (interface{}, error) {
				key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
				if err != nil {
					return nil, err
				}
				return &key.PublicKey, nil
			},
		},
		{
			name: "ECDSA P-384",
			keyFunc: func() (interface{}, error) {
				key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
				if err != nil {
					return nil, err
				}
				return &key.PublicKey, nil
			},
		},
		{
			name: "ECDSA P-521",
			keyFunc: func() (interface{}, error) {
				key, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
				if err != nil {
					return nil, err
				}
				return &key.PublicKey, nil
			},
		},
		{
			name: "ECDSA P-224 (unsupported)",
			keyFunc: func() (interface{}, error) {
				key, err := ecdsa.GenerateKey(elliptic.P224(), rand.Reader)
				if err != nil {
					return nil, err
				}
				return &key.PublicKey, nil
			},
			wantError: true,
		},
		{
			name: "RSA 2048",
			keyFunc: func() (interface{}, error) {
				key, err := rsa.GenerateKey(rand.Reader, 2048)
				if err != nil {
					return nil, err
				}
				return &key.PublicKey, nil
			},
		},
		{
			name: "Ed25519",
			keyFunc: func() (interface{}, error) {
				pub, _, err := ed25519.GenerateKey(rand.Reader)
				return pub, err
			},
		},
		{
			name: "Unsupported type",
			keyFunc: func() (interface{}, error) {
				return "not a key", nil
			},
			wantError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key, err := tt.keyFunc()
			if err != nil {
				t.Fatalf("failed to generate key: %v", err)
			}

			verifier, err := CreateSignatureVerifier(key)
			if tt.wantError {
				if err == nil {
					t.Error("expected error but got none")
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if verifier == nil {
				t.Error("expected non-nil verifier")
			}
		})
	}
}

func TestCreateTrustedPublicKeyMaterial(t *testing.T) {
	tests := []struct {
		name      string
		keyFunc   func() (interface{}, error)
		wantError bool
	}{
		{
			name: "ECDSA P-256",
			keyFunc: func() (interface{}, error) {
				key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
				if err != nil {
					return nil, err
				}
				return &key.PublicKey, nil
			},
		},
		{
			name: "ECDSA P-521",
			keyFunc: func() (interface{}, error) {
				key, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
				if err != nil {
					return nil, err
				}
				return &key.PublicKey, nil
			},
		},
		{
			name: "Unsupported type",
			keyFunc: func() (interface{}, error) {
				return "not a key", nil
			},
			wantError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key, err := tt.keyFunc()
			if err != nil {
				t.Fatalf("failed to generate key: %v", err)
			}

			material, err := CreateTrustedPublicKeyMaterial(key)
			if tt.wantError {
				if err == nil {
					t.Error("expected error but got none")
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if material == nil {
				t.Error("expected non-nil trusted material")
			}
		})
	}
}
