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

package utils

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"testing"

	protocommon "github.com/sigstore/protobuf-specs/gen/pb-go/common/v1"
	"github.com/sigstore/sigstore/pkg/signature"
)

func TestGetPublicKeyDetails(t *testing.T) {
	tests := []struct {
		name      string
		keyFunc   func() (interface{}, error)
		wantAlg   protocommon.PublicKeyDetails
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
			wantAlg:   protocommon.PublicKeyDetails_PKIX_ECDSA_P256_SHA_256,
			wantError: false,
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
			wantAlg:   protocommon.PublicKeyDetails_PKIX_ECDSA_P384_SHA_384,
			wantError: false,
		},
		{
			name: "ECDSA P-521 (unsupported)",
			keyFunc: func() (interface{}, error) {
				key, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
				if err != nil {
					return nil, err
				}
				return &key.PublicKey, nil
			},
			wantAlg:   0,
			wantError: true,
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
			wantAlg:   protocommon.PublicKeyDetails_PKIX_RSA_PKCS1V15_2048_SHA256,
			wantError: false,
		},
		{
			name: "RSA 3072",
			keyFunc: func() (interface{}, error) {
				key, err := rsa.GenerateKey(rand.Reader, 3072)
				if err != nil {
					return nil, err
				}
				return &key.PublicKey, nil
			},
			wantAlg:   protocommon.PublicKeyDetails_PKIX_RSA_PKCS1V15_3072_SHA256,
			wantError: false,
		},
		{
			name: "RSA 4096",
			keyFunc: func() (interface{}, error) {
				key, err := rsa.GenerateKey(rand.Reader, 4096)
				if err != nil {
					return nil, err
				}
				return &key.PublicKey, nil
			},
			wantAlg:   protocommon.PublicKeyDetails_PKIX_RSA_PKCS1V15_4096_SHA256,
			wantError: false,
		},
		{
			name: "Ed25519",
			keyFunc: func() (interface{}, error) {
				pub, _, err := ed25519.GenerateKey(rand.Reader)
				return pub, err
			},
			wantAlg:   protocommon.PublicKeyDetails_PKIX_ED25519_PH,
			wantError: false,
		},
		{
			name: "Unsupported type (string)",
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
				t.Fatalf("Failed to generate key: %v", err)
			}

			alg, err := GetPublicKeyDetails(key)
			if tt.wantError {
				if err == nil {
					t.Error("Expected error but got none")
				}
				return
			}

			if err != nil {
				t.Errorf("Unexpected error: %v", err)
				return
			}

			if alg != tt.wantAlg {
				t.Errorf("Got algorithm %v, want %v", alg, tt.wantAlg)
			}
		})
	}
}

func TestKeyTypeToString(t *testing.T) {
	tests := []struct {
		name    string
		keyType signature.PublicKeyType
		want    string
	}{
		{
			name:    "ECDSA",
			keyType: signature.ECDSA,
			want:    "ECDSA",
		},
		{
			name:    "RSA",
			keyType: signature.RSA,
			want:    "RSA",
		},
		{
			name:    "ED25519",
			keyType: signature.ED25519,
			want:    "ED25519",
		},
		{
			name:    "Unknown (999)",
			keyType: signature.PublicKeyType(999),
			want:    "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := KeyTypeToString(tt.keyType)
			if got != tt.want {
				t.Errorf("KeyTypeToString() = %q, want %q", got, tt.want)
			}
		})
	}
}
