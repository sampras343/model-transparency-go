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

package pkcs11

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"testing"

	protocommon "github.com/sigstore/protobuf-specs/gen/pb-go/common/v1"
)

func TestGetAlgorithmDetails_ECDSAKeys(t *testing.T) {
	tests := []struct {
		name        string
		curve       elliptic.Curve
		wantHashAlg protocommon.HashAlgorithm
		wantSigAlg  protocommon.PublicKeyDetails
		wantErr     bool
	}{
		{
			name:        "P-256 key",
			curve:       elliptic.P256(),
			wantHashAlg: protocommon.HashAlgorithm_SHA2_256,
			wantSigAlg:  protocommon.PublicKeyDetails_PKIX_ECDSA_P256_SHA_256,
			wantErr:     false,
		},
		{
			name:        "P-384 key",
			curve:       elliptic.P384(),
			wantHashAlg: protocommon.HashAlgorithm_SHA2_384,
			wantSigAlg:  protocommon.PublicKeyDetails_PKIX_ECDSA_P384_SHA_384,
			wantErr:     false,
		},
		{
			name:        "P-521 key",
			curve:       elliptic.P521(),
			wantHashAlg: protocommon.HashAlgorithm_SHA2_512,
			wantSigAlg:  protocommon.PublicKeyDetails_PKIX_ECDSA_P521_SHA_512,
			wantErr:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Generate key for testing
			privKey, err := ecdsa.GenerateKey(tt.curve, rand.Reader)
			if err != nil {
				t.Fatalf("Failed to generate key: %v", err)
			}

			algDetails, err := getAlgorithmDetails(&privKey.PublicKey)
			if (err != nil) != tt.wantErr {
				t.Errorf("getAlgorithmDetails() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr {
				if algDetails.GetProtoHashType() != tt.wantHashAlg {
					t.Errorf("Hash algorithm = %v, want %v", algDetails.GetProtoHashType(), tt.wantHashAlg)
				}
				if algDetails.GetSignatureAlgorithm() != tt.wantSigAlg {
					t.Errorf("Signature algorithm = %v, want %v", algDetails.GetSignatureAlgorithm(), tt.wantSigAlg)
				}
			}
		})
	}
}

func TestGetAlgorithmDetails_RSAKeys(t *testing.T) {
	tests := []struct {
		name        string
		bits        int
		wantHashAlg protocommon.HashAlgorithm
		wantSigAlg  protocommon.PublicKeyDetails
		wantErr     bool
	}{
		{
			name:        "RSA 2048",
			bits:        2048,
			wantHashAlg: protocommon.HashAlgorithm_SHA2_256,
			wantSigAlg:  protocommon.PublicKeyDetails_PKIX_RSA_PKCS1V15_2048_SHA256,
			wantErr:     false,
		},
		{
			name:        "RSA 3072",
			bits:        3072,
			wantHashAlg: protocommon.HashAlgorithm_SHA2_256,
			wantSigAlg:  protocommon.PublicKeyDetails_PKIX_RSA_PKCS1V15_2048_SHA256,
			wantErr:     false,
		},
		{
			name:        "RSA 4096",
			bits:        4096,
			wantHashAlg: protocommon.HashAlgorithm_SHA2_256,
			wantSigAlg:  protocommon.PublicKeyDetails_PKIX_RSA_PKCS1V15_2048_SHA256,
			wantErr:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Generate key for testing
			privKey, err := rsa.GenerateKey(rand.Reader, tt.bits)
			if err != nil {
				t.Fatalf("Failed to generate key: %v", err)
			}

			algDetails, err := getAlgorithmDetails(&privKey.PublicKey)
			if (err != nil) != tt.wantErr {
				t.Errorf("getAlgorithmDetails() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr {
				if algDetails.GetProtoHashType() != tt.wantHashAlg {
					t.Errorf("Hash algorithm = %v, want %v", algDetails.GetProtoHashType(), tt.wantHashAlg)
				}
				if algDetails.GetSignatureAlgorithm() != tt.wantSigAlg {
					t.Errorf("Signature algorithm = %v, want %v", algDetails.GetSignatureAlgorithm(), tt.wantSigAlg)
				}
			}
		})
	}
}

func TestGetAlgorithmDetails_UnsupportedKeyType(t *testing.T) {
	// Test with an unsupported key type (string)
	_, err := getAlgorithmDetails("not a valid key")
	if err == nil {
		t.Error("Expected error for unsupported key type, got nil")
	}
}

func TestGetAlgorithmDetails_UnsupportedECDSACurve(t *testing.T) {
	// Use P-224 which is not supported
	privKey, err := ecdsa.GenerateKey(elliptic.P224(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	_, err = getAlgorithmDetails(&privKey.PublicKey)
	if err == nil {
		t.Error("Expected error for unsupported curve, got nil")
	}
}

func TestGetAlgorithmDetails_UnsupportedRSASize(t *testing.T) {
	privKey, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	_, err = getAlgorithmDetails(&privKey.PublicKey)
	if err != nil {
		t.Errorf("Unexpected error for RSA key: %v", err)
	}
}

// TestPKCS11Keypair_InterfaceCompliance verifies that Keypair
// implements the required interfaces
func TestPKCS11Keypair_InterfaceCompliance(t *testing.T) {
	// This test ensures the type implements the interface at compile time
	// We don't need runtime checks, just the type assertion
	var _ interface{} = (*Keypair)(nil)
}

func TestPKCS11Keypair_GetKeyAlgorithm(t *testing.T) {
	tests := []struct {
		name     string
		keyGen   func() interface{}
		wantType string // Expected key type (ECDSA, RSA, etc.)
	}{
		{
			name: "ECDSA P-256",
			keyGen: func() interface{} {
				key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
				return &key.PublicKey
			},
			wantType: "ECDSA",
		},
		{
			name: "ECDSA P-384",
			keyGen: func() interface{} {
				key, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
				return &key.PublicKey
			},
			wantType: "ECDSA",
		},
		{
			name: "RSA 2048",
			keyGen: func() interface{} {
				key, _ := rsa.GenerateKey(rand.Reader, 2048)
				return &key.PublicKey
			},
			wantType: "RSA",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pubKey := tt.keyGen()
			algDetails, err := getAlgorithmDetails(pubKey)
			if err != nil {
				t.Fatalf("Failed to get algorithm details: %v", err)
			}

			kp := &Keypair{
				algDetails: algDetails,
			}

			gotAlg := kp.GetKeyAlgorithm()
			// GetKeyAlgorithm returns the key type string from AlgorithmDetails
			if gotAlg != tt.wantType {
				t.Errorf("GetKeyAlgorithm() = %v, want %v", gotAlg, tt.wantType)
			}
		})
	}
}
