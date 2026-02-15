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
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"fmt"
	"time"

	"github.com/sigstore/sigstore-go/pkg/root"
	sigstoresig "github.com/sigstore/sigstore/pkg/signature"
)

// CreateSignatureVerifier creates a sigstore signature.Verifier from a crypto.PublicKey.
// Supports ECDSA (P-256, P-384), RSA (PKCS1v15 with SHA256), and Ed25519 keys.
func CreateSignatureVerifier(pubKey crypto.PublicKey) (sigstoresig.Verifier, error) {
	switch k := pubKey.(type) {
	case *ecdsa.PublicKey:
		var hashFunc crypto.Hash
		switch k.Curve {
		case elliptic.P256():
			hashFunc = crypto.SHA256
		case elliptic.P384():
			hashFunc = crypto.SHA384
		default:
			return nil, fmt.Errorf("unsupported ECDSA curve: %s", k.Curve.Params().Name)
		}
		return sigstoresig.LoadECDSAVerifier(k, hashFunc)
	case *rsa.PublicKey:
		return sigstoresig.LoadRSAPKCS1v15Verifier(k, crypto.SHA256)
	case ed25519.PublicKey:
		return sigstoresig.LoadED25519phVerifier(k)
	default:
		return nil, fmt.Errorf("unsupported public key type: %T", pubKey)
	}
}

// CreateTrustedPublicKeyMaterial wraps a public key in sigstore-go's
// TrustedPublicKeyMaterial for use with sigstore-go's verify.NewVerifier().
// The key is wrapped with no expiration (suitable for key-based and
// certificate-based verification where validity is managed externally).
func CreateTrustedPublicKeyMaterial(pubKey crypto.PublicKey) (*root.TrustedPublicKeyMaterial, error) {
	verifier, err := CreateSignatureVerifier(pubKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create signature verifier: %w", err)
	}

	expiringKey := root.NewExpiringKey(verifier, time.Time{}, time.Time{})

	trustedMaterial := root.NewTrustedPublicKeyMaterial(func(_ string) (root.TimeConstrainedVerifier, error) {
		return expiringKey, nil
	})

	return trustedMaterial, nil
}
