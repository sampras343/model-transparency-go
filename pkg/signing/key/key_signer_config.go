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

package key

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"

	"github.com/sigstore/model-signing/pkg/dsse"
	"github.com/sigstore/model-signing/pkg/interfaces"
	sign "github.com/sigstore/model-signing/pkg/signature"
	"github.com/sigstore/model-signing/pkg/utils"
	protobundle "github.com/sigstore/protobuf-specs/gen/pb-go/bundle/v1"
	protocommon "github.com/sigstore/protobuf-specs/gen/pb-go/common/v1"
	"github.com/sigstore/sigstore-go/pkg/bundle"
)

// Ensure LocalKeySigner implements interfaces.Signer at compile time.
var _ interfaces.Signer = (*LocalKeySigner)(nil)

// Bundle media type for Sigstore bundle v0.3
const bundleMediaType = "application/vnd.dev.sigstore.bundle.v0.3+json"

// KeySignerConfig holds configuration for creating a Key signer.
//
//nolint:revive
type KeySignerConfig struct {
	PrivateKeyPath string
	Password       string
}

// LocalKeySigner signs model manifests using key.
type LocalKeySigner struct {
	config     KeySignerConfig
	privateKey crypto.PrivateKey
	publicKey  crypto.PublicKey
	keyHash    string
}

// NewLocalKeySigner creates a new private key signer with the given configuration.
func NewLocalKeySigner(config KeySignerConfig) (*LocalKeySigner, error) {
	if config.PrivateKeyPath == "" {
		return nil, fmt.Errorf("private key path is required")
	}

	// Read and parse the private key
	privateKey, err := loadPrivateKey(config.PrivateKeyPath, config.Password)
	if err != nil {
		return nil, fmt.Errorf("failed to load private key: %w", err)
	}

	// Extract public key from private key
	publicKey, err := extractPublicKey(privateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to extract public key: %w", err)
	}

	// Compute public key hash for verification material hint
	keyHash, err := computePublicKeyHash(publicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to compute key hash: %w", err)
	}

	return &LocalKeySigner{
		config:     config,
		privateKey: privateKey,
		publicKey:  publicKey,
		keyHash:    keyHash,
	}, nil
}

// Sign signs a payload and returns a Sigstore bundle signature.
//
// This creates a DSSE envelope with the signed payload and wraps it
// in a Sigstore bundle format for compatibility with verification.
func (s *LocalKeySigner) Sign(payload *interfaces.Payload) (interfaces.Signature, error) {
	// Convert payload to JSON
	payloadJSON, err := payload.ToJSON()
	if err != nil {
		return nil, fmt.Errorf("failed to convert payload to JSON: %w", err)
	}

	// Compute PAE (Pre-Authentication Encoding) for DSSE
	pae := computePAE(utils.InTotoJSONPayloadType, payloadJSON)

	// Sign the PAE
	signatureBytes, err := signWithKey(s.privateKey, pae)
	if err != nil {
		return nil, fmt.Errorf("failed to sign payload: %w", err)
	}

	// Create DSSE envelope using the shared dsse package
	envelope := dsse.CreateEnvelope(utils.InTotoJSONPayloadType, payloadJSON, signatureBytes)

	// Create Sigstore bundle with verification material
	protoBundle := &protobundle.Bundle{
		MediaType:            bundleMediaType,
		VerificationMaterial: s.createVerificationMaterial(),
		Content: &protobundle.Bundle_DsseEnvelope{
			DsseEnvelope: envelope.ToProtobuf(),
		},
	}

	// Convert to sigstore-go bundle
	bndl, err := bundle.NewBundle(protoBundle)
	if err != nil {
		return nil, fmt.Errorf("failed to create bundle: %w", err)
	}

	return sign.NewSignature(bndl), nil
}

// loadPrivateKey loads a private key from a PEM file with optional password.
func loadPrivateKey(path, password string) (crypto.PrivateKey, error) {
	pemBytes, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read private key file: %w", err)
	}

	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}

	var keyBytes []byte
	if password != "" {
		// Decrypt the key if password is provided
		//nolint:staticcheck // SA1019: x509.IsEncryptedPEMBlock is deprecated but needed for PKCS1
		if x509.IsEncryptedPEMBlock(block) {
			//nolint:staticcheck // SA1019: x509.DecryptPEMBlock is deprecated but needed for PKCS1
			keyBytes, err = x509.DecryptPEMBlock(block, []byte(password))
			if err != nil {
				return nil, fmt.Errorf("failed to decrypt private key: %w", err)
			}
		} else {
			return nil, fmt.Errorf("password provided but key is not encrypted")
		}
	} else {
		keyBytes = block.Bytes
	}

	// Try parsing as different key types
	// Try PKCS8 (most common)
	if key, err := x509.ParsePKCS8PrivateKey(keyBytes); err == nil {
		return key, nil
	}

	// Try EC private key
	if key, err := x509.ParseECPrivateKey(keyBytes); err == nil {
		return key, nil
	}

	// Try RSA private key
	if key, err := x509.ParsePKCS1PrivateKey(keyBytes); err == nil {
		return key, nil
	}

	return nil, fmt.Errorf("failed to parse private key (unsupported format)")
}

// extractPublicKey extracts the public key from a private key.
func extractPublicKey(privateKey crypto.PrivateKey) (crypto.PublicKey, error) {
	switch key := privateKey.(type) {
	case *ecdsa.PrivateKey:
		return &key.PublicKey, nil
	case *rsa.PrivateKey:
		return &key.PublicKey, nil
	case ed25519.PrivateKey:
		return key.Public(), nil
	default:
		return nil, fmt.Errorf("unsupported private key type: %T", privateKey)
	}
}

// computePublicKeyHash computes the SHA256 hash of the PEM-encoded public key.
//
// This hash is used as a hint in the verification material to identify which
// public key was used for signing.
func computePublicKeyHash(publicKey crypto.PublicKey) (string, error) {
	// Marshal public key to PKIX format
	pubKeyBytes, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return "", fmt.Errorf("failed to marshal public key: %w", err)
	}

	// Encode to PEM
	pemBlock := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubKeyBytes,
	}
	pemBytes := pem.EncodeToMemory(pemBlock)

	// Compute SHA256 hash
	hashBytes := sha256.Sum256(pemBytes)
	return fmt.Sprintf("%x", hashBytes), nil
}

// signWithKey signs data using the private key.
func signWithKey(privateKey crypto.PrivateKey, data []byte) ([]byte, error) {
	switch key := privateKey.(type) {
	case *ecdsa.PrivateKey:
		return signECDSA(key, data)
	case *rsa.PrivateKey:
		return signRSA(key, data)
	case ed25519.PrivateKey:
		return signEd25519(key, data)
	default:
		return nil, fmt.Errorf("unsupported private key type: %T", privateKey)
	}
}

// signECDSA signs data using an ECDSA private key.
func signECDSA(key *ecdsa.PrivateKey, data []byte) ([]byte, error) {
	// Hash the data with SHA256
	hash := sha256.Sum256(data)

	// Sign using ECDSA with ASN.1 encoding
	signature, err := ecdsa.SignASN1(rand.Reader, key, hash[:])
	if err != nil {
		return nil, fmt.Errorf("ECDSA signing failed: %w", err)
	}

	return signature, nil
}

// signRSA signs data using an RSA private key with PSS padding.
func signRSA(key *rsa.PrivateKey, data []byte) ([]byte, error) {
	// Hash the data with SHA256
	hash := sha256.Sum256(data)

	// Sign using RSA-PSS
	signature, err := rsa.SignPSS(rand.Reader, key, crypto.SHA256, hash[:], nil)
	if err != nil {
		return nil, fmt.Errorf("RSA-PSS signing failed: %w", err)
	}

	return signature, nil
}

// signEd25519 signs data using an Ed25519 private key.
func signEd25519(key ed25519.PrivateKey, data []byte) ([]byte, error) {
	signature := ed25519.Sign(key, data)
	return signature, nil
}

// computePAE computes the Pre-Authentication Encoding for DSSE.
//
// PAE(type, payload) = "DSSEv1" + SP + LEN(type) + SP + type + SP + LEN(payload) + SP + payload
func computePAE(payloadType string, payload []byte) []byte {
	pae := []byte("DSSEv1 ")
	pae = appendLength(pae, len(payloadType))
	pae = append(pae, ' ')
	pae = append(pae, []byte(payloadType)...)
	pae = append(pae, ' ')
	pae = appendLength(pae, len(payload))
	pae = append(pae, ' ')
	pae = append(pae, payload...)
	return pae
}

// appendLength appends an ASCII decimal representation of n to buf.
func appendLength(buf []byte, n int) []byte {
	return append(buf, []byte(fmt.Sprintf("%d", n))...)
}

// createVerificationMaterial creates the verification material for the bundle.
//
// This includes the public key hint (hash) which can be used to identify
// which public key should be used for verification.
func (s *LocalKeySigner) createVerificationMaterial() *protobundle.VerificationMaterial {
	return &protobundle.VerificationMaterial{
		Content: &protobundle.VerificationMaterial_PublicKey{
			PublicKey: &protocommon.PublicKeyIdentifier{
				Hint: s.keyHash,
			},
		},
	}
}

