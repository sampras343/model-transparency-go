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
	"fmt"

	"github.com/sigstore/model-signing/pkg/config"
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

// KeySignerConfig holds configuration for creating a local key signer.
//
//nolint:revive
type KeySignerConfig struct {
	// KeyConfig provides private key loading functionality.
	config.KeyConfig
}

// LocalKeySigner signs model manifests using a local private key.
// Implements the interfaces.Signer interface.
type LocalKeySigner struct {
	config     KeySignerConfig
	privateKey crypto.PrivateKey
	publicKey  crypto.PublicKey
	keyHash    string // Hash of public key used as verification material hint
}

// NewLocalKeySigner creates a new private key signer with the given configuration.
// Loads and validates the private key, extracts the public key, and computes the key hash.
// Returns an error if key loading or processing fails.
func NewLocalKeySigner(cfg KeySignerConfig) (*LocalKeySigner, error) {
	// Load private key using shared configuration primitive
	privateKey, err := cfg.LoadPrivateKey()
	if err != nil {
		return nil, err
	}

	// Extract public key from private key using shared utility
	publicKey, err := config.ExtractPublicKey(privateKey)
	if err != nil {
		return nil, err
	}

	// Compute public key hash for verification material hint using shared utility
	keyHash, err := config.ComputePublicKeyHash(publicKey)
	if err != nil {
		return nil, err
	}

	return &LocalKeySigner{
		config:     cfg,
		privateKey: privateKey,
		publicKey:  publicKey,
		keyHash:    keyHash,
	}, nil
}

// Sign signs a payload and returns a Sigstore bundle signature.
//
// Creates a DSSE envelope with the signed payload and wraps it
// in a Sigstore bundle format for compatibility with verification.
// Returns an error if serialization, signing, or bundle creation fails.
func (s *LocalKeySigner) Sign(payload *interfaces.Payload) (interfaces.Signature, error) {
	// Convert payload to JSON
	payloadJSON, err := payload.ToJSON()
	if err != nil {
		return nil, fmt.Errorf("failed to convert payload to JSON: %w", err)
	}

	// Compute PAE (Pre-Authentication Encoding) for DSSE using shared utility
	pae := utils.ComputePAE(utils.InTotoJSONPayloadType, payloadJSON)

	// Sign the PAE using shared utility
	signatureBytes, err := utils.SignWithKey(s.privateKey, pae)
	if err != nil {
		return nil, fmt.Errorf("failed to sign payload: %w", err)
	}

	// Create DSSE envelope using the shared dsse package
	envelope := dsse.CreateEnvelope(utils.InTotoJSONPayloadType, payloadJSON, signatureBytes)

	// Convert envelope to protobuf format
	protoEnvelope, err := envelope.ToProtobuf()
	if err != nil {
		return nil, fmt.Errorf("failed to convert envelope to protobuf: %w", err)
	}

	// Create Sigstore bundle with verification material
	protoBundle := &protobundle.Bundle{
		MediaType:            utils.BundleMediaType,
		VerificationMaterial: s.createVerificationMaterial(),
		Content: &protobundle.Bundle_DsseEnvelope{
			DsseEnvelope: protoEnvelope,
		},
	}

	// Convert to sigstore-go bundle
	bndl, err := bundle.NewBundle(protoBundle)
	if err != nil {
		return nil, fmt.Errorf("failed to create bundle: %w", err)
	}

	return sign.NewSignature(bndl), nil
}

// createVerificationMaterial creates the verification material for the bundle.
//
// Includes the public key hint (hash) which can be used to identify
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
