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

// Package dsse provides utilities for working with Dead Simple Signing Envelope (DSSE) format.
//
// This package wraps the go-securesystemslib/dsse library to provide a clean interface
// for common DSSE operations including payload encoding/decoding, signature extraction,
// and conversion to Sigstore protobuf format. It is designed for compatibility with
// sigstore-go bundles while supporting the official Sigstore protobuf specifications.
package dsse

import (
	"encoding/base64"
	"fmt"

	dsse_lib "github.com/secure-systems-lab/go-securesystemslib/dsse"
	protodsse "github.com/sigstore/protobuf-specs/gen/pb-go/dsse"
	"github.com/sigstore/sigstore-go/pkg/bundle"
)

// Envelope wraps a DSSE envelope with utility methods.
//
// This provides a clean interface for common DSSE operations like
// payload decoding, signature extraction, and validation.
//
// Note: We use go-securesystemslib/dsse internally for compatibility with sigstore-go,
// which returns this type from bundle.Envelope.RawEnvelope(). We provide ToProtobuf()
// to convert to the official Sigstore protobuf format when creating bundles.
type Envelope struct {
	raw *dsse_lib.Envelope
}

// NewEnvelope creates a new DSSE envelope wrapper from a raw envelope.
//
// The raw parameter should be a valid DSSE envelope from go-securesystemslib/dsse.
// Returns a new Envelope instance wrapping the provided raw envelope.
func NewEnvelope(raw *dsse_lib.Envelope) *Envelope {
	return &Envelope{raw: raw}
}

// ExtractFromBundle extracts a DSSE envelope from a Sigstore bundle.
//
// This function handles the multi-step process of extracting a DSSE envelope:
// 1. Get the envelope from the bundle
// 2. Access the raw DSSE envelope
//
// Returns an error if any step fails or if the envelope is missing.
func ExtractFromBundle(bndl *bundle.Bundle) (*Envelope, error) {
	envelope, err := bndl.Envelope()
	if err != nil {
		return nil, fmt.Errorf("failed to extract envelope from bundle: %w", err)
	}

	dsseEnvelope := envelope.RawEnvelope()
	if dsseEnvelope == nil {
		return nil, fmt.Errorf("bundle does not contain a DSSE envelope")
	}

	return &Envelope{raw: dsseEnvelope}, nil
}

// ValidateSignatureCount checks that exactly one signature is present.
//
// The current implementation only supports single-signature envelopes.
// Multi-signature support may be added in the future.
//
// Returns an error if zero or more than one signature is found.
func (e *Envelope) ValidateSignatureCount() error {
	if len(e.raw.Signatures) == 0 {
		return fmt.Errorf("no signatures found in envelope")
	}
	if len(e.raw.Signatures) > 1 {
		return fmt.Errorf("multiple signatures not supported")
	}
	return nil
}

// ValidatePayloadType checks that the DSSE payload matches the expected type.
//
// The expectedType parameter specifies the required payload type to match against.
// Returns an error if the envelope's payload type does not match the expected type.
func (e *Envelope) ValidatePayloadType(expectedType string) error {
	if e.raw.PayloadType != expectedType {
		return fmt.Errorf("expected DSSE payload %s, but got %s",
			expectedType, e.raw.PayloadType)
	}
	return nil
}

// DecodePayload decodes the base64-encoded DSSE payload.
//
// The DSSE spec requires the payload to be base64-encoded in the envelope.
// This method decodes it and returns the raw payload bytes.
//
// Returns the decoded payload bytes and an error if the payload is empty or decoding fails.
func (e *Envelope) DecodePayload() ([]byte, error) {
	if e.raw.Payload == "" {
		return nil, fmt.Errorf("envelope payload is empty")
	}

	payloadBytes, err := base64.StdEncoding.DecodeString(e.raw.Payload)
	if err != nil {
		return nil, fmt.Errorf("failed to decode payload: %w", err)
	}

	return payloadBytes, nil
}

// DecodeSignature decodes the base64-encoded signature.
//
// The DSSE spec requires signatures to be base64-encoded in the envelope.
// This method decodes the first signature and returns the raw signature bytes.
// Call ValidateSignatureCount first to ensure exactly one signature exists.
//
// Returns the decoded signature bytes and an error if no signature is found or decoding fails.
func (e *Envelope) DecodeSignature() ([]byte, error) {
	if len(e.raw.Signatures) == 0 {
		return nil, fmt.Errorf("no signatures found in envelope")
	}

	sig := e.raw.Signatures[0].Sig
	if sig == "" {
		return nil, fmt.Errorf("signature is empty")
	}

	sigBytes, err := base64.StdEncoding.DecodeString(sig)
	if err != nil {
		return nil, fmt.Errorf("failed to decode signature: %w", err)
	}

	return sigBytes, nil
}

// PayloadType returns the DSSE payload type.
//
// Returns the payload type string from the envelope.
func (e *Envelope) PayloadType() string {
	return e.raw.PayloadType
}

// RawEnvelope returns the underlying DSSE envelope.
//
// Use this when you need direct access to the envelope structure
// for operations not covered by the Envelope methods.
//
// Returns the raw go-securesystemslib/dsse Envelope instance.
func (e *Envelope) RawEnvelope() *dsse_lib.Envelope {
	return e.raw
}

// CreateEnvelope creates a new DSSE envelope with a single signature.
//
// The payloadType parameter specifies the type of the payload (e.g., "application/vnd.in-toto+json").
// The payload and signature parameters are automatically base64-encoded as required by the DSSE spec.
//
// Returns a new Envelope instance containing the encoded payload and signature.
func CreateEnvelope(payloadType string, payload []byte, signature []byte) *Envelope {
	envelope := &dsse_lib.Envelope{
		Payload:     base64.StdEncoding.EncodeToString(payload),
		PayloadType: payloadType,
		Signatures: []dsse_lib.Signature{
			{
				Sig:   base64.StdEncoding.EncodeToString(signature),
				KeyID: "", // Empty keyid as per DSSE spec
			},
		},
	}
	return &Envelope{raw: envelope}
}

// ToProtobuf converts the envelope to Sigstore protobuf format.
//
// The conversion handles:
// - Base64 decoding of payload and signatures (protobuf uses raw bytes)
// - Field name mapping (KeyID -> Keyid)
//
// Returns a protobuf Envelope in the official Sigstore format.
func (e *Envelope) ToProtobuf() *protodsse.Envelope {
	// Decode payload from base64
	payloadBytes, err := base64.StdEncoding.DecodeString(e.raw.Payload)
	if err != nil {
		// Should never happen if envelope was created properly
		payloadBytes = []byte{}
	}

	// Convert signatures
	signatures := make([]*protodsse.Signature, len(e.raw.Signatures))
	for i, sig := range e.raw.Signatures {
		sigBytes, err := base64.StdEncoding.DecodeString(sig.Sig)
		if err != nil {
			sigBytes = []byte{}
		}

		signatures[i] = &protodsse.Signature{
			Sig:   sigBytes,
			Keyid: sig.KeyID,
		}
	}

	return &protodsse.Envelope{
		Payload:     payloadBytes,
		PayloadType: e.raw.PayloadType,
		Signatures:  signatures,
	}
}
