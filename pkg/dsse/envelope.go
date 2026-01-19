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

package dsse

import (
	"encoding/base64"
	"fmt"

	dsse_lib "github.com/secure-systems-lab/go-securesystemslib/dsse"
	protodsse "github.com/sigstore/protobuf-specs/gen/pb-go/dsse"
	"github.com/sigstore/sigstore-go/pkg/bundle"
)

// Envelope wraps the raw DSSE envelope with utility methods.
//
// This provides a clean interface for common DSSE operations like
// payload decoding, signature extraction, and validation.
type Envelope struct {
	raw *dsse_lib.Envelope
}

// NewEnvelope creates a new DSSE envelope wrapper from a raw envelope.
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
func (e *Envelope) ValidatePayloadType(expectedType string) error {
	if e.raw.PayloadType != expectedType {
		return fmt.Errorf("expected DSSE payload %s, but got %s",
			expectedType, e.raw.PayloadType)
	}
	return nil
}

// DecodePayload decodes the base64-encoded DSSE payload.
//
// In DSSE envelopes, the payload is stored as a base64-encoded string
// in the JSON representation. This function handles the decoding.
func (e *Envelope) DecodePayload() ([]byte, error) {
	payloadBytes, err := base64.StdEncoding.DecodeString(e.raw.Payload)
	if err != nil {
		return nil, fmt.Errorf("failed to decode DSSE payload: %w", err)
	}
	return payloadBytes, nil
}

// DecodeSignature decodes the base64-encoded signature.
//
// Returns the first (and only) signature's bytes after base64 decoding.
// Call ValidateSignatureCount() first to ensure exactly one signature exists.
func (e *Envelope) DecodeSignature() ([]byte, error) {
	if len(e.raw.Signatures) == 0 {
		return nil, fmt.Errorf("no signatures found in envelope")
	}

	signatureBytes, err := base64.StdEncoding.DecodeString(e.raw.Signatures[0].Sig)
	if err != nil {
		return nil, fmt.Errorf("failed to decode signature: %w", err)
	}
	return signatureBytes, nil
}

// PayloadType returns the DSSE payload type.
func (e *Envelope) PayloadType() string {
	return e.raw.PayloadType
}

// RawEnvelope returns the underlying raw DSSE envelope.
//
// Use this when you need direct access to the envelope structure
// for operations not covered by the Envelope methods.
func (e *Envelope) RawEnvelope() *dsse_lib.Envelope {
	return e.raw
}

// CreateEnvelope creates a new DSSE envelope with a single signature.
//
// The payload and signature are base64-encoded as required by the DSSE spec.
// This is a convenience function for signing operations.
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

// ToProtobuf converts the DSSE envelope to protobuf format.
//
// The go-securesystemslib envelope stores Payload and Sig as base64-encoded strings,
// but the protobuf expects []byte. This function handles the conversion by decoding
// the base64 strings to bytes.
func (e *Envelope) ToProtobuf() *protodsse.Envelope {
	// Decode base64 payload to bytes
	payloadBytes, _ := base64.StdEncoding.DecodeString(e.raw.Payload)

	// Decode base64 signatures to bytes
	signatures := make([]*protodsse.Signature, len(e.raw.Signatures))
	for i, sig := range e.raw.Signatures {
		sigBytes, _ := base64.StdEncoding.DecodeString(sig.Sig)
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
