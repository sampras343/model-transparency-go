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
	"encoding/json"
	"strings"
	"testing"

	dsse_lib "github.com/secure-systems-lab/go-securesystemslib/dsse"
)

func TestCreateEnvelope(t *testing.T) {
	payloadType := "application/vnd.in-toto+json"
	payload := []byte(`{"test": "data"}`)
	signature := []byte("test-signature")

	envelope := CreateEnvelope(payloadType, payload, signature)

	if envelope == nil {
		t.Fatal("Expected non-nil envelope")
	}

	// Verify payload type
	if envelope.raw.PayloadType != payloadType {
		t.Errorf("Expected payloadType '%s', got '%s'", payloadType, envelope.raw.PayloadType)
	}

	// Verify payload is base64 encoded
	expectedPayload := base64.StdEncoding.EncodeToString(payload)
	if envelope.raw.Payload != expectedPayload {
		t.Errorf("Expected base64 encoded payload '%s', got '%s'", expectedPayload, envelope.raw.Payload)
	}

	// Verify signature is base64 encoded
	if len(envelope.raw.Signatures) != 1 {
		t.Fatalf("Expected 1 signature, got %d", len(envelope.raw.Signatures))
	}

	expectedSig := base64.StdEncoding.EncodeToString(signature)
	if envelope.raw.Signatures[0].Sig != expectedSig {
		t.Errorf("Expected base64 encoded signature '%s', got '%s'", expectedSig, envelope.raw.Signatures[0].Sig)
	}

	// Verify KeyID is empty
	if envelope.raw.Signatures[0].KeyID != "" {
		t.Errorf("Expected empty KeyID, got '%s'", envelope.raw.Signatures[0].KeyID)
	}
}

func TestCreateEnvelope_EmptyPayload(t *testing.T) {
	envelope := CreateEnvelope("test/type", []byte{}, []byte("sig"))

	if envelope == nil {
		t.Fatal("Expected non-nil envelope")
	}

	// Empty payload should still be base64 encoded
	decoded, err := base64.StdEncoding.DecodeString(envelope.raw.Payload)
	if err != nil {
		t.Fatalf("Failed to decode payload: %v", err)
	}

	if len(decoded) != 0 {
		t.Errorf("Expected empty decoded payload, got %d bytes", len(decoded))
	}
}

func TestToProtobuf(t *testing.T) {
	payloadType := "application/vnd.in-toto+json"
	payload := []byte(`{"test": "data"}`)
	signature := []byte("test-signature-bytes")

	envelope := CreateEnvelope(payloadType, payload, signature)
	protoEnvelope, err := envelope.ToProtobuf()
	if err != nil {
		t.Fatalf("ToProtobuf failed: %v", err)
	}

	if protoEnvelope == nil {
		t.Fatal("Expected non-nil protobuf envelope")
	}

	// Verify payload type
	if protoEnvelope.PayloadType != payloadType {
		t.Errorf("Expected payloadType '%s', got '%s'", payloadType, protoEnvelope.PayloadType)
	}

	// Verify payload is decoded to bytes
	if string(protoEnvelope.Payload) != string(payload) {
		t.Errorf("Expected payload '%s', got '%s'", string(payload), string(protoEnvelope.Payload))
	}

	// Verify signature is decoded to bytes
	if len(protoEnvelope.Signatures) != 1 {
		t.Fatalf("Expected 1 signature, got %d", len(protoEnvelope.Signatures))
	}

	if string(protoEnvelope.Signatures[0].Sig) != string(signature) {
		t.Errorf("Expected signature '%s', got '%s'", string(signature), string(protoEnvelope.Signatures[0].Sig))
	}

	// Verify KeyID is preserved
	if protoEnvelope.Signatures[0].Keyid != "" {
		t.Errorf("Expected empty KeyID, got '%s'", protoEnvelope.Signatures[0].Keyid)
	}
}

func TestToProtobuf_MultipleSignatures(t *testing.T) {
	// Create envelope with raw DSSE that has multiple signatures
	payload := []byte(`{"test": "data"}`)
	rawEnvelope := &dsse_lib.Envelope{
		Payload:     base64.StdEncoding.EncodeToString(payload),
		PayloadType: "test/type",
		Signatures: []dsse_lib.Signature{
			{
				Sig:   base64.StdEncoding.EncodeToString([]byte("sig1")),
				KeyID: "key1",
			},
			{
				Sig:   base64.StdEncoding.EncodeToString([]byte("sig2")),
				KeyID: "key2",
			},
		},
	}

	envelope := &Envelope{raw: rawEnvelope}
	protoEnvelope, err := envelope.ToProtobuf()
	if err != nil {
		t.Fatalf("ToProtobuf failed: %v", err)
	}

	if len(protoEnvelope.Signatures) != 2 {
		t.Fatalf("Expected 2 signatures, got %d", len(protoEnvelope.Signatures))
	}

	// Verify first signature
	if string(protoEnvelope.Signatures[0].Sig) != "sig1" {
		t.Errorf("Expected first signature 'sig1', got '%s'", string(protoEnvelope.Signatures[0].Sig))
	}
	if protoEnvelope.Signatures[0].Keyid != "key1" {
		t.Errorf("Expected first KeyID 'key1', got '%s'", protoEnvelope.Signatures[0].Keyid)
	}

	// Verify second signature
	if string(protoEnvelope.Signatures[1].Sig) != "sig2" {
		t.Errorf("Expected second signature 'sig2', got '%s'", string(protoEnvelope.Signatures[1].Sig))
	}
	if protoEnvelope.Signatures[1].Keyid != "key2" {
		t.Errorf("Expected second KeyID 'key2', got '%s'", protoEnvelope.Signatures[1].Keyid)
	}
}

func TestRawEnvelope(t *testing.T) {
	payload := []byte(`{"test": "data"}`)
	signature := []byte("sig")

	envelope := CreateEnvelope("test/type", payload, signature)
	rawEnvelope := envelope.RawEnvelope()

	if rawEnvelope == nil {
		t.Fatal("Expected non-nil raw envelope")
	}

	if rawEnvelope != envelope.raw {
		t.Error("Expected RawEnvelope to return the same raw envelope reference")
	}
}

func TestEnvelope_PayloadDecoding(t *testing.T) {
	// Create an envelope and verify payload can be decoded correctly
	originalPayload := map[string]interface{}{
		"test":   "data",
		"number": float64(42),
		"nested": map[string]interface{}{
			"key": "value",
		},
	}

	payloadJSON, err := json.Marshal(originalPayload)
	if err != nil {
		t.Fatalf("Failed to marshal payload: %v", err)
	}

	envelope := CreateEnvelope("application/vnd.in-toto+json", payloadJSON, []byte("sig"))

	// Decode the payload
	decodedPayload, err := base64.StdEncoding.DecodeString(envelope.raw.Payload)
	if err != nil {
		t.Fatalf("Failed to decode payload: %v", err)
	}

	// Unmarshal and compare
	var decoded map[string]interface{}
	if err := json.Unmarshal(decodedPayload, &decoded); err != nil {
		t.Fatalf("Failed to unmarshal payload: %v", err)
	}

	if decoded["test"] != "data" {
		t.Errorf("Expected test='data', got '%v'", decoded["test"])
	}

	if decoded["number"] != float64(42) {
		t.Errorf("Expected number=42, got '%v'", decoded["number"])
	}
}

func TestEnvelope_SignatureDecoding(t *testing.T) {
	// Test signature decoding works correctly
	originalSignature := []byte{0x01, 0x02, 0x03, 0x04, 0xFF, 0xFE}

	envelope := CreateEnvelope("test/type", []byte("payload"), originalSignature)

	// Decode the signature
	decodedSig, err := base64.StdEncoding.DecodeString(envelope.raw.Signatures[0].Sig)
	if err != nil {
		t.Fatalf("Failed to decode signature: %v", err)
	}

	// Compare bytes
	if len(decodedSig) != len(originalSignature) {
		t.Fatalf("Expected signature length %d, got %d", len(originalSignature), len(decodedSig))
	}

	for i, b := range originalSignature {
		if decodedSig[i] != b {
			t.Errorf("Signature byte %d: expected 0x%02x, got 0x%02x", i, b, decodedSig[i])
		}
	}
}

func TestEnvelope_Integration(t *testing.T) {
	// Test the full workflow: Create -> ToProtobuf
	payloadType := "application/vnd.in-toto+json"
	payload := []byte(`{"_type":"https://in-toto.io/Statement/v1","subject":[{"name":"test"}]}`)
	signature := []byte{0xDE, 0xAD, 0xBE, 0xEF}

	// Create envelope
	envelope := CreateEnvelope(payloadType, payload, signature)

	// Convert to protobuf
	protoEnvelope, err := envelope.ToProtobuf()
	if err != nil {
		t.Fatalf("ToProtobuf failed: %v", err)
	}

	// Verify everything is correct
	if protoEnvelope.PayloadType != payloadType {
		t.Errorf("PayloadType mismatch: expected '%s', got '%s'", payloadType, protoEnvelope.PayloadType)
	}

	if string(protoEnvelope.Payload) != string(payload) {
		t.Error("Payload mismatch after conversion")
	}

	if len(protoEnvelope.Signatures) != 1 {
		t.Fatalf("Expected 1 signature, got %d", len(protoEnvelope.Signatures))
	}

	if string(protoEnvelope.Signatures[0].Sig) != string(signature) {
		t.Error("Signature mismatch after conversion")
	}
}

func TestEnvelope_Base64Encoding(t *testing.T) {
	// Test that base64 encoding is standard (not URL encoding)
	payload := []byte("Test with special characters: +/=")
	signature := []byte("Signature with special: +/=")

	envelope := CreateEnvelope("test/type", payload, signature)

	// Verify it uses standard base64 (contains + and / not - and _)
	expectedPayload := base64.StdEncoding.EncodeToString(payload)
	if envelope.raw.Payload != expectedPayload {
		t.Errorf("Expected standard base64 encoding for payload")
	}

	expectedSig := base64.StdEncoding.EncodeToString(signature)
	if envelope.raw.Signatures[0].Sig != expectedSig {
		t.Errorf("Expected standard base64 encoding for signature")
	}
}

func TestEnvelope_LargePayload(t *testing.T) {
	// Test with large payload
	largePayload := make([]byte, 1024*1024) // 1MB
	for i := range largePayload {
		largePayload[i] = byte(i % 256)
	}

	envelope := CreateEnvelope("test/type", largePayload, []byte("sig"))
	protoEnvelope, err := envelope.ToProtobuf()
	if err != nil {
		t.Fatalf("ToProtobuf failed: %v", err)
	}

	// Verify payload is correctly encoded/decoded
	if len(protoEnvelope.Payload) != len(largePayload) {
		t.Errorf("Expected payload length %d, got %d", len(largePayload), len(protoEnvelope.Payload))
	}

	// Spot check a few bytes
	testIndices := []int{0, len(largePayload) / 2, len(largePayload) - 1}
	for _, idx := range testIndices {
		if protoEnvelope.Payload[idx] != largePayload[idx] {
			t.Errorf("Payload byte mismatch at index %d", idx)
		}
	}
}

func TestEnvelope_EmptySignature(t *testing.T) {
	// Test with empty signature
	envelope := CreateEnvelope("test/type", []byte("payload"), []byte{})
	protoEnvelope, err := envelope.ToProtobuf()
	if err != nil {
		t.Fatalf("ToProtobuf failed: %v", err)
	}

	if len(protoEnvelope.Signatures) != 1 {
		t.Fatalf("Expected 1 signature, got %d", len(protoEnvelope.Signatures))
	}

	if len(protoEnvelope.Signatures[0].Sig) != 0 {
		t.Errorf("Expected empty signature, got %d bytes", len(protoEnvelope.Signatures[0].Sig))
	}
}

func TestToProtobuf_InvalidPayloadBase64(t *testing.T) {
	// Create envelope with invalid base64 payload
	rawEnvelope := &dsse_lib.Envelope{
		Payload:     "not-valid-base64!!!", // Invalid base64
		PayloadType: "test/type",
		Signatures: []dsse_lib.Signature{
			{
				Sig:   base64.StdEncoding.EncodeToString([]byte("sig")),
				KeyID: "",
			},
		},
	}

	envelope := &Envelope{raw: rawEnvelope}
	_, err := envelope.ToProtobuf()

	if err == nil {
		t.Fatal("Expected error for invalid payload base64, got nil")
	}

	// Verify error message mentions payload
	if !strings.Contains(err.Error(), "payload") {
		t.Errorf("Expected error message to mention 'payload', got: %v", err)
	}
}

func TestToProtobuf_InvalidSignatureBase64(t *testing.T) {
	// Create envelope with valid payload but invalid signature base64
	rawEnvelope := &dsse_lib.Envelope{
		Payload:     base64.StdEncoding.EncodeToString([]byte("valid payload")),
		PayloadType: "test/type",
		Signatures: []dsse_lib.Signature{
			{
				Sig:   "not-valid-base64!!!", // Invalid base64
				KeyID: "key1",
			},
		},
	}

	envelope := &Envelope{raw: rawEnvelope}
	_, err := envelope.ToProtobuf()

	if err == nil {
		t.Fatal("Expected error for invalid signature base64, got nil")
	}

	// Verify error message mentions signature
	if !strings.Contains(err.Error(), "signature") {
		t.Errorf("Expected error message to mention 'signature', got: %v", err)
	}
}

func TestToProtobuf_InvalidSignatureBase64_SecondSignature(t *testing.T) {
	// Create envelope with multiple signatures where second one is invalid
	rawEnvelope := &dsse_lib.Envelope{
		Payload:     base64.StdEncoding.EncodeToString([]byte("valid payload")),
		PayloadType: "test/type",
		Signatures: []dsse_lib.Signature{
			{
				Sig:   base64.StdEncoding.EncodeToString([]byte("sig1")),
				KeyID: "key1",
			},
			{
				Sig:   "invalid-base64!!!", // Invalid base64
				KeyID: "key2",
			},
		},
	}

	envelope := &Envelope{raw: rawEnvelope}
	_, err := envelope.ToProtobuf()

	if err == nil {
		t.Fatal("Expected error for invalid signature base64, got nil")
	}

	// Verify error message mentions signature index
	if !strings.Contains(err.Error(), "signature 1") {
		t.Errorf("Expected error message to mention 'signature 1', got: %v", err)
	}
}
