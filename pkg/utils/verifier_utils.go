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
	"encoding/json"
	"fmt"

	"github.com/sigstore/model-signing/pkg/manifest"
)

// VerifySignedContent extracts and validates the payload from a DSSE signature.
// Verifies the payload type matches in-toto JSON format and the statement type is correct.
// Returns the extracted Manifest or an error if validation fails.
func VerifySignedContent(payloadType string, payload []byte) (*manifest.Manifest, error) {
	if payloadType != InTotoJSONPayloadType {
		return nil, fmt.Errorf("expected DSSE payload %s, but got %s", InTotoJSONPayloadType, payloadType)
	}

	var dssePayload map[string]interface{}
	if err := json.Unmarshal(payload, &dssePayload); err != nil {
		return nil, fmt.Errorf("failed to unmarshal DSSE payload: %w", err)
	}

	payloadTypeField, ok := dssePayload["_type"].(string)
	if !ok {
		return nil, fmt.Errorf("_type field missing or not a string")
	}

	if payloadTypeField != InTotoStatementType {
		return nil, fmt.Errorf("expected in-toto %s payload, but got %s", InTotoStatementType, payloadTypeField)
	}

	return DSSEPayloadToManifest(dssePayload)
}

// hexToBytes converts a hexadecimal string to bytes.
// Returns the decoded bytes or an error if the hex string is invalid or has odd length.
func hexToBytes(hexStr string) ([]byte, error) {
	if len(hexStr)%2 != 0 {
		return nil, fmt.Errorf("hex string has odd length")
	}

	bytes := make([]byte, len(hexStr)/2)
	for i := 0; i < len(hexStr); i += 2 {
		var b byte
		_, err := fmt.Sscanf(hexStr[i:i+2], "%02x", &b)
		if err != nil {
			return nil, fmt.Errorf("invalid hex at position %d: %w", i, err)
		}
		bytes[i/2] = b
	}
	return bytes, nil
}

// MaskToken masks sensitive tokens for safe logging.
// Shows only the first 4 and last 4 characters, replacing the middle with "...".
// Returns "***" for tokens with 8 or fewer characters, or empty string for empty input.
func MaskToken(token string) string {
	if token == "" {
		return ""
	}
	// Convert to runes to handle Unicode characters properly
	runes := []rune(token)
	if len(runes) <= 8 {
		return "***"
	}
	return string(runes[:4]) + "..." + string(runes[len(runes)-4:])
}
