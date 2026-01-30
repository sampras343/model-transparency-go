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

package payload

import (
	"encoding/json"
	"fmt"

	"github.com/sigstore/model-signing/pkg/manifest"
	"github.com/sigstore/model-signing/pkg/utils"
)

// VerifySignedContent extracts and validates the payload from a DSSE signature.
// Verifies the payload type matches in-toto JSON format and the statement type is correct.
// Returns the extracted Manifest or an error if validation fails.
func VerifySignedContent(payloadType string, payload []byte) (*manifest.Manifest, error) {
	if payloadType != utils.InTotoJSONPayloadType {
		return nil, fmt.Errorf("expected DSSE payload %s, but got %s", utils.InTotoJSONPayloadType, payloadType)
	}

	var dssePayload map[string]interface{}
	if err := json.Unmarshal(payload, &dssePayload); err != nil {
		return nil, fmt.Errorf("failed to unmarshal DSSE payload: %w", err)
	}

	payloadTypeField, ok := dssePayload["_type"].(string)
	if !ok {
		return nil, fmt.Errorf("_type field missing or not a string")
	}

	if payloadTypeField != utils.InTotoStatementType {
		return nil, fmt.Errorf("expected in-toto %s payload, but got %s", utils.InTotoStatementType, payloadTypeField)
	}

	return DSSEPayloadToManifest(dssePayload)
}
