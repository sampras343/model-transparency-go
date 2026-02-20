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

package modelartifact

import (
	"encoding/hex"
	"fmt"

	"github.com/sigstore/model-signing/pkg/hashing/digests"
	"github.com/sigstore/model-signing/pkg/manifest"
	"github.com/sigstore/model-signing/pkg/utils"
)

// unmarshalPayloadCompat converts a DSSE payload in the v0.2 experimental
// format to a Manifest. Maintained for backward compatibility with signatures
// created before v1.0.
func unmarshalPayloadCompat(dssePayload map[string]interface{}) (*manifest.Manifest, error) {
	// Model name is not defined in v0.2, use a constant
	modelName := "compat-undefined-not-present"

	// Serialization format is not present, build a default
	serializationArgs := map[string]interface{}{
		"method":         utils.SerializationMethodFiles,
		"hash_type":      utils.DefaultHashAlgorithm,
		"allow_symlinks": false,
	}

	serializationType, err := manifest.SerializationTypeFromArgs(serializationArgs)
	if err != nil {
		return nil, fmt.Errorf("failed to create compat serialization type: %w", err)
	}

	// Extract subjects (the only field with actual content in v0.2)
	subjectsRaw, ok := dssePayload["subject"]
	if !ok {
		return nil, fmt.Errorf("subject field missing in compat format")
	}

	subjects, ok := subjectsRaw.([]interface{})
	if !ok {
		return nil, fmt.Errorf("subject field is not an array")
	}

	items := make([]manifest.ManifestItem, 0, len(subjects))
	for _, subjectRaw := range subjects {
		subject, ok := subjectRaw.(map[string]interface{})
		if !ok {
			return nil, fmt.Errorf("subject is not an object")
		}

		name, ok := subject["name"].(string)
		if !ok {
			return nil, fmt.Errorf("subject name missing or not a string")
		}

		digestMap, ok := subject["digest"].(map[string]interface{})
		if !ok {
			return nil, fmt.Errorf("subject digest missing or not an object")
		}

		// v0.2 only supported sha256
		algorithm := utils.DefaultHashAlgorithm
		digestValue, ok := digestMap[algorithm].(string)
		if !ok {
			return nil, fmt.Errorf("subject digest %s missing or not a string", utils.DefaultHashAlgorithm)
		}

		digestBytes, err := hex.DecodeString(digestValue)
		if err != nil {
			return nil, fmt.Errorf("failed to parse digest for %s: %w", name, err)
		}

		digest := digests.NewDigest(algorithm, digestBytes)
		item, err := serializationType.NewItem(name, digest)
		if err != nil {
			return nil, fmt.Errorf("failed to create manifest item for %s: %w", name, err)
		}

		items = append(items, item)
	}

	return manifest.NewManifest(modelName, items, serializationType), nil
}
