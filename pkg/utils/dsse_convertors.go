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
	"encoding/hex"
	"fmt"

	"github.com/sigstore/model-signing/pkg/hashing/digests"
	"github.com/sigstore/model-signing/pkg/hashing/engines/memory"
	"github.com/sigstore/model-signing/pkg/manifest"
)

// DSSEPayloadToManifest converts a DSSE payload (as a map) to a Manifest.
// Handles the current v1.0 predicate format with full validation of subjects, digests, and resources.
// Returns the reconstructed Manifest or an error if the payload is invalid or inconsistent.
func DSSEPayloadToManifest(dssePayload map[string]interface{}) (*manifest.Manifest, error) {
	predicateType, ok := dssePayload["predicateType"].(string)
	if !ok {
		return nil, fmt.Errorf("predicateType field missing or not a string")
	}

	if predicateType != PredicateType {
		if predicateType == PredicateTypeCompat {
			return DSSEPayloadToManifestCompat(dssePayload)
		}
		return nil, fmt.Errorf("predicate type mismatch, expected %s, got %s", PredicateType, predicateType)
	}

	// Extract subjects
	subjectsRaw, ok := dssePayload["subject"]
	if !ok {
		return nil, fmt.Errorf("subject field is not an array")
	}

	subjects, ok := subjectsRaw.([]interface{})
	if !ok {
		return nil, fmt.Errorf("subject field is not an array")
	}

	if len(subjects) != 1 {
		return nil, fmt.Errorf("expected only one subject, got %d", len(subjects))
	}

	subject, ok := subjects[0].(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("subject is not an object")
	}

	modelName, ok := subject["name"].(string)
	if !ok {
		return nil, fmt.Errorf("subject name missing or not a string")
	}

	digestMap, ok := subject["digest"].(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("subject digest missing or not an object")
	}

	expectedDigest, ok := digestMap["sha256"].(string)
	if !ok {
		return nil, fmt.Errorf("subject digest sha256 missing or not a string")
	}

	// Extract predicate
	predicateRaw, ok := dssePayload["predicate"]
	if !ok {
		return nil, fmt.Errorf("predicate field missing")
	}

	predicate, ok := predicateRaw.(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("predicate is not an object")
	}

	// Extract serialization
	serializationRaw, ok := predicate["serialization"]
	if !ok {
		return nil, fmt.Errorf("predicate serialization field missing")
	}

	serializationArgs, ok := serializationRaw.(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("serialization is not an object")
	}

	serializationType, err := manifest.SerializationTypeFromArgs(serializationArgs)
	if err != nil {
		return nil, fmt.Errorf("failed to parse serialization type: %w", err)
	}

	// Extract resources
	resourcesRaw, ok := predicate["resources"]
	if !ok {
		return nil, fmt.Errorf("predicate resources field missing")
	}

	resources, ok := resourcesRaw.([]interface{})
	if !ok {
		return nil, fmt.Errorf("resources is not an array")
	}

	// Reconstruct manifest items and collect digests
	items := make([]manifest.ManifestItem, 0, len(resources))
	digestList := make([]digests.Digest, 0, len(resources))

	for _, resourceRaw := range resources {
		resource, ok := resourceRaw.(map[string]interface{})
		if !ok {
			return nil, fmt.Errorf("resource is not an object")
		}

		name, ok := resource["name"].(string)
		if !ok {
			return nil, fmt.Errorf("resource name missing or not a string")
		}

		algorithm, ok := resource["algorithm"].(string)
		if !ok {
			return nil, fmt.Errorf("resource algorithm missing or not a string")
		}

		digestValue, ok := resource["digest"].(string)
		if !ok {
			return nil, fmt.Errorf("resource digest missing or not a string")
		}

		// Parse digest from hex
		digestBytes, err := hex.DecodeString(digestValue)
		if err != nil {
			return nil, fmt.Errorf("failed to parse digest for %s: %w", name, err)
		}

		digest := digests.NewDigest(algorithm, digestBytes)
		digestList = append(digestList, digest)

		item, err := serializationType.NewItem(name, digest)
		if err != nil {
			return nil, fmt.Errorf("failed to create manifest item for %s: %w", name, err)
		}

		items = append(items, item)
	}

	// Verify root digest using helper function
	rootDigest, err := memory.ComputeRootDigest(digestList)
	if err != nil {
		return nil, fmt.Errorf("failed to compute root digest: %w", err)
	}

	obtainedDigest := rootDigest.Hex()
	if obtainedDigest != expectedDigest {
		return nil, fmt.Errorf("manifest is inconsistent: root digest is %s, but resources hash to %s",
			expectedDigest, obtainedDigest)
	}

	return manifest.NewManifest(modelName, items, serializationType), nil
}

// DSSEPayloadToManifestCompat converts a DSSE payload in the v0.2 experimental format to a Manifest.
// Maintained for backward compatibility with signatures created before v1.0.
// Returns a Manifest with placeholder values for missing v0.2 fields, or an error if conversion fails.
func DSSEPayloadToManifestCompat(dssePayload map[string]interface{}) (*manifest.Manifest, error) {
	// Model name is not defined in v0.2, use a constant
	modelName := "compat-undefined-not-present"

	// Serialization format is not present, build a fake one
	serializationArgs := map[string]interface{}{
		"method":         "files",
		"hash_type":      "sha256",
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
		algorithm := "sha256"
		digestValue, ok := digestMap[algorithm].(string)
		if !ok {
			return nil, fmt.Errorf("subject digest sha256 missing or not a string")
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

	// Note: There is no verification that the manifest is complete at this point
	return manifest.NewManifest(modelName, items, serializationType), nil
}
