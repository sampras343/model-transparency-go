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
	"encoding/json"
	"fmt"

	intoto "github.com/in-toto/attestation/go/v1"
	"github.com/sigstore/model-signing/pkg/hashing/digests"
	"github.com/sigstore/model-signing/pkg/hashing/engines/memory"
	"github.com/sigstore/model-signing/pkg/manifest"
	"github.com/sigstore/model-signing/pkg/utils"
	"google.golang.org/protobuf/encoding/protojson"
	structpb "google.golang.org/protobuf/types/known/structpb"
)

// MarshalPayload converts a Manifest into an in-toto JSON payload suitable
// for DSSE signing. This is the canonical bytes representation that gets
// signed by sigstore-go.
//
// The payload is an in-toto Statement with:
//   - subject: model name + SHA256 root digest over all file digests
//   - predicateType: "https://model_signing/signature/v1.0"
//   - predicate: serialization metadata + resource list
func MarshalPayload(m *manifest.Manifest) ([]byte, error) {
	// Build resources list and collect digests for root hash
	descriptors := m.ResourceDescriptors()
	resources := make([]map[string]interface{}, 0, len(descriptors))
	digestList := make([]digests.Digest, 0, len(descriptors))

	for _, desc := range descriptors {
		digestList = append(digestList, desc.Digest)

		resource := map[string]interface{}{
			"name":      desc.Identifier,
			"algorithm": desc.Digest.Algorithm(),
			"digest":    desc.Digest.Hex(),
		}
		resources = append(resources, resource)
	}

	// Compute root digest (SHA256 over all individual digests in order)
	rootDigest, err := memory.ComputeRootDigest(digestList)
	if err != nil {
		return nil, fmt.Errorf("failed to compute root digest: %w", err)
	}

	// Build subject with model name and root digest
	subject := &intoto.ResourceDescriptor{
		Name: m.ModelName(),
		Digest: map[string]string{
			"sha256": rootDigest.Hex(),
		},
	}

	// Build predicate with serialization metadata + resources
	serializationParams := convertToProtoCompatible(m.SerializationParameters())
	resourcesCompat := convertToProtoCompatible(resources)

	predicateMap := map[string]interface{}{
		"serialization": serializationParams,
		"resources":     resourcesCompat,
	}

	predicateStruct, err := structpb.NewStruct(predicateMap)
	if err != nil {
		return nil, fmt.Errorf("failed to build predicate struct: %w", err)
	}

	// Create in-toto statement
	statement := &intoto.Statement{
		Type:          utils.InTotoStatementType,
		Subject:       []*intoto.ResourceDescriptor{subject},
		PredicateType: utils.PredicateType,
		Predicate:     predicateStruct,
	}

	// Serialize to JSON
	opts := protojson.MarshalOptions{
		UseProtoNames:   false,
		EmitUnpopulated: false,
	}

	return opts.Marshal(statement)
}

// UnmarshalPayload reconstructs a Manifest from a verified in-toto JSON
// payload (as extracted from a DSSE envelope after verification).
//
// Validates the root digest against the resource digests. Handles both
// v1.0 and v0.2 (compat) predicate formats.
func UnmarshalPayload(data []byte) (*manifest.Manifest, error) {
	// Parse JSON into a generic map for flexible handling
	var dssePayload map[string]interface{}
	if err := json.Unmarshal(data, &dssePayload); err != nil {
		return nil, fmt.Errorf("failed to unmarshal payload JSON: %w", err)
	}

	predicateType, ok := dssePayload["predicateType"].(string)
	if !ok {
		return nil, fmt.Errorf("predicateType field missing or not a string")
	}

	if predicateType == utils.PredicateTypeCompat {
		return unmarshalPayloadCompat(dssePayload)
	}

	if predicateType != utils.PredicateType {
		return nil, fmt.Errorf("predicate type mismatch, expected %s, got %s", utils.PredicateType, predicateType)
	}

	return unmarshalPayloadV1(dssePayload)
}

// unmarshalPayloadV1 handles the v1.0 predicate format.
func unmarshalPayloadV1(dssePayload map[string]interface{}) (*manifest.Manifest, error) {
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

	expectedDigest, ok := digestMap[utils.DefaultHashAlgorithm].(string)
	if !ok {
		return nil, fmt.Errorf("subject digest %s missing or not a string", utils.DefaultHashAlgorithm)
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

	// Verify root digest
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

// convertToProtoCompatible recursively converts Go types to protobuf-compatible types.
// Handles typed slices like []string or []map[string]interface{} which
// structpb.NewStruct cannot process directly.
func convertToProtoCompatible(v interface{}) interface{} {
	switch val := v.(type) {
	case map[string]interface{}:
		result := make(map[string]interface{}, len(val))
		for k, v := range val {
			result[k] = convertToProtoCompatible(v)
		}
		return result
	case []map[string]interface{}:
		result := make([]interface{}, len(val))
		for i, m := range val {
			result[i] = convertToProtoCompatible(m)
		}
		return result
	case []string:
		result := make([]interface{}, len(val))
		for i, s := range val {
			result[i] = s
		}
		return result
	case []interface{}:
		result := make([]interface{}, len(val))
		for i, v := range val {
			result[i] = convertToProtoCompatible(v)
		}
		return result
	default:
		return val
	}
}
