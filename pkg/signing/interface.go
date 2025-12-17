package signing

import (
	"encoding/json"
	"fmt"

	"github.com/sigstore/model-signing/pkg/hashing/digests"
	"github.com/sigstore/model-signing/pkg/hashing/engines/memory"
	"github.com/sigstore/model-signing/pkg/manifest"
)

const (
	InTotoJSONPayloadType = "application/vnd.in-toto+json"
	InTotoStatementType   = "https://in-toto.io/Statement/v1"
	PredicateType         = "https://model_signing/signature/v1.0"
	PredicateTypeCompat   = "https://model_signing/Digests/v0.1"
)

// Signature represents a cryptographic signature over a model.
//
// Implementations wrap different signature formats
type Signature interface {
	// Write serializes the signature to the given path.
	Write(path string) error

	// Read deserializes a signature from the given path.
	// This is a factory method that returns a concrete implementation.
	Read(path string) (Signature, error)
}

// Signer signs a payload and produces a Signature.
// Each implementation may manage key material differently.
type Signer interface {
	// Sign creates a signature over the provided payload.
	Sign(payload *Payload) (Signature, error)
}

// Verifier verifies a signature and extracts the manifest.
//
// Each Verifier implementation is paired with a corresponding Signer
// to ensure compatible signature formats and key materials.
type Verifier interface {
	// Verify checks the signature's authenticity and returns the manifest.
	// Returns an error if verification fails.
	Verify(signature Signature) (*manifest.Manifest, error)
}

// DSSEPayloadToManifest converts a DSSE payload (as a map) to a Manifest.
//
// This handles the current v1.0 predicate format.
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

	// Reconstruct manifest items and verify root digest
	hasher, err := memory.NewSHA256Engine(nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create hasher: %w", err)
	}

	items := make([]manifest.ManifestItem, 0, len(resources))
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
		digestBytes, err := hexToBytes(digestValue)
		if err != nil {
			return nil, fmt.Errorf("failed to parse digest for %s: %w", name, err)
		}

		digest := digests.NewDigest(algorithm, digestBytes)
		hasher.Update(digest.Value())

		item, err := serializationType.NewItem(name, digest)
		if err != nil {
			return nil, fmt.Errorf("failed to create manifest item for %s: %w", name, err)
		}

		items = append(items, item)
	}

	// Verify root digest
	rootDigest, err := hasher.Compute()
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

// DSSEPayloadToManifestCompat handles the v0.2 experimental format.
//
// This format is maintained for backward compatibility with signatures
// created before v1.0.
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

		digestBytes, err := hexToBytes(digestValue)
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

// VerifySignedContent is a helper for verifiers to extract and validate
// the payload from a signature.
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

// hexToBytes converts a hex string to bytes.
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
