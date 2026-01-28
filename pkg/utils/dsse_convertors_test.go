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

import "testing"

func TestDSSEPayloadToManifest_ValidPayload(t *testing.T) {
	// Create a minimal valid payload
	payload := map[string]interface{}{
		"_type":         InTotoStatementType,
		"predicateType": PredicateType,
		"subject": []interface{}{
			map[string]interface{}{
				"name": "test-model",
				"digest": map[string]interface{}{
					// This is a valid root hash computed from the resources below
					"sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
				},
			},
		},
		"predicate": map[string]interface{}{
			"serialization": map[string]interface{}{
				"method":         "files",
				"hash_type":      "sha256",
				"allow_symlinks": false,
			},
			"resources": []interface{}{},
		},
	}

	manifest, err := DSSEPayloadToManifest(payload)
	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}

	if manifest == nil {
		t.Fatal("Expected non-nil manifest")
	}

	if manifest.ModelName() != "test-model" {
		t.Errorf("Expected model name 'test-model', got '%s'", manifest.ModelName())
	}
}

func TestDSSEPayloadToManifest_MissingPredicateType(t *testing.T) {
	payload := map[string]interface{}{
		"_type": InTotoStatementType,
		"subject": []interface{}{
			map[string]interface{}{
				"name": "test-model",
				"digest": map[string]interface{}{
					"sha256": "abcd1234",
				},
			},
		},
	}

	_, err := DSSEPayloadToManifest(payload)
	if err == nil {
		t.Error("Expected error for missing predicateType")
	}
}

func TestDSSEPayloadToManifest_WrongPredicateType(t *testing.T) {
	payload := map[string]interface{}{
		"_type":         InTotoStatementType,
		"predicateType": "https://wrong.predicate.type",
		"subject": []interface{}{
			map[string]interface{}{
				"name": "test-model",
				"digest": map[string]interface{}{
					"sha256": "abcd1234",
				},
			},
		},
	}

	_, err := DSSEPayloadToManifest(payload)
	if err == nil {
		t.Error("Expected error for wrong predicateType")
	}
}

func TestDSSEPayloadToManifest_MissingSubject(t *testing.T) {
	payload := map[string]interface{}{
		"_type":         InTotoStatementType,
		"predicateType": PredicateType,
	}

	_, err := DSSEPayloadToManifest(payload)
	if err == nil {
		t.Error("Expected error for missing subject")
	}
}

func TestDSSEPayloadToManifest_MultipleSubjects(t *testing.T) {
	payload := map[string]interface{}{
		"_type":         InTotoStatementType,
		"predicateType": PredicateType,
		"subject": []interface{}{
			map[string]interface{}{
				"name": "model1",
				"digest": map[string]interface{}{
					"sha256": "abcd1234",
				},
			},
			map[string]interface{}{
				"name": "model2",
				"digest": map[string]interface{}{
					"sha256": "efgh5678",
				},
			},
		},
	}

	_, err := DSSEPayloadToManifest(payload)
	if err == nil {
		t.Error("Expected error for multiple subjects")
	}
}

func TestDSSEPayloadToManifest_MissingPredicate(t *testing.T) {
	payload := map[string]interface{}{
		"_type":         InTotoStatementType,
		"predicateType": PredicateType,
		"subject": []interface{}{
			map[string]interface{}{
				"name": "test-model",
				"digest": map[string]interface{}{
					"sha256": "abcd1234",
				},
			},
		},
	}

	_, err := DSSEPayloadToManifest(payload)
	if err == nil {
		t.Error("Expected error for missing predicate")
	}
}

func TestDSSEPayloadToManifest_MissingSerialization(t *testing.T) {
	payload := map[string]interface{}{
		"_type":         InTotoStatementType,
		"predicateType": PredicateType,
		"subject": []interface{}{
			map[string]interface{}{
				"name": "test-model",
				"digest": map[string]interface{}{
					"sha256": "abcd1234",
				},
			},
		},
		"predicate": map[string]interface{}{
			"resources": []interface{}{},
		},
	}

	_, err := DSSEPayloadToManifest(payload)
	if err == nil {
		t.Error("Expected error for missing serialization")
	}
}

func TestDSSEPayloadToManifest_MissingResources(t *testing.T) {
	payload := map[string]interface{}{
		"_type":         InTotoStatementType,
		"predicateType": PredicateType,
		"subject": []interface{}{
			map[string]interface{}{
				"name": "test-model",
				"digest": map[string]interface{}{
					"sha256": "abcd1234",
				},
			},
		},
		"predicate": map[string]interface{}{
			"serialization": map[string]interface{}{
				"method":         "files",
				"hash_type":      "sha256",
				"allow_symlinks": false,
			},
		},
	}

	_, err := DSSEPayloadToManifest(payload)
	if err == nil {
		t.Error("Expected error for missing resources")
	}
}

func TestDSSEPayloadToManifest_InvalidResourceDigest(t *testing.T) {
	payload := map[string]interface{}{
		"_type":         InTotoStatementType,
		"predicateType": PredicateType,
		"subject": []interface{}{
			map[string]interface{}{
				"name": "test-model",
				"digest": map[string]interface{}{
					"sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
				},
			},
		},
		"predicate": map[string]interface{}{
			"serialization": map[string]interface{}{
				"method":         "files",
				"hash_type":      "sha256",
				"allow_symlinks": false,
			},
			"resources": []interface{}{
				map[string]interface{}{
					"name":      "file1.txt",
					"algorithm": "sha256",
					"digest":    "invalid-hex",
				},
			},
		},
	}

	_, err := DSSEPayloadToManifest(payload)
	if err == nil {
		t.Error("Expected error for invalid resource digest")
	}
}

func TestDSSEPayloadToManifestCompat_ValidPayload(t *testing.T) {
	// Create a v0.2 format payload
	payload := map[string]interface{}{
		"_type":         InTotoStatementType,
		"predicateType": PredicateTypeCompat,
		"subject": []interface{}{
			map[string]interface{}{
				"name": "file1.txt",
				"digest": map[string]interface{}{
					"sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
				},
			},
			map[string]interface{}{
				"name": "file2.txt",
				"digest": map[string]interface{}{
					"sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
				},
			},
		},
	}

	manifest, err := DSSEPayloadToManifestCompat(payload)
	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}

	if manifest == nil {
		t.Fatal("Expected non-nil manifest")
	}

	if manifest.ModelName() != "compat-undefined-not-present" {
		t.Errorf("Expected compat model name, got '%s'", manifest.ModelName())
	}
}

func TestDSSEPayloadToManifestCompat_MissingSubject(t *testing.T) {
	payload := map[string]interface{}{
		"_type":         InTotoStatementType,
		"predicateType": PredicateTypeCompat,
	}

	_, err := DSSEPayloadToManifestCompat(payload)
	if err == nil {
		t.Error("Expected error for missing subject in compat format")
	}
}

func TestDSSEPayloadToManifestCompat_InvalidDigest(t *testing.T) {
	payload := map[string]interface{}{
		"_type":         InTotoStatementType,
		"predicateType": PredicateTypeCompat,
		"subject": []interface{}{
			map[string]interface{}{
				"name": "file1.txt",
				"digest": map[string]interface{}{
					"sha256": "zzz-invalid",
				},
			},
		},
	}

	_, err := DSSEPayloadToManifestCompat(payload)
	if err == nil {
		t.Error("Expected error for invalid digest in compat format")
	}
}

func TestDSSEPayloadToManifest_CompatFallback(t *testing.T) {
	// Test that PredicateTypeCompat triggers compat parsing
	payload := map[string]interface{}{
		"_type":         InTotoStatementType,
		"predicateType": PredicateTypeCompat,
		"subject": []interface{}{
			map[string]interface{}{
				"name": "file1.txt",
				"digest": map[string]interface{}{
					"sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
				},
			},
		},
	}

	// Call main function which should delegate to compat
	manifest, err := DSSEPayloadToManifest(payload)
	if err != nil {
		t.Fatalf("Expected no error for compat fallback, got: %v", err)
	}

	if manifest.ModelName() != "compat-undefined-not-present" {
		t.Error("Expected compat fallback to be used")
	}
}

func TestVerifySignedContent_ValidPayload(t *testing.T) {
	// Create a valid in-toto statement
	payloadJSON := []byte(`{
		"_type": "` + InTotoStatementType + `",
		"predicateType": "` + PredicateType + `",
		"subject": [
			{
				"name": "test-model",
				"digest": {
					"sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
				}
			}
		],
		"predicate": {
			"serialization": {
				"method": "files",
				"hash_type": "sha256",
				"allow_symlinks": false
			},
			"resources": []
		}
	}`)

	manifest, err := VerifySignedContent(InTotoJSONPayloadType, payloadJSON)
	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}

	if manifest == nil {
		t.Fatal("Expected non-nil manifest")
	}
}

func TestVerifySignedContent_WrongPayloadType(t *testing.T) {
	payloadJSON := []byte(`{"test": "data"}`)

	_, err := VerifySignedContent("application/wrong-type", payloadJSON)
	if err == nil {
		t.Error("Expected error for wrong payload type")
	}
}

func TestVerifySignedContent_InvalidJSON(t *testing.T) {
	payloadJSON := []byte(`{invalid json}`)

	_, err := VerifySignedContent(InTotoJSONPayloadType, payloadJSON)
	if err == nil {
		t.Error("Expected error for invalid JSON")
	}
}

func TestVerifySignedContent_Missing_Type(t *testing.T) {
	payloadJSON := []byte(`{
		"predicateType": "` + PredicateType + `",
		"subject": []
	}`)

	_, err := VerifySignedContent(InTotoJSONPayloadType, payloadJSON)
	if err == nil {
		t.Error("Expected error for missing _type field")
	}
}

func TestVerifySignedContent_Wrong_Type(t *testing.T) {
	payloadJSON := []byte(`{
		"_type": "https://wrong.type",
		"predicateType": "` + PredicateType + `",
		"subject": []
	}`)

	_, err := VerifySignedContent(InTotoJSONPayloadType, payloadJSON)
	if err == nil {
		t.Error("Expected error for wrong _type value")
	}
}
