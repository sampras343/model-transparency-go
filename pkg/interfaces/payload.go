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

package interfaces

import (
	"fmt"

	intoto "github.com/in-toto/attestation/go/v1"
	"github.com/sigstore/model-signing/pkg/hashing/digests"
	"github.com/sigstore/model-signing/pkg/hashing/engines/memory"
	"github.com/sigstore/model-signing/pkg/manifest"
	"github.com/sigstore/model-signing/pkg/utils"
	"google.golang.org/protobuf/encoding/protojson"
	structpb "google.golang.org/protobuf/types/known/structpb"
)

// Payload represents an in-toto payload used to represent a model for signing.
//
// This payload represents all the objects (files, shards, etc.) of the model
// paired with their hashes. It can be seen as a serialization of a manifest.
//
// The structure follows the in-toto attestation format with:
// - subject: Contains the model name and a global digest over all resources
// - predicateType: Identifies this as a model signature (v1.0)
// - predicate: Contains serialization info and the list of resources
//
// The global digest in the subject is computed as SHA256 over all individual
// digests in the order they appear in the predicate
type Payload struct {
	Statement *intoto.Statement
}

// NewPayload creates a signing payload from a manifest.
//
// It computes a root digest over all resource digests and constructs
// an in-toto statement suitable for signing.
func NewPayload(m *manifest.Manifest) (*Payload, error) {
	// Build resources list and collect digests
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

	// Compute root digest using helper function
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

	// Build predicate
	predicateMap := map[string]interface{}{
		"serialization": m.SerializationParameters(),
		"resources":     resources,
		// Other properties can go here in future extensions
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

	return &Payload{Statement: statement}, nil
}

// ToJSON serializes the payload to JSON format suitable for DSSE.
func (p *Payload) ToJSON() ([]byte, error) {
	// Use protojson to convert the statement to JSON
	opts := protojson.MarshalOptions{
		UseProtoNames:   true,
		EmitUnpopulated: false,
	}

	return opts.Marshal(p.Statement)
}

// PayloadFromJSON deserializes a payload from JSON.
func PayloadFromJSON(data []byte) (*Payload, error) {
	statement := &intoto.Statement{}

	opts := protojson.UnmarshalOptions{
		DiscardUnknown: false,
	}

	if err := opts.Unmarshal(data, statement); err != nil {
		return nil, fmt.Errorf("failed to unmarshal statement: %w", err)
	}

	return &Payload{Statement: statement}, nil
}
