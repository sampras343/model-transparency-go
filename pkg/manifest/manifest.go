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

// Package manifest provides types and functions for creating and managing
// model manifests that pair resource identifiers with cryptographic digests.
package manifest

import (
	"bytes"
	"sort"

	"github.com/sigstore/model-signing/pkg/hashing/digests"
)

// ResourceDescriptor describes content from a manifest with an identifier and digest.
//
// This type is similar to in-toto's ResourceDescriptor but requires all fields
// to be present, unlike in-toto where fields are optional. It can be mapped to
// in-toto format when needed for interoperability.
//
// See github.com/in-toto/attestation/blob/main/spec/v1/resource_descriptor.md
// for the in-toto specification.
type ResourceDescriptor struct {
	// Identifier is a string that uniquely identifies this object within the
	// manifest. Depending on the serialized format, users might require the
	// identifier to be unique across all manifests stored in a system.
	// Corresponds to name, uri, or content in the in-toto specification.
	Identifier string

	// Digest is the cryptographic hash of the resource.
	Digest digests.Digest
}

// Manifest is a generic manifest file to represent a model.
//
// It pairs identifiers (names of resources) with their digests and records
// the serialization type used to generate those identifiers.
type Manifest struct {
	name              string
	items             map[string]digests.Digest
	serializationType SerializationType
}

// NewManifest builds a manifest from a collection of already hashed objects.
//
// The modelName parameter is an informative name for the model; changing it
// does not affect equality. The items slice is converted into a map keyed by
// each item's canonical Name(). The serializationType records the method and
// parameters used to generate the manifest.
//
// Returns a new Manifest instance.
func NewManifest(modelName string, items []ManifestItem, serializationType SerializationType) *Manifest {
	itemMap := make(map[string]digests.Digest, len(items))
	for _, it := range items {
		itemMap[it.Name()] = it.Digest()
	}
	return &Manifest{
		name:              modelName,
		items:             itemMap,
		serializationType: serializationType,
	}
}

// ModelName returns the informative name of the model.
//
// This name does not affect manifest equality.
func (manifest *Manifest) ModelName() string {
	return manifest.name
}

// SerializationParameters returns the serialization method and arguments used
// to build the manifest.
//
// Returns a shallow copy of the underlying parameters, so callers can safely
// mutate the returned map without affecting the manifest.
func (manifest *Manifest) SerializationParameters() map[string]any {
	params := manifest.serializationType.Parameters()
	out := make(map[string]any, len(params))
	for k, v := range params {
		out[k] = v
	}
	return out
}

// Equal reports whether two manifests have the same items and digests.
//
// This comparison ignores the model name and serialization type; only the
// mapping from identifiers to digests is compared. Returns true if both
// manifests contain the same identifier-to-digest mappings.
func (manifest *Manifest) Equal(other *Manifest) bool {
	if manifest == other {
		return true
	}
	if other == nil {
		return false
	}

	if len(manifest.items) != len(other.items) {
		return false
	}

	for name, digest := range manifest.items {
		otherDigest, ok := other.items[name]
		if !ok {
			return false
		}
		if !equalDigest(digest, otherDigest) {
			return false
		}
	}

	return true
}

// equalDigest compares two digests by algorithm and value.
//
// Returns true if both digests use the same algorithm and have equal values.
func equalDigest(a, b digests.Digest) bool {
	if a.Algorithm() != b.Algorithm() {
		return false
	}
	return bytes.Equal(a.Value(), b.Value())
}

// ResourceDescriptors returns each resource from the manifest.
//
// Resources are sorted by identifier to provide a stable, deterministic order.
// Returns a slice of ResourceDescriptor instances.
//
//nolint:revive
func (m *Manifest) ResourceDescriptors() []ResourceDescriptor {
	ids := make([]string, 0, len(m.items))
	for id := range m.items {
		ids = append(ids, id)
	}
	sort.Strings(ids)

	descs := make([]ResourceDescriptor, 0, len(ids))
	for _, id := range ids {
		descs = append(descs, ResourceDescriptor{
			Identifier: id,
			Digest:     m.items[id],
		})
	}
	return descs
}
