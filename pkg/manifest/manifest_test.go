//
// Copyright 2025 The Sigstore Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package manifest

import (
	"testing"

	"github.com/sigstore/model-signing/pkg/hashing/digests"
)

func newTestDigest(alg string, b byte) digests.Digest {
	return digests.NewDigest(alg, []byte{b})
}

func TestNewManifestAndResourceDescriptorsSorted(t *testing.T) {
	ser := NewFileSerialization("sha256", false, nil)

	item1 := NewFileManifestItem("b.txt", newTestDigest("sha256", 0x02))
	item2 := NewFileManifestItem("a.txt", newTestDigest("sha256", 0x01))

	m := NewManifest("test_model", []ManifestItem{item1, item2}, ser)

	if m.ModelName() != "test_model" {
		t.Fatalf("ModelName() = %q, want %q", m.ModelName(), "test_model")
	}

	descs := m.ResourceDescriptors()
	if len(descs) != 2 {
		t.Fatalf("ResourceDescriptors length = %d, want %d", len(descs), 2)
	}

	// Should be sorted lexicographically by identifier.
	if descs[0].Identifier != "a.txt" || descs[1].Identifier != "b.txt" {
		t.Fatalf("ResourceDescriptors not sorted by identifier: got [%q, %q]",
			descs[0].Identifier, descs[1].Identifier)
	}
}

func TestManifestEqualSameItemsDifferentOrder(t *testing.T) {
	ser := NewFileSerialization("sha256", false, nil)

	item1 := NewFileManifestItem("a.txt", newTestDigest("sha256", 0x01))
	item2 := NewFileManifestItem("b.txt", newTestDigest("sha256", 0x02))

	// manifest1 builds map with items in [item1, item2] order
	m1 := NewManifest("model1", []ManifestItem{item1, item2}, ser)

	// manifest2 builds map with items in [item2, item1] order
	m2 := NewManifest("model2", []ManifestItem{item2, item1}, ser)

	if !m1.Equal(m2) {
		t.Fatalf("manifests with same items in different order should be equal")
	}

	// also test symmetry
	if !m2.Equal(m1) {
		t.Fatalf("manifest equality not symmetric")
	}
}

func TestManifestNotEqualDifferentDigest(t *testing.T) {
	ser := NewFileSerialization("sha256", false, nil)

	item1 := NewFileManifestItem("a.txt", newTestDigest("sha256", 0x01))
	item1Modified := NewFileManifestItem("a.txt", newTestDigest("sha256", 0xFF))

	m1 := NewManifest("model", []ManifestItem{item1}, ser)
	m2 := NewManifest("model", []ManifestItem{item1Modified}, ser)

	if m1.Equal(m2) {
		t.Fatalf("manifests with different digests for same identifier should not be equal")
	}
}

func TestManifestNotEqualDifferentItems(t *testing.T) {
	ser := NewFileSerialization("sha256", false, nil)

	item1 := NewFileManifestItem("a.txt", newTestDigest("sha256", 0x01))
	item2 := NewFileManifestItem("b.txt", newTestDigest("sha256", 0x02))

	m1 := NewManifest("model", []ManifestItem{item1}, ser)
	m2 := NewManifest("model", []ManifestItem{item1, item2}, ser)

	if m1.Equal(m2) {
		t.Fatalf("manifests with different item sets should not be equal")
	}
}

func TestManifestSerializationParametersCopy(t *testing.T) {
	ser := NewFileSerialization("sha256", false, []string{"ignore/me"})
	m := NewManifest("model", nil, ser)

	params := m.SerializationParameters()
	params["hash_type"] = "tampered"

	params2 := m.SerializationParameters()
	if params2["hash_type"] != "sha256" {
		t.Fatalf("underlying serialization parameters mutated via returned map: got %v", params2["hash_type"])
	}
}

func TestEqualDigestHelper(t *testing.T) {
	d1 := newTestDigest("sha256", 0x01)
	d2 := newTestDigest("sha256", 0x01)
	d3 := newTestDigest("sha256", 0x02)
	d4 := newTestDigest("sha512", 0x01)

	if !equalDigest(d1, d2) {
		t.Fatalf("equalDigest(d1, d2) = false, want true")
	}
	if equalDigest(d1, d3) {
		t.Fatalf("equalDigest(d1, d3) = true, want false (different value)")
	}
	if equalDigest(d1, d4) {
		t.Fatalf("equalDigest(d1, d4) = true, want false (different algorithm)")
	}
}
