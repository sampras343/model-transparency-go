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

package signing

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/sigstore/model-signing/pkg/logging"
	"github.com/sigstore/model-signing/pkg/modelartifact"
)

func createTestModel(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "weights.bin"), []byte("model weights"), 0644); err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestPreparePayload_ForwardsHashAlgorithm(t *testing.T) {
	modelDir := createTestModel(t)
	sigPath := filepath.Join(modelDir, "model.sig")

	m, payload, err := PreparePayload(modelDir, sigPath, modelartifact.Options{
		HashAlgorithm: "blake2b",
	}, logging.EnsureLogger(nil))
	if err != nil {
		t.Fatalf("PreparePayload failed: %v", err)
	}
	if m == nil || payload == nil {
		t.Fatal("expected non-nil manifest and payload")
	}

	for _, rd := range m.ResourceDescriptors() {
		if rd.Digest.Algorithm() != "blake2b" {
			t.Errorf("expected blake2b digest, got %s", rd.Digest.Algorithm())
		}
	}
}

func TestPreparePayload_ForwardsShardSize(t *testing.T) {
	modelDir := createTestModel(t)
	sigPath := filepath.Join(modelDir, "model.sig")

	m, payload, err := PreparePayload(modelDir, sigPath, modelartifact.Options{
		ShardSize: 4,
	}, logging.EnsureLogger(nil))
	if err != nil {
		t.Fatalf("PreparePayload failed: %v", err)
	}
	if m == nil || payload == nil {
		t.Fatal("expected non-nil manifest and payload")
	}

	// "model weights" is 13 bytes; with ShardSize=4 we expect 4 shards (4+4+4+1)
	descs := m.ResourceDescriptors()
	if len(descs) < 2 {
		t.Errorf("expected multiple shards with ShardSize=4, got %d descriptors", len(descs))
	}
}

func TestPreparePayload_ExcludesSignaturePath(t *testing.T) {
	modelDir := createTestModel(t)
	sigPath := filepath.Join(modelDir, "model.sig")

	// Create the signature file so it would be hashed if not excluded
	if err := os.WriteFile(sigPath, []byte("sig"), 0644); err != nil {
		t.Fatal(err)
	}

	m, _, err := PreparePayload(modelDir, sigPath, modelartifact.Options{}, logging.EnsureLogger(nil))
	if err != nil {
		t.Fatalf("PreparePayload failed: %v", err)
	}

	for _, rd := range m.ResourceDescriptors() {
		if rd.Identifier == "model.sig" {
			t.Error("signature file should be excluded from manifest")
		}
	}
}
