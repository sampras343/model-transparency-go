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

package oci

import (
	"os"
	"path/filepath"
	"testing"
)

func TestParseManifest(t *testing.T) {
	tests := []struct {
		name    string
		json    string
		wantErr bool
	}{
		{
			name: "valid OCI manifest",
			json: `{
				"schemaVersion": 2,
				"mediaType": "application/vnd.oci.image.manifest.v1+json",
				"config": {
					"mediaType": "application/vnd.oci.image.config.v1+json",
					"digest": "sha256:44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a",
					"size": 233
				},
				"layers": [
					{
						"mediaType": "application/vnd.oci.image.layer.v1.tar+gzip",
						"digest": "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
						"size": 1234
					}
				]
			}`,
			wantErr: false,
		},
		{
			name:    "invalid JSON",
			json:    `{invalid}`,
			wantErr: true,
		},
		{
			name:    "empty JSON",
			json:    `{}`,
			wantErr: false, // Parse succeeds, validation catches errors
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m, err := ParseManifest([]byte(tt.json))
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseManifest() error = %v, wantErr %v", err, tt.wantErr)
			}
			if err == nil && m == nil {
				t.Error("ParseManifest() returned nil manifest without error")
			}
		})
	}
}

func TestImageManifest_Validate(t *testing.T) {
	tests := []struct {
		name     string
		manifest *ImageManifest
		wantErr  bool
	}{
		{
			name: "valid manifest",
			manifest: &ImageManifest{
				SchemaVersion: 2,
				Config: Descriptor{
					Digest: "sha256:44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a",
				},
				Layers: []Descriptor{
					{
						Digest: "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
					},
				},
			},
			wantErr: false,
		},
		{
			name: "wrong schema version",
			manifest: &ImageManifest{
				SchemaVersion: 1,
				Config: Descriptor{
					Digest: "sha256:44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a",
				},
				Layers: []Descriptor{
					{
						Digest: "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
					},
				},
			},
			wantErr: true,
		},
		{
			name: "missing config digest",
			manifest: &ImageManifest{
				SchemaVersion: 2,
				Config:        Descriptor{},
				Layers: []Descriptor{
					{
						Digest: "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
					},
				},
			},
			wantErr: true,
		},
		{
			name: "no layers",
			manifest: &ImageManifest{
				SchemaVersion: 2,
				Config: Descriptor{
					Digest: "sha256:44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a",
				},
				Layers: []Descriptor{},
			},
			wantErr: true,
		},
		{
			name: "invalid digest format",
			manifest: &ImageManifest{
				SchemaVersion: 2,
				Config: Descriptor{
					Digest: "invalid-digest",
				},
				Layers: []Descriptor{
					{
						Digest: "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
					},
				},
			},
			wantErr: true,
		},
		{
			name: "unsupported algorithm",
			manifest: &ImageManifest{
				SchemaVersion: 2,
				Config: Descriptor{
					Digest: "md5:d41d8cd98f00b204e9800998ecf8427e",
				},
				Layers: []Descriptor{
					{
						Digest: "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
					},
				},
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.manifest.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestIsOCIManifest(t *testing.T) {
	// Create temp directory for test files
	tmpDir, err := os.MkdirTemp("", "oci-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Create valid OCI manifest file
	validManifest := `{
		"schemaVersion": 2,
		"config": {"digest": "sha256:44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a"},
		"layers": [{"digest": "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"}]
	}`
	validPath := filepath.Join(tmpDir, "valid.json")
	if err := os.WriteFile(validPath, []byte(validManifest), 0644); err != nil {
		t.Fatalf("failed to write valid manifest: %v", err)
	}

	// Create invalid JSON file
	invalidPath := filepath.Join(tmpDir, "invalid.json")
	if err := os.WriteFile(invalidPath, []byte("{invalid}"), 0644); err != nil {
		t.Fatalf("failed to write invalid file: %v", err)
	}

	// Create non-JSON file
	nonJsonPath := filepath.Join(tmpDir, "model.bin")
	if err := os.WriteFile(nonJsonPath, []byte("binary data"), 0644); err != nil {
		t.Fatalf("failed to write non-json file: %v", err)
	}

	tests := []struct {
		name string
		path string
		want bool
	}{
		{
			name: "valid OCI manifest",
			path: validPath,
			want: true,
		},
		{
			name: "invalid JSON",
			path: invalidPath,
			want: false,
		},
		{
			name: "non-JSON file",
			path: nonJsonPath,
			want: false,
		},
		{
			name: "non-existent file",
			path: filepath.Join(tmpDir, "nonexistent.json"),
			want: false,
		},
		{
			name: "directory",
			path: tmpDir,
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := IsOCIManifest(tt.path)
			if got != tt.want {
				t.Errorf("IsOCIManifest() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestCreateManifestFromOCILayers(t *testing.T) {
	tests := []struct {
		name          string
		manifest      *ImageManifest
		modelName     string
		includeConfig bool
		wantItems     int
		wantErr       bool
	}{
		{
			name: "with config",
			manifest: &ImageManifest{
				SchemaVersion: 2,
				Config: Descriptor{
					Digest: "sha256:44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a",
				},
				Layers: []Descriptor{
					{
						Digest: "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
					},
				},
			},
			modelName:     "test-model",
			includeConfig: true,
			wantItems:     2, // config + 1 layer
			wantErr:       false,
		},
		{
			name: "without config",
			manifest: &ImageManifest{
				SchemaVersion: 2,
				Config: Descriptor{
					Digest: "sha256:44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a",
				},
				Layers: []Descriptor{
					{
						Digest: "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
					},
				},
			},
			modelName:     "test-model",
			includeConfig: false,
			wantItems:     1, // 1 layer only
			wantErr:       false,
		},
		{
			name: "multiple layers with annotations",
			manifest: &ImageManifest{
				SchemaVersion: 2,
				Config: Descriptor{
					Digest: "sha256:44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a",
				},
				Layers: []Descriptor{
					{
						Digest: "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
						Annotations: map[string]string{
							"org.opencontainers.image.title": "model.safetensors",
						},
					},
					{
						Digest: "sha256:abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
						Annotations: map[string]string{
							"org.opencontainers.image.title": "tokenizer.json",
						},
					},
				},
			},
			modelName:     "",
			includeConfig: true,
			wantItems:     3, // config + 2 layers
			wantErr:       false,
		},
		{
			name: "no layers",
			manifest: &ImageManifest{
				SchemaVersion: 2,
				Config: Descriptor{
					Digest: "sha256:44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a",
				},
				Layers: []Descriptor{},
			},
			modelName:     "test-model",
			includeConfig: true,
			wantItems:     0,
			wantErr:       true,
		},
		{
			name: "extract model name from annotations",
			manifest: &ImageManifest{
				SchemaVersion: 2,
				Config: Descriptor{
					Digest: "sha256:44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a",
				},
				Layers: []Descriptor{
					{
						Digest: "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
					},
				},
				Annotations: map[string]string{
					"org.opencontainers.image.name": "my-model",
				},
			},
			modelName:     "",
			includeConfig: false,
			wantItems:     1,
			wantErr:       false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m, err := CreateManifestFromOCILayers(tt.manifest, tt.modelName, tt.includeConfig)
			if (err != nil) != tt.wantErr {
				t.Errorf("CreateManifestFromOCILayers() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if err == nil {
				items := m.ResourceDescriptors()
				if len(items) != tt.wantItems {
					t.Errorf("CreateManifestFromOCILayers() got %d items, want %d", len(items), tt.wantItems)
				}
			}
		})
	}
}

func TestModelNameFromPath(t *testing.T) {
	tests := []struct {
		name string
		path string
		want string
	}{
		{
			name: "simple json file",
			path: "/path/to/model.json",
			want: "model",
		},
		{
			name: "file with multiple dots",
			path: "/path/to/my.model.v1.json",
			want: "my.model.v1",
		},
		{
			name: "just filename",
			path: "manifest.json",
			want: "manifest",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ModelNameFromPath(tt.path)
			if got != tt.want {
				t.Errorf("ModelNameFromPath() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestCreateManifestFromOCILayersWithIgnore(t *testing.T) {
	manifest := &ImageManifest{
		SchemaVersion: 2,
		Config: Descriptor{
			Digest: "sha256:44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a",
		},
		Layers: []Descriptor{
			{
				Digest: "sha256:1111111111111111111111111111111111111111111111111111111111111111",
				Annotations: map[string]string{
					"org.opencontainers.image.title": "model.safetensors",
				},
			},
			{
				Digest: "sha256:2222222222222222222222222222222222222222222222222222222222222222",
				Annotations: map[string]string{
					"org.opencontainers.image.title": "merges.txt",
				},
			},
			{
				Digest: "sha256:3333333333333333333333333333333333333333333333333333333333333333",
				Annotations: map[string]string{
					"org.opencontainers.image.title": "tokenizer.json",
				},
			},
		},
	}

	tests := []struct {
		name        string
		ignorePaths []string
		wantItems   int
	}{
		{
			name:        "no ignore paths",
			ignorePaths: nil,
			wantItems:   4, // config + 3 layers
		},
		{
			name:        "ignore one layer",
			ignorePaths: []string{"merges.txt"},
			wantItems:   3, // config + 2 layers
		},
		{
			name:        "ignore multiple layers",
			ignorePaths: []string{"merges.txt", "tokenizer.json"},
			wantItems:   2, // config + 1 layer
		},
		{
			name:        "ignore config",
			ignorePaths: []string{"config.json"},
			wantItems:   3, // 3 layers only
		},
		{
			name:        "ignore all",
			ignorePaths: []string{"config.json", "model.safetensors", "merges.txt", "tokenizer.json"},
			wantItems:   0, // should error
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m, err := CreateManifestFromOCILayersWithIgnore(manifest, "test", true, tt.ignorePaths)
			if tt.wantItems == 0 {
				if err == nil {
					t.Error("expected error when all items are ignored, got nil")
				}
				return
			}
			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}
			items := m.ResourceDescriptors()
			if len(items) != tt.wantItems {
				t.Errorf("got %d items, want %d", len(items), tt.wantItems)
			}
		})
	}
}

func TestCompareManifests(t *testing.T) {
	// Create two identical manifests
	manifest1 := &ImageManifest{
		SchemaVersion: 2,
		Config: Descriptor{
			Digest: "sha256:44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a",
		},
		Layers: []Descriptor{
			{
				Digest: "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
			},
		},
	}

	manifest2 := &ImageManifest{
		SchemaVersion: 2,
		Config: Descriptor{
			Digest: "sha256:44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a",
		},
		Layers: []Descriptor{
			{
				Digest: "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
			},
		},
	}

	manifest3 := &ImageManifest{
		SchemaVersion: 2,
		Config: Descriptor{
			Digest: "sha256:44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a",
		},
		Layers: []Descriptor{
			{
				Digest: "sha256:1111111111111111111111111111111111111111111111111111111111111111",
			},
		},
	}

	m1, err := CreateManifestFromOCILayers(manifest1, "test", true)
	if err != nil {
		t.Fatalf("failed to create manifest1: %v", err)
	}

	m2, err := CreateManifestFromOCILayers(manifest2, "test", true)
	if err != nil {
		t.Fatalf("failed to create manifest2: %v", err)
	}

	m3, err := CreateManifestFromOCILayers(manifest3, "test", true)
	if err != nil {
		t.Fatalf("failed to create manifest3: %v", err)
	}

	// Test equal manifests
	if err := CompareManifests(m1, m2); err != nil {
		t.Errorf("CompareManifests() expected equal manifests, got error: %v", err)
	}

	// Test different manifests
	if err := CompareManifests(m1, m3); err == nil {
		t.Error("CompareManifests() expected error for different manifests, got nil")
	}
}
