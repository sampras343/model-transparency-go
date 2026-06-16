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

package manifest

import (
	"reflect"
	"testing"

	"github.com/sigstore/model-signing/pkg/hashing/digests"
)

func TestNewFileManifestItemNameAndDigest(t *testing.T) {
	d := digests.NewDigest("sha256", []byte{0x01, 0x02})

	item := NewFileManifestItem("some/nested/path.txt", d)

	if got := item.Name(); got != "some/nested/path.txt" {
		t.Fatalf("Name() = %q, want %q", got, "some/nested/path.txt")
	}

	if item.Digest().Algorithm() != "sha256" {
		t.Fatalf("Digest().Algorithm() = %q, want %q", item.Digest().Algorithm(), "sha256")
	}
}

func TestNewFileManifestItemDigestImmutability(t *testing.T) {
	raw := []byte{0x01, 0x02, 0x03}
	d := digests.NewDigest("sha256", raw)

	item := NewFileManifestItem("file.txt", d)
	value := item.Digest().Value()

	// mutate returned slice
	value[0] = 0xFF

	// fetch again – should not reflect mutation
	value2 := item.Digest().Value()
	if value2[0] != 0x01 {
		t.Fatalf("digest value mutated through returned slice, got %v", value2)
	}
}

func TestNewShardedFileManifestItemNameAndDigest(t *testing.T) {
	d := digests.NewDigest("sha256", []byte{0x0A})

	item := NewShardedFileManifestItem("shards/file.bin", 10, 20, d)

	wantName := "shards/file.bin:10:20"
	if got := item.Name(); got != wantName {
		t.Fatalf("Name() = %q, want %q", got, wantName)
	}

	if item.Digest().Algorithm() != "sha256" {
		t.Fatalf("Digest().Algorithm() = %q, want %q", item.Digest().Algorithm(), "sha256")
	}
}

func TestParseShardNameValid(t *testing.T) {
	name := "path/to/file:100:200"
	path, start, end, err := parseShardName(name)
	if err != nil {
		t.Fatalf("parseShardName(%q) unexpected error: %v", name, err)
	}

	if path != "path/to/file" {
		t.Errorf("path = %q, want %q", path, "path/to/file")
	}
	if start != 100 {
		t.Errorf("start = %d, want %d", start, 100)
	}
	if end != 200 {
		t.Errorf("end = %d, want %d", end, 200)
	}
}

func TestParseShardNameInvalid(t *testing.T) {
	tests := []string{
		"no-colons-here",
		"only:two",
		"path:not-an-int:2",
		"path:1:not-an-int",
	}

	for _, tc := range tests {
		_, _, _, err := parseShardName(tc)
		if err == nil {
			t.Fatalf("parseShardName(%q) = nil error, want non-nil", tc)
		}
	}
}

func TestParseShardNameWithColonsInPath(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		wantPath  string
		wantStart int64
		wantEnd   int64
	}{
		{
			name:      "single colon in path",
			input:     "file:with:colon:0:1024",
			wantPath:  "file:with:colon",
			wantStart: 0,
			wantEnd:   1024,
		},
		{
			name:      "multiple colons in path",
			input:     "a:b:c:d:100:200",
			wantPath:  "a:b:c:d",
			wantStart: 100,
			wantEnd:   200,
		},
		{
			name:      "colon at start of path",
			input:     ":leading:50:75",
			wantPath:  ":leading",
			wantStart: 50,
			wantEnd:   75,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path, start, end, err := parseShardName(tt.input)
			if err != nil {
				t.Fatalf("parseShardName(%q) unexpected error: %v", tt.input, err)
			}
			if path != tt.wantPath {
				t.Errorf("path = %q, want %q", path, tt.wantPath)
			}
			if start != tt.wantStart {
				t.Errorf("start = %d, want %d", start, tt.wantStart)
			}
			if end != tt.wantEnd {
				t.Errorf("end = %d, want %d", end, tt.wantEnd)
			}
		})
	}
}

func TestShardedFileManifestItemRoundTripName(t *testing.T) {
	d := digests.NewDigest("sha256", []byte{0xAB})
	item := NewShardedFileManifestItem("foo/bar.bin", 0, 4096, d)

	path, start, end, err := parseShardName(item.Name())
	if err != nil {
		t.Fatalf("parseShardName(%q) unexpected error: %v", item.Name(), err)
	}

	if path != "foo/bar.bin" || start != 0 || end != 4096 {
		t.Fatalf("round-trip parseShardName mismatch: got (%q, %d, %d)", path, start, end)
	}

	if !reflect.DeepEqual(item.Digest().Value(), d.Value()) {
		t.Fatalf("Digest mismatch after round-trip")
	}
}

func TestFileManifestItemPathNormalization(t *testing.T) {
	d := digests.NewDigest("sha256", []byte{0x01})
	tests := []struct {
		input string
		want  string
	}{
		{"./config.json", "config.json"},
		{"subdir/./weights.bin", "subdir/weights.bin"},
		{"subdir//file", "subdir/file"},
		{"./a/./b//c", "a/b/c"},
		{"normal/path.txt", "normal/path.txt"},
	}
	for _, tt := range tests {
		item := NewFileManifestItem(tt.input, d)
		if got := item.Name(); got != tt.want {
			t.Errorf("NewFileManifestItem(%q).Name() = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestShardedFileManifestItemPathNormalization(t *testing.T) {
	d := digests.NewDigest("sha256", []byte{0x01})
	tests := []struct {
		input string
		want  string
	}{
		{"./file.bin", "file.bin:0:10"},
		{"dir/./file.bin", "dir/file.bin:0:10"},
		{"dir//file.bin", "dir/file.bin:0:10"},
	}
	for _, tt := range tests {
		item := NewShardedFileManifestItem(tt.input, 0, 10, d)
		if got := item.Name(); got != tt.want {
			t.Errorf("NewShardedFileManifestItem(%q, 0, 10).Name() = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func FuzzParseShardName(f *testing.F) {
	f.Add("file.bin:0:1024")
	f.Add("dir/file.bin:100:200")
	f.Add("path:with:colons:0:10")
	f.Add(":0:10")
	f.Add("file:0:")
	f.Add("")
	f.Add("no-colons")

	f.Fuzz(func(t *testing.T, name string) {
		_, _, _, _ = parseShardName(name)
	})
}
