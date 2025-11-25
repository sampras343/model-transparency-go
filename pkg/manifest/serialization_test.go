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
	"reflect"
	"testing"

	"github.com/sigstore/model-signing/pkg/hashing/digests"
)

func TestFileSerializationParametersAndNewItem(t *testing.T) {
	ignore := []string{"ignore/this", "and/that"}
	s := NewFileSerialization("sha256", true, ignore)

	params := s.Parameters()
	if got := params["method"]; got != fileMethod {
		t.Fatalf("method = %v, want %v", got, fileMethod)
	}
	if got := params["hash_type"]; got != "sha256" {
		t.Fatalf("hash_type = %v, want %v", got, "sha256")
	}
	if got := params["allow_symlinks"]; got != true {
		t.Fatalf("allow_symlinks = %v, want %v", got, true)
	}
	gotIgnore, ok := params["ignore_paths"].([]string)
	if !ok {
		t.Fatalf("ignore_paths type = %T, want []string", params["ignore_paths"])
	}
	if !reflect.DeepEqual(gotIgnore, ignore) {
		t.Fatalf("ignore_paths = %v, want %v", gotIgnore, ignore)
	}

	d := digests.NewDigest("sha256", []byte{0x01})
	item, err := s.NewItem("path/to/file", d)
	if err != nil {
		t.Fatalf("NewItem unexpected error: %v", err)
	}

	if item.Name() != "path/to/file" {
		t.Fatalf("item.Name() = %q, want %q", item.Name(), "path/to/file")
	}
	if !reflect.DeepEqual(item.Digest().Value(), d.Value()) {
		t.Fatalf("item.Digest() != d")
	}
}

func TestFileSerializationFromArgsRoundTrip(t *testing.T) {
	args := map[string]any{
		"method":         fileMethod,
		"hash_type":      "sha256",
		"allow_symlinks": false,
		"ignore_paths":   []string{"foo", "bar"},
	}

	s, err := SerializationTypeFromArgs(args)
	if err != nil {
		t.Fatalf("SerializationTypeFromArgs error: %v", err)
	}

	fileSer, ok := s.(*FileSerialization)
	if !ok {
		t.Fatalf("SerializationTypeFromArgs returned %T, want *FileSerialization", s)
	}

	params := fileSer.Parameters()
	if params["hash_type"] != "sha256" {
		t.Errorf("hash_type = %v, want %v", params["hash_type"], "sha256")
	}
	if params["allow_symlinks"] != false {
		t.Errorf("allow_symlinks = %v, want %v", params["allow_symlinks"], false)
	}
}

func TestShardSerializationParametersAndNewItem(t *testing.T) {
	ignore := []string{"ignore/this", "and/that"}
	s := NewShardSerialization("sha256-sharded-1024", 1024, false, ignore)

	params := s.Parameters()
	if got := params["method"]; got != shardMethod {
		t.Fatalf("method = %v, want %v", got, shardMethod)
	}
	if got := params["hash_type"]; got != "sha256-sharded-1024" {
		t.Fatalf("hash_type = %v, want %v", got, "sha256-sharded-1024")
	}
	if got := params["shard_size"]; got != int64(1024) {
		t.Fatalf("shard_size = %v, want %v", got, int64(1024))
	}
	if got := params["allow_symlinks"]; got != false {
		t.Fatalf("allow_symlinks = %v, want %v", got, false)
	}
	gotIgnore, ok := params["ignore_paths"].([]string)
	if !ok {
		t.Fatalf("ignore_paths type = %T, want []string", params["ignore_paths"])
	}
	if !reflect.DeepEqual(gotIgnore, ignore) {
		t.Fatalf("ignore_paths = %v, want %v", gotIgnore, ignore)
	}

	d := digests.NewDigest("sha256-sharded-1024", []byte{0x0A})
	item, err := s.NewItem("file.bin:0:1024", d)
	if err != nil {
		t.Fatalf("NewItem unexpected error: %v", err)
	}

	if item.Name() != "file.bin:0:1024" {
		t.Fatalf("item.Name() = %q, want %q", item.Name(), "file.bin:0:1024")
	}
}

func TestShardSerializationFromArgsRoundTrip(t *testing.T) {
	args := map[string]any{
		"method":         shardMethod,
		"hash_type":      "sha256-sharded-1024",
		"shard_size":     2048, // int is fine
		"allow_symlinks": true,
		"ignore_paths":   []string{"foo"},
	}

	s, err := SerializationTypeFromArgs(args)
	if err != nil {
		t.Fatalf("SerializationTypeFromArgs error: %v", err)
	}

	shardSer, ok := s.(*ShardSerialization)
	if !ok {
		t.Fatalf("SerializationTypeFromArgs returned %T, want *ShardSerialization", s)
	}

	params := shardSer.Parameters()
	if params["hash_type"] != "sha256-sharded-1024" {
		t.Errorf("hash_type = %v, want %v", params["hash_type"], "sha256-sharded-1024")
	}
	if params["shard_size"] != int64(2048) {
		t.Errorf("shard_size = %v, want %v", params["shard_size"], int64(2048))
	}
	if params["allow_symlinks"] != true {
		t.Errorf("allow_symlinks = %v, want %v", params["allow_symlinks"], true)
	}
}

func TestSerializationTypeFromArgsUnknownMethod(t *testing.T) {
	args := map[string]any{
		"method": "unknown",
	}

	if _, err := SerializationTypeFromArgs(args); err == nil {
		t.Fatalf("SerializationTypeFromArgs with unknown method = nil error, want non-nil")
	}
}

func TestSerializationParametersDefensiveCopy(t *testing.T) {
	s := NewFileSerialization("sha256", false, []string{"ignore/me"})
	params := s.Parameters()

	// Mutate returned map and inner slice
	params["hash_type"] = "tampered"
	if paths, ok := params["ignore_paths"].([]string); ok && len(paths) > 0 {
		paths[0] = "tampered"
	}

	// Get a fresh copy
	params2 := s.Parameters()
	if params2["hash_type"] != "sha256" {
		t.Fatalf("underlying hash_type mutated via returned map, got %v", params2["hash_type"])
	}

	if paths2, ok := params2["ignore_paths"].([]string); ok && len(paths2) > 0 {
		if paths2[0] != "ignore/me" {
			t.Fatalf("underlying ignore_paths mutated via returned map, got %v", paths2)
		}
	}
}
