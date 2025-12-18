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
	"fmt"

	"github.com/sigstore/model-signing/pkg/hashing/digests"
)

// SerializationType describes the serialization process that generated
// the manifest. It records enough parameters to recreate the manifest
// deterministically from a model.
//
// Parameters() returns a map that can be serialized (e.g. into JSON),
// and from which the same SerializationType can be reconstructed.
type SerializationType interface {
	// Method returns the serialization method identifier (e.g. "files", "shards").
	Method() string

	// Parameters returns the arguments of the serialization method as a map.
	// The returned map is safe to serialize; callers should treat it as
	// read-only and not retain it for mutation.
	Parameters() map[string]any

	// NewItem builds a ManifestItem of the correct type, parsing the given
	// name according to the serialization method.
	NewItem(name string, digest digests.Digest) (ManifestItem, error)
}

const (
	fileMethod  = "files"
	shardMethod = "shards"
)

// SerializationTypeFromArgs reconstructs a SerializationType from a map
// representation, the inverse of SerializationType.Parameters().
func SerializationTypeFromArgs(args map[string]any) (SerializationType, error) {
	rawMethod, ok := args["method"]
	if !ok {
		return nil, fmt.Errorf("serialization args missing `method` field")
	}

	method, ok := rawMethod.(string)
	if !ok {
		return nil, fmt.Errorf("serialization `method` field must be a string, got %T", rawMethod)
	}

	switch method {
	case fileMethod:
		return fileSerializationFromArgs(args)
	case shardMethod:
		return shardSerializationFromArgs(args)
	default:
		return nil, fmt.Errorf("unknown serialization type %q", method)
	}
}

// FileSerialization records the manifest serialization type for
// serialization by files.
type FileSerialization struct {
	hashType      string
	allowSymlinks bool
	ignorePaths   []string
}

// NewFileSerialization constructs a FileSerialization instance.
func NewFileSerialization(hashType string, allowSymlinks bool, ignorePaths []string) *FileSerialization {
	pathsCopy := make([]string, len(ignorePaths))
	copy(pathsCopy, ignorePaths)

	return &FileSerialization{
		hashType:      hashType,
		allowSymlinks: allowSymlinks,
		ignorePaths:   pathsCopy,
	}
}

// Method implements SerializationType.
func (s *FileSerialization) Method() string {
	return fileMethod
}

// Parameters implements SerializationType.
func (s *FileSerialization) Parameters() map[string]any {
	params := map[string]any{
		"method":         s.Method(),
		"hash_type":      s.hashType,
		"allow_symlinks": s.allowSymlinks,
	}
	if len(s.ignorePaths) > 0 {
		pathsCopy := make([]string, len(s.ignorePaths))
		copy(pathsCopy, s.ignorePaths)
		params["ignore_paths"] = pathsCopy
	}
	return params
}

// NewItem implements SerializationType.
// For file serialization, the name is treated as a POSIX path.
func (s *FileSerialization) NewItem(name string, digest digests.Digest) (ManifestItem, error) {
	return NewFileManifestItem(name, digest), nil
}

func fileSerializationFromArgs(args map[string]any) (*FileSerialization, error) {
	rawHashType, ok := args["hash_type"]
	if !ok {
		return nil, fmt.Errorf("file serialization args missing `hash_type`")
	}
	hashType, ok := rawHashType.(string)
	if !ok {
		return nil, fmt.Errorf("file serialization `hash_type` must be string, got %T", rawHashType)
	}

	rawAllowSymlinks, ok := args["allow_symlinks"]
	if !ok {
		return nil, fmt.Errorf("file serialization args missing `allow_symlinks`")
	}
	allowSymlinks, ok := rawAllowSymlinks.(bool)
	if !ok {
		return nil, fmt.Errorf("file serialization `allow_symlinks` must be bool, got %T", rawAllowSymlinks)
	}

	var ignorePaths []string
	if rawIgnore, ok := args["ignore_paths"]; ok {
		if slice, ok := rawIgnore.([]string); ok {
			ignorePaths = slice
		} else {
			// Allow []any of strings
			if ifaceSlice, ok := rawIgnore.([]any); ok {
				for _, v := range ifaceSlice {
					if s, ok := v.(string); ok {
						ignorePaths = append(ignorePaths, s)
					}
				}
			} else {
				return nil, fmt.Errorf("file serialization `ignore_paths` must be []string, got %T", rawIgnore)
			}
		}
	}

	return NewFileSerialization(hashType, allowSymlinks, ignorePaths), nil
}

// ShardSerialization records the manifest serialization type when
// files are split into shards of a fixed size.
type ShardSerialization struct {
	hashType      string
	shardSize     int64
	allowSymlinks bool
	ignorePaths   []string
}

// NewShardSerialization constructs a ShardSerialization instance.
func NewShardSerialization(hashType string, shardSize int64, allowSymlinks bool, ignorePaths []string) *ShardSerialization {
	pathsCopy := make([]string, len(ignorePaths))
	copy(pathsCopy, ignorePaths)

	return &ShardSerialization{
		hashType:      hashType,
		shardSize:     shardSize,
		allowSymlinks: allowSymlinks,
		ignorePaths:   pathsCopy,
	}
}

// Method implements SerializationType.
func (s *ShardSerialization) Method() string {
	return shardMethod
}

// Parameters implements SerializationType.
func (s *ShardSerialization) Parameters() map[string]any {
	params := map[string]any{
		"method":         s.Method(),
		"hash_type":      s.hashType,
		"shard_size":     s.shardSize,
		"allow_symlinks": s.allowSymlinks,
	}
	if len(s.ignorePaths) > 0 {
		pathsCopy := make([]string, len(s.ignorePaths))
		copy(pathsCopy, s.ignorePaths)
		params["ignore_paths"] = pathsCopy
	}
	return params
}

// NewItem implements SerializationType.
// For shard serialization, the name must be "path:start:end".
func (s *ShardSerialization) NewItem(name string, digest digests.Digest) (ManifestItem, error) {
	path, start, end, err := parseShardName(name)
	if err != nil {
		return nil, err
	}
	return NewShardedFileManifestItem(path, start, end, digest), nil
}

func shardSerializationFromArgs(args map[string]any) (*ShardSerialization, error) {
	rawHashType, ok := args["hash_type"]
	if !ok {
		return nil, fmt.Errorf("shard serialization args missing `hash_type`")
	}
	hashType, ok := rawHashType.(string)
	if !ok {
		return nil, fmt.Errorf("shard serialization `hash_type` must be string, got %T", rawHashType)
	}

	rawShardSize, ok := args["shard_size"]
	if !ok {
		return nil, fmt.Errorf("shard serialization args missing `shard_size`")
	}

	// type safety for shardSize
	var shardSize int64
	switch v := rawShardSize.(type) {
	case int:
		shardSize = int64(v)
	case int64:
		shardSize = v
	case float64:
		shardSize = int64(v)
	default:
		return nil, fmt.Errorf("shard serialization `shard_size` must be numeric, got %T", rawShardSize)
	}

	rawAllowSymlinks, ok := args["allow_symlinks"]
	if !ok {
		return nil, fmt.Errorf("shard serialization args missing `allow_symlinks`")
	}
	allowSymlinks, ok := rawAllowSymlinks.(bool)
	if !ok {
		return nil, fmt.Errorf("shard serialization `allow_symlinks` must be bool, got %T", rawAllowSymlinks)
	}

	var ignorePaths []string
	if rawIgnore, ok := args["ignore_paths"]; ok {
		if slice, ok := rawIgnore.([]string); ok {
			ignorePaths = slice
		} else if ifaceSlice, ok := rawIgnore.([]any); ok {
			for _, v := range ifaceSlice {
				if s, ok := v.(string); ok {
					ignorePaths = append(ignorePaths, s)
				}
			}
		} else {
			return nil, fmt.Errorf("shard serialization `ignore_paths` must be []string, got %T", rawIgnore)
		}
	}

	return NewShardSerialization(hashType, shardSize, allowSymlinks, ignorePaths), nil
}
