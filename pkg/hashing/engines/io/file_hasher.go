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

// Package io provides hash engine interfaces for file-based hashing operations.
//
// This package defines specialized interfaces for hash engines that operate on
// files rather than in-memory data. It provides semantic distinction in APIs
// that specifically require file-based hashing.
package io

import (
	hashengines "github.com/sigstore/model-signing/pkg/hashing/engines"
)

// FileHasher is a marker interface for hash engines that operate on files.
//
// This interface is intentionally an alias of HashEngine, but provides semantic
// distinction in APIs that specifically require file-based hashing rather than
// arbitrary in-memory content hashing.
type FileHasher interface {
	hashengines.HashEngine
}

// FileHasherFactory is a function type that creates FileHasher instances for a given file path.
//
// The path parameter specifies the file to hash.
// Returns an error if the file cannot be accessed or the hasher cannot be created.
type FileHasherFactory func(path string) (FileHasher, error)

// ShardedFileHasherFactory is a function type that creates FileHasher instances for file shards.
//
// The path parameter specifies the file to hash.
// The start and end parameters define the byte range [start, end) within the file to hash.
// Returns an error if the file cannot be accessed, the range is invalid, or the hasher cannot be created.
type ShardedFileHasherFactory func(path string, start, end int64) (FileHasher, error)
