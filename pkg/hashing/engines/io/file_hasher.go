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

package io

import (
	hashengines "github.com/sigstore/model-signing/pkg/hashing/engines"
)

// FileHasher is a marker interface for hash engines that hash files.
//
// It's intentionally just an alias of HashEngine for now, but it gives
// you a semantic distinction in APIs that specifically expect file-based
// hashing rather than arbitrary content hashing.
type FileHasher interface {
	hashengines.HashEngine
}

type FileHasherFactory func(path string) (FileHasher, error)

type ShardedFileHasherFactory func(path string, start, end int64) (FileHasher, error)
