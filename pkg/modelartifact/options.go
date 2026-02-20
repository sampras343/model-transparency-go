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

// Package modelartifact provides the primary API for canonicalizing ML models
// into deterministic manifests suitable for signing with sigstore-go.
//
// This package is the core of the model-signing library. It handles:
//   - Walking model directories and hashing files into a deterministic manifest
//   - Serializing manifests to in-toto JSON payloads for DSSE signing
//   - Deserializing verified payloads back into manifests for comparison
//   - Comparing actual vs. expected manifests to detect tampering
//
// Typical usage for signing:
//
//	m, err := modelartifact.Canonicalize("/path/to/model", modelartifact.Options{})
//	payload, err := modelartifact.MarshalPayload(m)
//	// Pass payload to sigstore-go's sign.Bundle() as DSSEData
//
// Typical usage for verification:
//
//	expectedManifest, err := modelartifact.UnmarshalPayload(verifiedPayload)
//	actualManifest, err := modelartifact.Canonicalize("/path/to/model", modelartifact.Options{})
//	err = modelartifact.Compare(actualManifest, expectedManifest)
package modelartifact

import (
	"github.com/sigstore/model-signing/pkg/logging"
)

// Options configures how a model is canonicalized.
type Options struct {
	// HashAlgorithm is the hash algorithm to use (default: "sha256").
	// Supported algorithms: "sha256", "blake2b".
	HashAlgorithm string

	// IgnorePaths is a list of paths to exclude from canonicalization.
	// Paths can be absolute or relative to the model root.
	IgnorePaths []string

	// IgnoreGitPaths automatically excludes .git, .gitignore, .gitattributes,
	// .github, and .gitmodules from canonicalization.
	IgnoreGitPaths bool

	// AllowSymlinks follows symbolic links instead of skipping them.
	AllowSymlinks bool

	// ShardSize enables shard-based serialization if > 0.
	// When 0 (default), file-based serialization is used where each file
	// is hashed as a single unit. When > 0, large files are split into
	// fixed-size shards and each shard is hashed separately.
	ShardSize int64

	// Logger is an optional logger for debug output.
	Logger logging.Logger
}
