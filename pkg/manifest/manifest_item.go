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
	"path/filepath"
	"strconv"
	"strings"

	"github.com/sigstore/model-signing/pkg/hashing/digests"
)

// ManifestItem represents an individual object of a model stored in a manifest.
//
// It pairs a canonical name with its cryptographic digest. Implementations
// include FileManifestItem for complete files and ShardedFileManifestItem
// for file shards.
//
//nolint:revive
type ManifestItem interface {
	// Name returns the canonical identifier for this item.
	Name() string

	// Digest returns the cryptographic hash of this item.
	Digest() digests.Digest
}

// FileManifestItem records a file path identifier with its digest.
//
// The path is stored in canonical POSIX-like form using forward slashes
// as path separators.
type FileManifestItem struct {
	path   string
	digest digests.Digest
}

// NewFileManifestItem creates a new file manifest item.
//
// The path parameter is automatically converted to POSIX form (forward slashes).
// Returns a FileManifestItem pairing the canonical path with its digest.
func NewFileManifestItem(path string, digest digests.Digest) *FileManifestItem {
	key := filepath.ToSlash((path))
	return &FileManifestItem{
		path:   key,
		digest: digest,
	}
}

// Name returns the canonical identifier for the file.
//
// Returns the file path in POSIX form (forward slash separators).
func (item *FileManifestItem) Name() string {
	return item.path
}

// Digest returns the cryptographic hash of the file.
func (item *FileManifestItem) Digest() digests.Digest {
	return item.digest
}

// ShardedFileManifestItem records a file shard together with its digest.
//
// A shard represents a contiguous byte range [start, end) within a file.
// This is useful for hashing large files in chunks rather than as a whole.
type ShardedFileManifestItem struct {
	path   string
	start  int64
	end    int64
	digest digests.Digest
}

// NewShardedFileManifestItem builds a manifest item for a file shard.
//
// The path parameter is automatically converted to POSIX form. The start and
// end parameters define the byte range [start, end) within the file.
// Returns a ShardedFileManifestItem pairing the shard with its digest.
func NewShardedFileManifestItem(path string, start, end int64, digest digests.Digest) *ShardedFileManifestItem {
	canonical := filepath.ToSlash(path)
	return &ShardedFileManifestItem{
		path:   canonical,
		start:  start,
		end:    end,
		digest: digest,
	}
}

// Name returns the canonical identifier for the shard.
//
// Returns a string in the format "path:start:end" where path is in POSIX form.
func (item *ShardedFileManifestItem) Name() string {
	return fmt.Sprintf("%s:%d:%d", item.path, item.start, item.end)
}

// Digest returns the cryptographic hash of the file shard.
func (item *ShardedFileManifestItem) Digest() digests.Digest {
	return item.digest
}

// parseShardName parses a shard identifier of the form "path:start:end".
//
// Returns the path, start offset, end offset, and an error if the format is
// invalid or the numeric values cannot be parsed.
func parseShardName(name string) (path string, start, end int64, err error) {
	parts := strings.Split(name, ":")
	if len(parts) != 3 {
		err = fmt.Errorf("invalid resource name: expected 3 components separated by `:`, got %q", name)
		return
	}

	path = parts[0]

	start, err = strconv.ParseInt(parts[1], 10, 64)
	if err != nil {
		err = fmt.Errorf("invalid shard start %q: %w", parts[1], err)
		return
	}

	end, err = strconv.ParseInt(parts[2], 10, 64)
	if err != nil {
		err = fmt.Errorf("invalid shard end %q: %w", parts[2], err)
		return
	}

	return
}
