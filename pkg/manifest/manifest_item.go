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

// ManifestItem represents an individual object of a model stored as an item
// in a manifest. It pairs a canonical name with its digest.
//
//nolint:revive
type ManifestItem interface {
	Name() string
	Digest() digests.Digest
}

// FileManifestItem records a filename path identigier with its digest
// The path is currently stored as Canonical POSIX like form
type FileManifestItem struct {
	path   string
	digest digests.Digest
}

func NewFileManifestItem(path string, digest digests.Digest) *FileManifestItem {
	key := filepath.ToSlash((path))
	return &FileManifestItem{
		path:   key,
		digest: digest,
	}
}

// Name returns the canonical identifier for the file (its POSIX path).
func (item *FileManifestItem) Name() string {
	return item.path
}

// Digest returns the digest of the file.
func (item *FileManifestItem) Digest() digests.Digest {
	return item.digest
}

// ShardedFileManifestItem records a file shard together with its digest.
//
// The shard represents the byte range [start, end) of the file.
type ShardedFileManifestItem struct {
	path   string
	start  int64
	end    int64
	digest digests.Digest
}

// NewShardedFileManifestItem builds a manifest item pairing a file shard
// with its digest. The path is canonicalized to POSIX form.
func NewShardedFileManifestItem(path string, start, end int64, digest digests.Digest) *ShardedFileManifestItem {
	canonical := filepath.ToSlash(path)
	return &ShardedFileManifestItem{
		path:   canonical,
		start:  start,
		end:    end,
		digest: digest,
	}
}

// Name returns the canonical identifier for the shard: "path:start:end".
func (item *ShardedFileManifestItem) Name() string {
	return fmt.Sprintf("%s:%d:%d", item.path, item.start, item.end)
}

// Digest returns the digest of the file shard.
func (item *ShardedFileManifestItem) Digest() digests.Digest {
	return item.digest
}

// parseShardName parses a shard identifier of the form "path:start:end".
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
