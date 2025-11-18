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
	"fmt"
	"io"
	"os"

	"github.com/sigstore/model-signing/pkg/hashing/digests"
	hashengines "github.com/sigstore/model-signing/pkg/hashing/engines"
)

// SimpleFileHasher hashes an entire file by streaming it into an inner StreamingHashEngine.
// It reads the file exactly once and never loads the whole thing into
// memory (unless chunkSize == 0, in which case it tries to read it at once).
type SimpleFileHasher struct {
	filePath           string
	contentHasher      hashengines.StreamingHashEngine
	chunkSize          int
	digestNameOverride string
}

// NewSimpleFileHasher constructs a SimpleFileHasher.
//
//   - filePath: path to the file to hash
//   - contentHasher: the StreamingHashEngine used to hash file contents
//   - chunkSize: number of bytes to read per chunk; 0 means "read all at once"
//   - digestNameOverride: if non-empty, overrides the underlying engine's name
func NewSimpleFileHasher(
	filePath string,
	contentHasher hashengines.StreamingHashEngine,
	chunkSize int,
	digestNameOverride string,
) (*SimpleFileHasher, error) {
	if chunkSize < 0 {
		return nil, fmt.Errorf("chunk size must be non-negative, got %d", chunkSize)
	}

	if filePath == "" {
		return nil, fmt.Errorf("file path must be non-empty")
	}

	if contentHasher == nil {
		return nil, fmt.Errorf("content hasher must not be nil")
	}

	return &SimpleFileHasher{
		filePath:           filePath,
		contentHasher:      contentHasher,
		chunkSize:          chunkSize,
		digestNameOverride: digestNameOverride,
	}, nil
}

// SetFile changes the file that will be hashed on the next Compute call.
func (h *SimpleFileHasher) SetFile(filePath string) error {
	if filePath == "" {
		return fmt.Errorf("file path must be non-empty")
	}
	h.filePath = filePath
	return nil
}

// DigestName returns either the override or the underlying content hasher's name.
func (h *SimpleFileHasher) DigestName() string {
	if h.digestNameOverride != "" {
		return h.digestNameOverride
	}
	return h.contentHasher.DigestName()
}

// DigestSize is delegated to the inner content hasher.
func (h *SimpleFileHasher) DigestSize() int {
	return h.contentHasher.DigestSize()
}

// Compute hashes the entire file and returns a Digest.
//
// It streams the file into the inner StreamingHashEngine, then wraps
// the result with a potentially overridden algorithm name. Errors
// from I/O or the inner hasher are propagated.
func (h *SimpleFileHasher) Compute() (digests.Digest, error) {
	// Reset inner state before each computation.
	h.contentHasher.Reset(nil)

	f, err := os.Open(h.filePath)
	if err != nil {
		return digests.Digest{}, fmt.Errorf("open file %q: %w", h.filePath, err)
	}
	defer f.Close()

	if h.chunkSize == 0 {
		// Read everything in one go.
		data, err := io.ReadAll(f)
		if err != nil {
			return digests.Digest{}, fmt.Errorf("read file %q: %w", h.filePath, err)
		}
		h.contentHasher.Update(data)
	} else {
		// Stream in fixed-size chunks.
		buf := make([]byte, h.chunkSize)
		for {
			n, err := f.Read(buf)
			if n > 0 {
				h.contentHasher.Update(buf[:n])
			}
			if err != nil {
				if err == io.EOF {
					break
				}
				return digests.Digest{}, fmt.Errorf("read file %q: %w", h.filePath, err)
			}
		}
	}

	d, err := h.contentHasher.Compute()
	if err != nil {
		return digests.Digest{}, fmt.Errorf("compute digest: %w", err)
	}

	// Override algorithm name to match this engine's digest name.
	return digests.NewDigest(h.DigestName(), d.Value()), nil
}
