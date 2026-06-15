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

package config

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"unicode/utf8"

	hashengines "github.com/sigstore/model-signing/pkg/hashing/engines"
	hashio "github.com/sigstore/model-signing/pkg/hashing/engines/io"
	_ "github.com/sigstore/model-signing/pkg/hashing/engines/memory" // Register default hash engines (sha256, blake2b)
	"github.com/sigstore/model-signing/pkg/logging"
	"github.com/sigstore/model-signing/pkg/manifest"
	"github.com/sigstore/model-signing/pkg/utils"
)

// ErrSymlinkNotAllowed is returned when a symbolic link is encountered during
// file enumeration and allow_symlinks is false (the default per OMS spec §6.1.1).
var ErrSymlinkNotAllowed = errors.New("symbolic link encountered but allow_symlinks is false")

// ErrInvalidUTF8Path is returned when a file path contains byte sequences
// that are not valid UTF-8 (spec §6.1.2).
var ErrInvalidUTF8Path = errors.New("file path is not valid UTF-8")

// HashingConfig holds configuration for hashing models.
//
// It determines which files to hash, how to hash them, and which files to ignore.
type HashingConfig struct {
	// Serialization method ("files" or "shards")
	serializationMethod string

	// Hash algorithm (e.g., "sha256", "blake2b")
	hashAlgorithm string

	// Whether to allow symlinks
	allowSymlinks bool

	// Paths to ignore during hashing
	ignoredPaths []string

	// Whether to ignore git-related paths
	ignoreGitPaths bool

	// Shard size (only for shard serialization)
	shardSize int64

	// Chunk size for file reading (0 = read all at once)
	chunkSize int

	// Logger for warnings (e.g. symlink targets outside model root)
	logger logging.Logger
}

// PathLike is a type alias for path-like strings.
type PathLike = string

// gitRelatedPaths defines git-related paths excluded by default per spec §6.2.
var gitRelatedPaths = []string{
	".git",
	".gitignore",
	".gitattributes",
	".github",
}

// NewHashingConfig creates a new hashing configuration with defaults.
//
// Defaults: file serialization, sha256 hash, symlinks disabled,
// no ignored paths, 8KB chunk size.
//
// Returns a HashingConfig ready for customization via method chaining.
func NewHashingConfig() *HashingConfig {
	return &HashingConfig{
		serializationMethod: utils.SerializationMethodFiles,
		hashAlgorithm:       utils.DefaultHashAlgorithm,
		allowSymlinks:       false,
		ignoredPaths:        []string{},
		ignoreGitPaths:      false,
		shardSize:           0,
		chunkSize:           8192, // 8KB default chunk size
	}
}

// UseFileSerialization configures the hasher to use file-based serialization.
//
// In this mode, each file is hashed entirely as a single unit.
//
// Parameters:
//   - hashAlgorithm: Hash algorithm name (e.g., "sha256", "blake2b")
//   - allowSymlinks: Whether to follow and hash symbolic links
//   - ignorePaths: Paths to ignore during hashing
//
// Returns the HashingConfig for method chaining.
func (c *HashingConfig) UseFileSerialization(hashAlgorithm string, allowSymlinks bool, ignorePaths []string) *HashingConfig {
	c.serializationMethod = utils.SerializationMethodFiles
	c.hashAlgorithm = hashAlgorithm
	c.allowSymlinks = allowSymlinks
	if ignorePaths != nil {
		c.ignoredPaths = append(c.ignoredPaths, ignorePaths...)
	}
	return c
}

// UseShardSerialization configures the hasher to use shard-based serialization.
//
// In this mode, large files are split into fixed-size shards, and each shard
// is hashed separately.
//
// Parameters:
//   - hashAlgorithm: Hash algorithm name (e.g., "sha256", "blake2b")
//   - shardSize: Size of each shard in bytes
//   - allowSymlinks: Whether to follow and hash symbolic links
//   - ignorePaths: Paths to ignore during hashing
//
// Returns the HashingConfig for method chaining.
func (c *HashingConfig) UseShardSerialization(hashAlgorithm string, shardSize int64, allowSymlinks bool, ignorePaths []string) *HashingConfig {
	c.serializationMethod = utils.SerializationMethodShards
	c.hashAlgorithm = hashAlgorithm
	c.shardSize = shardSize
	c.allowSymlinks = allowSymlinks
	if ignorePaths != nil {
		c.ignoredPaths = append(c.ignoredPaths, ignorePaths...)
	}
	return c
}

// SetIgnoredPaths sets the paths to ignore during hashing.
//
// If ignoreGitPaths is true, common git-related paths are also ignored and
// stored in the manifest so verification can automatically apply them.
//
// Parameters:
//   - paths: List of paths to ignore (relative to model root)
//   - ignoreGitPaths: Whether to automatically ignore .git and related paths
//
// Returns the HashingConfig for method chaining.
func (c *HashingConfig) SetIgnoredPaths(paths []string, ignoreGitPaths bool) *HashingConfig {
	c.ignoredPaths = paths
	c.ignoreGitPaths = ignoreGitPaths

	// Add git-related paths to ignore list so they're stored in manifest
	if ignoreGitPaths {
		c.ignoredPaths = append(c.ignoredPaths, gitRelatedPaths...)
	}

	return c
}

// AddIgnoredPaths adds additional paths to the ignore list.
//
// Absolute paths are converted to relative paths using modelPath as
// the base. All paths are stored as forward-slash POSIX paths per
// spec §6.2.1 so they are portable across machines and OSes.
//
// Parameters:
//   - modelPath: Base path for resolving absolute paths to relative
//   - paths: Paths to add to the ignore list (can be absolute or relative)
//
// Returns the HashingConfig for method chaining.
func (c *HashingConfig) AddIgnoredPaths(modelPath string, paths []string) *HashingConfig {
	for _, p := range paths {
		var relPath string
		if filepath.IsAbs(p) {
			rel, err := filepath.Rel(modelPath, p)
			if err != nil {
				relPath = filepath.ToSlash(p)
			} else {
				relPath = filepath.ToSlash(rel)
			}
		} else {
			relPath = filepath.ToSlash(p)
		}
		c.ignoredPaths = append(c.ignoredPaths, relPath)
	}
	return c
}

// SetAllowSymlinks sets whether to follow symbolic links.
//
// Returns the HashingConfig for method chaining.
func (c *HashingConfig) SetAllowSymlinks(allow bool) *HashingConfig {
	c.allowSymlinks = allow
	return c
}

// SetChunkSize sets the chunk size for file reading.
//
// A size of 0 means files are read all at once. Non-zero values enable
// chunked reading for memory efficiency with large files.
//
// Returns the HashingConfig for method chaining.
func (c *HashingConfig) SetChunkSize(size int) *HashingConfig {
	c.chunkSize = size
	return c
}

// SetLogger sets the logger for warnings during file enumeration
// (e.g. symlink targets outside model root, symlink cycles).
func (c *HashingConfig) SetLogger(logger logging.Logger) *HashingConfig {
	c.logger = logger
	return c
}

// Hash hashes a model directory and returns a manifest.
//
// If filesToHash is nil, all files in the directory are hashed (subject to ignore rules).
// If filesToHash is provided, only those specific files are hashed.
//
// Parameters:
//   - modelPath: Path to the model directory to hash
//   - filesToHash: Optional list of specific files to hash (nil means all files)
//
// Returns a Manifest containing all hashed files and their digests.
func (c *HashingConfig) Hash(modelPath string, filesToHash []string) (*manifest.Manifest, error) {
	// Get absolute path for model
	absModelPath, err := filepath.Abs(modelPath)
	if err != nil {
		return nil, fmt.Errorf("failed to get absolute path for model: %w", err)
	}

	// Determine which files to hash
	var filePaths []string
	if filesToHash != nil {
		// Use provided list (convert to absolute paths and filter out ignored paths)
		for _, f := range filesToHash {
			var absPath string
			if filepath.IsAbs(f) {
				absPath = f
			} else {
				absPath = filepath.Join(absModelPath, f)
			}

			// Check if path should be ignored
			if !c.shouldIgnorePath(absPath, absModelPath) {
				filePaths = append(filePaths, absPath)
			}
		}
	} else {
		// Walk directory to find all files
		filePaths, err = c.walkDirectory(absModelPath)
		if err != nil {
			return nil, fmt.Errorf("failed to walk directory: %w", err)
		}
	}

	// Hash files based on serialization method
	var items []manifest.ManifestItem
	switch c.serializationMethod {
	case utils.SerializationMethodFiles:
		items, err = c.hashFiles(absModelPath, filePaths)
	case utils.SerializationMethodShards:
		items, err = c.hashFilesWithShards(absModelPath, filePaths)
	default:
		return nil, fmt.Errorf("unknown serialization method: %s", c.serializationMethod)
	}

	if err != nil {
		return nil, fmt.Errorf("failed to hash files: %w", err)
	}

	// Create manifest
	modelName := filepath.Base(absModelPath)
	serializationType := c.GetSerializationType()

	return manifest.NewManifest(modelName, items, serializationType), nil
}

// walkDirectory walks the model directory and returns all file paths to hash.
//
// Returns a list of absolute file paths that should be hashed, respecting
// ignore rules and symlink configuration.
func (c *HashingConfig) walkDirectory(modelPath string) ([]string, error) {
	absModelRoot, err := filepath.Abs(modelPath)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve model path: %w", err)
	}
	absModelRoot = filepath.Clean(absModelRoot) + string(filepath.Separator)

	var files []string

	err = filepath.WalkDir(modelPath, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		// Check if path should be ignored before other checks so we
		// can skip entire directory subtrees early via SkipDir.
		if c.shouldIgnorePath(path, modelPath) {
			if d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}

		if d.IsDir() {
			return nil
		}

		// DirEntry.Type() returns the file type bits without an extra syscall.
		if d.Type()&os.ModeSymlink != 0 {
			if !c.allowSymlinks {
				relPath, relErr := filepath.Rel(modelPath, path)
				if relErr != nil {
					relPath = path
				}
				return fmt.Errorf("%w: %s", ErrSymlinkNotAllowed, relPath)
			}
			target, err := filepath.EvalSymlinks(path)
			if err != nil {
				// EvalSymlinks fails on cycles (OMS spec §6.1.1)
				c.warnf("symlink cycle or broken link: %s: %v", path, err)
				return nil
			}
			if !strings.HasPrefix(filepath.Clean(target)+string(filepath.Separator), absModelRoot) {
				c.warnf("symlink target outside model root: %s -> %s", path, target)
			}
			targetInfo, err := os.Stat(target)
			if err != nil {
				return fmt.Errorf("failed to stat symlink target %s: %w", target, err)
			}
			if !targetInfo.Mode().IsRegular() {
				return nil
			}
			files = append(files, path)
			return nil
		}

		if !d.Type().IsRegular() {
			return nil
		}

		files = append(files, path)
		return nil
	})

	if err != nil {
		return nil, err
	}

	return files, nil
}

// shouldIgnorePath checks if a path should be ignored based on configuration.
//
// Returns true if the path matches any configured ignore patterns.
// Handles ignore paths that are:
// - Absolute paths (compared directly with the absolute file path)
// - Paths relative to modelPath (e.g., "subdir/file.txt")
// - Paths relative to CWD (e.g., "./model/file.txt" from CLI)
func (c *HashingConfig) shouldIgnorePath(path, modelPath string) bool {
	// Get relative path from model root
	relPath, err := filepath.Rel(modelPath, path)
	if err != nil {
		return false
	}

	// Check against ignored paths
	for _, ignoredPath := range c.ignoredPaths {
		if c.pathMatches(path, relPath, ignoredPath) {
			return true
		}
	}

	// Git-related paths are added to c.ignoredPaths when ignoreGitPaths is true,
	// so no separate checking is needed. This ensures they're stored in the manifest.
	return false
}

// pathMatches checks if a file path matches an ignored path pattern.
// It handles multiple path formats to support CLI usage patterns.
func (c *HashingConfig) pathMatches(absPath, relPath, ignoredPath string) bool {
	// Case 1: ignoredPath is absolute - compare with absolute path
	if filepath.IsAbs(ignoredPath) {
		if absPath == ignoredPath || strings.HasPrefix(absPath, ignoredPath+string(filepath.Separator)) {
			return true
		}
	}

	// Case 2: ignoredPath is relative to modelPath - compare with relPath
	// This handles patterns like "subdir/file.txt" or "file.txt"
	if relPath == ignoredPath || strings.HasPrefix(relPath, ignoredPath+string(filepath.Separator)) {
		return true
	}

	// Case 3: ignoredPath might be relative to CWD (e.g., "./model/file.txt" from CLI)
	// Convert to absolute and compare with absPath
	absIgnored, err := filepath.Abs(ignoredPath)
	if err == nil && absIgnored != ignoredPath { // Only if conversion changed something
		if absPath == absIgnored || strings.HasPrefix(absPath, absIgnored+string(filepath.Separator)) {
			return true
		}
	}

	return false
}

// hashFiles hashes files using file-based serialization.
//
// Returns a list of ManifestItems, one per file.
func (c *HashingConfig) hashFiles(modelPath string, filePaths []string) ([]manifest.ManifestItem, error) {
	items := make([]manifest.ManifestItem, 0, len(filePaths))

	for _, filePath := range filePaths {
		relPath, err := filepath.Rel(modelPath, filePath)
		if err != nil {
			return nil, fmt.Errorf("failed to get relative path for %s: %w", filePath, err)
		}

		if relPath == "." {
			relPath = filepath.Base(filePath)
		}

		if !utf8.ValidString(relPath) {
			return nil, fmt.Errorf("%w: %q", ErrInvalidUTF8Path, relPath)
		}

		if err := utils.ValidateManifestPath(relPath); err != nil {
			return nil, err
		}

		info, err := os.Stat(filePath)
		if err != nil {
			return nil, fmt.Errorf("failed to stat %s: %w", filePath, err)
		}
		if !info.Mode().IsRegular() {
			continue
		}

		// Create file hasher
		hasher, err := c.createFileHasher(filePath)
		if err != nil {
			return nil, fmt.Errorf("failed to create hasher for %s: %w", filePath, err)
		}

		// Compute digest
		digest, err := hasher.Compute()
		if err != nil {
			return nil, fmt.Errorf("failed to hash %s: %w", filePath, err)
		}

		// Create manifest item
		item := manifest.NewFileManifestItem(relPath, digest)
		items = append(items, item)
	}

	return items, nil
}

// hashFilesWithShards hashes files using shard-based serialization.
//
// Returns a list of ManifestItems, potentially multiple per file if
// files are larger than the configured shard size.
func (c *HashingConfig) hashFilesWithShards(modelPath string, filePaths []string) ([]manifest.ManifestItem, error) {
	items := make([]manifest.ManifestItem, 0)

	for _, filePath := range filePaths {
		relPath, err := filepath.Rel(modelPath, filePath)
		if err != nil {
			return nil, fmt.Errorf("failed to get relative path for %s: %w", filePath, err)
		}

		if relPath == "." {
			relPath = filepath.Base(filePath)
		}

		if !utf8.ValidString(relPath) {
			return nil, fmt.Errorf("%w: %q", ErrInvalidUTF8Path, relPath)
		}

		if err := utils.ValidateManifestPath(relPath); err != nil {
			return nil, err
		}

		fileInfo, err := os.Stat(filePath)
		if err != nil {
			return nil, fmt.Errorf("failed to stat %s: %w", filePath, err)
		}
		if !fileInfo.Mode().IsRegular() {
			continue
		}
		fileSize := fileInfo.Size()

		// Zero-byte files are omitted from resources (spec §6.3.2)
		if fileSize == 0 {
			continue
		}

		numShards := (fileSize + c.shardSize - 1) / c.shardSize

		// Hash each shard
		for i := int64(0); i < numShards; i++ {
			start := i * c.shardSize
			end := start + c.shardSize
			if end > fileSize {
				end = fileSize
			}

			// Create sharded file hasher
			hasher, err := c.createShardedFileHasher(filePath, start, end)
			if err != nil {
				return nil, fmt.Errorf("failed to create shard hasher for %s[%d:%d]: %w", filePath, start, end, err)
			}

			// Compute digest
			digest, err := hasher.Compute()
			if err != nil {
				return nil, fmt.Errorf("failed to hash shard %s[%d:%d]: %w", filePath, start, end, err)
			}

			// Create manifest item for shard
			item := manifest.NewShardedFileManifestItem(relPath, start, end, digest)
			items = append(items, item)
		}
	}

	return items, nil
}

// createFileHasher creates a file hasher based on the configured algorithm.
//
// Returns a FileHasher configured with the appropriate hash engine and chunk size.
func (c *HashingConfig) createFileHasher(filePath string) (hashio.FileHasher, error) {
	contentHasher, err := c.createContentHasher()
	if err != nil {
		return nil, err
	}

	return hashio.NewSimpleFileHasher(filePath, contentHasher, c.chunkSize, "")
}

// createShardedFileHasher creates a sharded file hasher.
//
// Parameters:
//   - filePath: Path to the file to hash
//   - start: Starting byte offset for this shard
//   - end: Ending byte offset for this shard
//
// Returns a FileHasher configured for the specified shard.
func (c *HashingConfig) createShardedFileHasher(filePath string, start, end int64) (hashio.FileHasher, error) {
	contentHasher, err := c.createContentHasher()
	if err != nil {
		return nil, err
	}

	return hashio.NewShardedFileHasher(filePath, contentHasher, start, end, c.chunkSize, c.shardSize, "")
}

// createContentHasher creates a streaming hash engine based on the configured algorithm.
//
// Returns a StreamingHashEngine for the configured hash algorithm.
func (c *HashingConfig) createContentHasher() (hashengines.StreamingHashEngine, error) {
	// Use the hash engine registry for creating engines
	return hashengines.Create(c.hashAlgorithm)
}

// GetSerializationType returns the serialization type configuration.
//
// This is used when creating manifests and signatures.
func (c *HashingConfig) GetSerializationType() manifest.SerializationType {
	switch c.serializationMethod {
	case utils.SerializationMethodFiles:
		return manifest.NewFileSerialization(
			c.hashAlgorithm,
			c.allowSymlinks,
			c.ignoredPaths,
		)
	case utils.SerializationMethodShards:
		return manifest.NewShardSerialization(
			c.hashAlgorithm,
			c.shardSize,
			c.allowSymlinks,
			c.ignoredPaths,
		)
	default:
		// Fallback to files
		return manifest.NewFileSerialization(
			c.hashAlgorithm,
			c.allowSymlinks,
			c.ignoredPaths,
		)
	}
}

func (c *HashingConfig) warnf(format string, args ...interface{}) {
	if c.logger != nil {
		c.logger.Warn(format, args...)
	}
}
