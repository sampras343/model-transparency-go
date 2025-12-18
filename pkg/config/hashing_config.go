package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	hashengines "github.com/sigstore/model-signing/pkg/hashing/engines"
	hashio "github.com/sigstore/model-signing/pkg/hashing/engines/io"
	"github.com/sigstore/model-signing/pkg/manifest"
)

// Config holds configuration for hashing models.
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
}

// PathLike is a type alias for path-like strings.
type PathLike = string

// Common git-related paths to ignore
var gitRelatedPaths = []string{
	".git",
	".gitignore",
	".gitattributes",
	".github",
	".gitmodules",
}

// NewHashingConfig creates a new hashing configuration with defaults.
func NewHashingConfig() *HashingConfig {
	return &HashingConfig{
		serializationMethod: "files",
		hashAlgorithm:       "sha256",
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
func (c *HashingConfig) UseFileSerialization(hashAlgorithm string, allowSymlinks bool, ignorePaths []string) *HashingConfig {
	c.serializationMethod = "files"
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
func (c *HashingConfig) UseShardSerialization(hashAlgorithm string, shardSize int64, allowSymlinks bool, ignorePaths []string) *HashingConfig {
	c.serializationMethod = "shards"
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
// If ignoreGitPaths is true, common git-related paths are also ignored.
func (c *HashingConfig) SetIgnoredPaths(paths []string, ignoreGitPaths bool) *HashingConfig {
	c.ignoredPaths = paths
	c.ignoreGitPaths = ignoreGitPaths
	return c
}

// AddIgnoredPaths adds additional paths to the ignore list.
//
// The paths are interpreted relative to modelPath.
// Returns the config for method chaining (builder pattern).
func (c *HashingConfig) AddIgnoredPaths(modelPath string, paths []string) *HashingConfig {
	for _, p := range paths {
		// Make path absolute relative to model path if not already absolute
		var absPath string
		if filepath.IsAbs(p) {
			absPath = p
		} else {
			absPath = filepath.Join(modelPath, p)
		}
		c.ignoredPaths = append(c.ignoredPaths, absPath)
	}
	return c
}

// SetAllowSymlinks sets whether to follow symbolic links.
func (c *HashingConfig) SetAllowSymlinks(allow bool) *HashingConfig {
	c.allowSymlinks = allow
	return c
}

// SetChunkSize sets the chunk size for file reading.
func (c *HashingConfig) SetChunkSize(size int) *HashingConfig {
	c.chunkSize = size
	return c
}

// Hash hashes a model directory and returns a manifest.
//
// If filesToHash is nil, all files in the directory are hashed (subject to ignore rules).
// If filesToHash is provided, only those specific files are hashed.
func (c *HashingConfig) Hash(modelPath string, filesToHash []string) (*manifest.Manifest, error) {
	// Get absolute path for model
	absModelPath, err := filepath.Abs(modelPath)
	if err != nil {
		return nil, fmt.Errorf("failed to get absolute path for model: %w", err)
	}

	// Determine which files to hash
	var filePaths []string
	if filesToHash != nil {
		// Use provided list (convert to absolute paths)
		filePaths = make([]string, len(filesToHash))
		for i, f := range filesToHash {
			if filepath.IsAbs(f) {
				filePaths[i] = f
			} else {
				filePaths[i] = filepath.Join(absModelPath, f)
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
	case "files":
		items, err = c.hashFiles(absModelPath, filePaths)
	case "shards":
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
func (c *HashingConfig) walkDirectory(modelPath string) ([]string, error) {
	var files []string

	err := filepath.Walk(modelPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		// Skip directories
		if info.IsDir() {
			return nil
		}

		// Check if it's a symlink
		if info.Mode()&os.ModeSymlink != 0 {
			if !c.allowSymlinks {
				return nil // Skip symlinks if not allowed
			}
			// Resolve symlink and check if target exists
			target, err := filepath.EvalSymlinks(path)
			if err != nil {
				return fmt.Errorf("failed to resolve symlink %s: %w", path, err)
			}
			targetInfo, err := os.Stat(target)
			if err != nil {
				return fmt.Errorf("failed to stat symlink target %s: %w", target, err)
			}
			if targetInfo.IsDir() {
				return nil // Skip directory symlinks
			}
		}

		// Check if path should be ignored
		if c.shouldIgnorePath(path, modelPath) {
			if info.IsDir() {
				return filepath.SkipDir
			}
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
func (c *HashingConfig) shouldIgnorePath(path, modelPath string) bool {
	// Get relative path from model root
	relPath, err := filepath.Rel(modelPath, path)
	if err != nil {
		return false
	}

	// Check against ignored paths
	for _, ignoredPath := range c.ignoredPaths {
		// Handle both absolute and relative ignored paths
		var compareWith string
		if filepath.IsAbs(ignoredPath) {
			compareWith = path
		} else {
			compareWith = relPath
		}

		// Check for exact match or prefix match
		if compareWith == ignoredPath || strings.HasPrefix(compareWith, ignoredPath+string(filepath.Separator)) {
			return true
		}
	}

	// Check git-related paths if configured
	if c.ignoreGitPaths {
		for _, gitPath := range gitRelatedPaths {
			if relPath == gitPath || strings.HasPrefix(relPath, gitPath+string(filepath.Separator)) {
				return true
			}
		}
	}

	return false
}

// hashFiles hashes files using file-based serialization.
func (c *HashingConfig) hashFiles(modelPath string, filePaths []string) ([]manifest.ManifestItem, error) {
	items := make([]manifest.ManifestItem, 0, len(filePaths))

	for _, filePath := range filePaths {
		// Get relative path for manifest
		relPath, err := filepath.Rel(modelPath, filePath)
		if err != nil {
			return nil, fmt.Errorf("failed to get relative path for %s: %w", filePath, err)
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
func (c *HashingConfig) hashFilesWithShards(modelPath string, filePaths []string) ([]manifest.ManifestItem, error) {
	items := make([]manifest.ManifestItem, 0)

	for _, filePath := range filePaths {
		// Get relative path for manifest
		relPath, err := filepath.Rel(modelPath, filePath)
		if err != nil {
			return nil, fmt.Errorf("failed to get relative path for %s: %w", filePath, err)
		}

		// Get file size
		fileInfo, err := os.Stat(filePath)
		if err != nil {
			return nil, fmt.Errorf("failed to stat %s: %w", filePath, err)
		}
		fileSize := fileInfo.Size()

		// Calculate number of shards
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
func (c *HashingConfig) createFileHasher(filePath string) (hashio.FileHasher, error) {
	contentHasher, err := c.createContentHasher()
	if err != nil {
		return nil, err
	}

	return hashio.NewSimpleFileHasher(filePath, contentHasher, c.chunkSize, "")
}

// createShardedFileHasher creates a sharded file hasher.
func (c *HashingConfig) createShardedFileHasher(filePath string, start, end int64) (hashio.FileHasher, error) {
	contentHasher, err := c.createContentHasher()
	if err != nil {
		return nil, err
	}

	return hashio.NewShardedFileHasher(filePath, contentHasher, start, end, c.chunkSize, c.shardSize, "")
}

// createContentHasher creates a streaming hash engine based on the HashingConfigured algorithm.
func (c *HashingConfig) createContentHasher() (hashengines.StreamingHashEngine, error) {
	// Use the hash engine registry for creating engines
	return hashengines.Create(c.hashAlgorithm)
}

// GetSerializationType returns the serialization type configuration.
//
// This is used when creating manifests and signatures.
func (c *HashingConfig) GetSerializationType() manifest.SerializationType {
	switch c.serializationMethod {
	case "files":
		return manifest.NewFileSerialization(
			c.hashAlgorithm,
			c.allowSymlinks,
			c.ignoredPaths,
		)
	case "shards":
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
