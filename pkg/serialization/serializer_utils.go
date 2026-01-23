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

package serialization

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// CheckFileOrDirectory validates that a path is a regular file or directory.
//
// This function performs several checks:
//   - Verifies the path exists and is accessible
//   - Ensures the path is either a regular file or directory (not a socket, pipe, or special file)
//   - Optionally validates symlink handling based on allowSymlinks parameter
//   - When allowSymlinks is false, rejects symlinks even if they point to valid targets
//   - When allowSymlinks is true, follows symlinks and validates their targets
//
// Parameters:
//   - path: the filesystem path to validate
//   - allowSymlinks: whether to permit symbolic links
//
// Returns nil if the path is valid, or an error describing why it is not.
// Possible errors include: path does not exist, permission denied, broken symlink,
// special file type, or symlink when not allowed.
func CheckFileOrDirectory(path string, allowSymlinks bool) error {
	// Use Lstat to detect symlinks without following them.
	info, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("cannot use %q as file or directory: %w", path, err)
	}

	mode := info.Mode()
	isSymlink := mode&os.ModeSymlink != 0

	if !allowSymlinks && isSymlink {
		return fmt.Errorf(
			"cannot use %q because it is a symlink; this behavior can be changed with allowSymlinks", path,
		)
	}

	// If symlinks are allowed, follow them to ensure target is a file or directory.
	if isSymlink && allowSymlinks {
		info, err = os.Stat(path)
		if err != nil {
			return fmt.Errorf(
				"cannot use %q as file or directory; it might be a broken symlink, missing, or permission denied: %w",
				path, err,
			)
		}
		mode = info.Mode()
	}

	if !mode.IsRegular() && !mode.IsDir() {
		return fmt.Errorf(
			"cannot use %q as file or directory; it might be a special file, missing, or there might be a permission issue",
			path,
		)
	}

	return nil
}

// ShouldIgnore determines whether a path should be excluded from serialization.
//
// A path is ignored if it matches or is a descendant of any entry in ignorePaths.
// When an ignorePaths entry is a directory, all of its children are also ignored.
// The matching is based on path relativity, similar to Python's pathlib.Path.is_relative_to().
//
// Both the target path and ignore paths are converted to absolute paths before comparison
// to ensure consistent matching regardless of how paths are specified.
//
// Parameters:
//   - path: the path to check for exclusion
//   - ignorePaths: list of paths that should be ignored
//
// Returns true if the path should be ignored, false otherwise.
// Returns false if ignorePaths is empty or if path conversion to absolute fails.
func ShouldIgnore(path string, ignorePaths []string) bool {
	if len(ignorePaths) == 0 {
		return false
	}

	absPath, err := filepath.Abs(path)
	if err != nil {
		return false
	}

	for _, base := range ignorePaths {
		if base == "" {
			continue
		}

		absBase, err := filepath.Abs(base)
		if err != nil {
			continue
		}

		rel, err := filepath.Rel(absBase, absPath)
		if err != nil {
			continue
		}

		if rel == "." {
			return true
		}
		if rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			return true
		}
	}

	return false
}
