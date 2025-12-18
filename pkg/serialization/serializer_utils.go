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

// CheckFileOrDirectory checks that the given path is either a file or a directory.
// There is no support for sockets, pipes, or other special files.
// Furthermore, this will return an error if the path is a broken symlink,
// does not exist, or there are permission errors.
// If allowSymlinks is false (the default), symlinks are rejected even if they
// ultimately point to a regular file or directory.
func CheckFileOrDirectory(path string, allowSymlinks bool) error {
	// Use Lstat so we can detect symlinks without following them.
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

// ShouldIgnore determines if the provided path should be ignored during serialization.
//
// If an entry in ignorePaths is a directory, all of its children are also ignored.
// The check is done using path relativity, similar to pathlib.Path.is_relative_to().
func ShouldIgnore(path string, ignorePaths []string) bool {
	if len(ignorePaths) == 0 {
		return false
	}

	absPath, err := filepath.Abs(path)
	if err != nil {
		// If we can't resolve the path, err on the side of not ignoring it.
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
