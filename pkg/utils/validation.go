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

package utils

import (
	"fmt"
	"os"
)

// PathType represents the type of path to validate.
type PathType int

const (
	// PathTypeFile expects a regular file.
	PathTypeFile PathType = iota
	// PathTypeFolder expects a directory.
	PathTypeFolder
	// PathTypeAny accepts either file or directory.
	PathTypeAny
)

// PathValidator provides path validation utilities.
type PathValidator struct {
	fieldName string
	path      string
	pathType  PathType
}

// NewPathValidator creates a new path validator with the specified field name, path, and expected type.
// Returns a configured PathValidator ready to perform validation.
func NewPathValidator(fieldName, path string, pathType PathType) *PathValidator {
	return &PathValidator{
		fieldName: fieldName,
		path:      path,
		pathType:  pathType,
	}
}

// Validate performs the path validation.
// Checks that the path is not empty, exists, and matches the expected type (file, folder, or either).
// Returns nil if validation succeeds, or a descriptive error if validation fails.
func (v *PathValidator) Validate() error {
	if v.path == "" {
		return fmt.Errorf("%s is required", v.fieldName)
	}

	info, err := os.Stat(v.path)
	if err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("%s %q does not exist", v.fieldName, v.path)
		}
		return fmt.Errorf("checking %s %q: %w", v.fieldName, v.path, err)
	}

	switch v.pathType {
	case PathTypeFile:
		if info.IsDir() {
			return fmt.Errorf("%s %q is a directory, expected file", v.fieldName, v.path)
		}
	case PathTypeFolder:
		if !info.IsDir() {
			return fmt.Errorf("%s %q is a file, expected directory", v.fieldName, v.path)
		}
	case PathTypeAny:
		// Accept both files and directories
	}

	return nil
}

// ValidateMultiple validates multiple paths of the same type.
// Empty paths in the slice are rejected. If any path fails validation, the first error is returned.
// Returns nil if all paths are valid, or an error describing the first validation failure.
func ValidateMultiple(fieldName string, paths []string, pathType PathType) error {
	for i, path := range paths {
		if path == "" {
			return fmt.Errorf("%s contains empty path at index %d", fieldName, i)
		}
		if err := NewPathValidator(fmt.Sprintf("%s[%d]", fieldName, i), path, pathType).Validate(); err != nil {
			return err
		}
	}
	return nil
}

// ValidateFileExists validates that a path exists and is a file.
// Returns nil if the path is a valid file, or an error if the path is empty, does not exist, or is a directory.
func ValidateFileExists(fieldName, path string) error {
	return NewPathValidator(fieldName, path, PathTypeFile).Validate()
}

// ValidateFolderExists validates that a path exists and is a directory.
// Returns nil if the path is a valid directory, or an error if the path is empty, does not exist, or is a file.
func ValidateFolderExists(fieldName, path string) error {
	return NewPathValidator(fieldName, path, PathTypeFolder).Validate()
}

// ValidatePathExists validates that a path exists (file or directory).
// Returns nil if the path exists, or an error if the path is empty or does not exist.
func ValidatePathExists(fieldName, path string) error {
	return NewPathValidator(fieldName, path, PathTypeAny).Validate()
}

// ValidateOptionalFile validates a file path only if it's not empty.
// Useful for optional configuration files.
// Returns nil if the path is empty or is a valid file, or an error if the path does not exist or is a directory.
func ValidateOptionalFile(fieldName, path string) error {
	if path == "" {
		return nil
	}
	return ValidateFileExists(fieldName, path)
}

// ValidateOptionalFolder validates a folder path only if it's not empty.
// Useful for optional directories.
// Returns nil if the path is empty or is a valid directory, or an error if the path does not exist or is a file.
func ValidateOptionalFolder(fieldName, path string) error {
	if path == "" {
		return nil
	}
	return ValidateFolderExists(fieldName, path)
}
