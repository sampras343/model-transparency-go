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

package verify

import (
	"fmt"
)

// ErrorType represents the category of verification error.
type ErrorType int

const (
	// ErrTypeUnknown indicates an unclassified error.
	ErrTypeUnknown ErrorType = iota

	// ErrTypeSignatureInvalid indicates the cryptographic signature is invalid.
	ErrTypeSignatureInvalid

	// ErrTypeManifestMismatch indicates the model doesn't match the signature.
	ErrTypeManifestMismatch

	// ErrTypeFileNotFound indicates a required file is missing.
	ErrTypeFileNotFound

	// ErrTypeInvalidFormat indicates an invalid signature or manifest format.
	ErrTypeInvalidFormat

	// ErrTypeConfiguration indicates a configuration error.
	ErrTypeConfiguration

	// ErrTypeIO indicates an I/O error (file read/write).
	ErrTypeIO
)

// String returns a human-readable name for the error type.
func (e ErrorType) String() string {
	switch e {
	case ErrTypeSignatureInvalid:
		return "InvalidSignature"
	case ErrTypeManifestMismatch:
		return "ManifestMismatch"
	case ErrTypeFileNotFound:
		return "FileNotFound"
	case ErrTypeInvalidFormat:
		return "InvalidFormat"
	case ErrTypeConfiguration:
		return "ConfigurationError"
	case ErrTypeIO:
		return "IOError"
	default:
		return "UnknownError"
	}
}

// VerificationError is a structured error type for verification failures.
//
// It provides detailed information about what went wrong, including:
// - The type of error (signature invalid, manifest mismatch, etc.)
// - The specific path or identifier involved (if applicable)
// - A human-readable message
// - The underlying cause (wrapped error)
//
// Example usage:
//
//	if err != nil {
//	    var verifyErr *VerificationError
//	    if errors.As(err, &verifyErr) {
//	        log.Printf("Verification failed: type=%s, path=%s, msg=%s",
//	                   verifyErr.Type, verifyErr.Path, verifyErr.Message)
//	    }
//	}
type VerificationError struct {
	// Type categorizes the error for programmatic handling.
	Type ErrorType

	// Path is the file path or identifier related to the error (optional).
	Path string

	// Message is a human-readable description of what went wrong.
	Message string

	// Cause is the underlying error that caused this verification error.
	Cause error
}

// Error implements the error interface.
func (e *VerificationError) Error() string {
	if e.Path != "" && e.Cause != nil {
		return fmt.Sprintf("%s: %s (path: %s): %v", e.Type, e.Message, e.Path, e.Cause)
	}
	if e.Path != "" {
		return fmt.Sprintf("%s: %s (path: %s)", e.Type, e.Message, e.Path)
	}
	if e.Cause != nil {
		return fmt.Sprintf("%s: %s: %v", e.Type, e.Message, e.Cause)
	}
	return fmt.Sprintf("%s: %s", e.Type, e.Message)
}

// Unwrap returns the underlying cause for error chain unwrapping.
func (e *VerificationError) Unwrap() error {
	return e.Cause
}

// NewVerificationError creates a new verification error.
func NewVerificationError(errType ErrorType, message string, cause error) *VerificationError {
	return &VerificationError{
		Type:    errType,
		Message: message,
		Cause:   cause,
	}
}

// NewVerificationErrorWithPath creates a new verification error with a path.
func NewVerificationErrorWithPath(errType ErrorType, path, message string, cause error) *VerificationError {
	return &VerificationError{
		Type:    errType,
		Path:    path,
		Message: message,
		Cause:   cause,
	}
}

// IsType checks if an error is a VerificationError of a specific type.
//
// Example:
//
//	if IsType(err, ErrTypeSignatureInvalid) {
//	    // Handle invalid signature
//	}
func IsType(err error, errType ErrorType) bool {
	var verifyErr *VerificationError
	if As(err, &verifyErr) {
		return verifyErr.Type == errType
	}
	return false
}

// As is a helper that wraps errors.As for VerificationError.
func As(err error, target **VerificationError) bool {
	if err == nil {
		return false
	}

	// Check if err is already a *VerificationError
	if ve, ok := err.(*VerificationError); ok {
		*target = ve
		return true
	}

	return false
}
