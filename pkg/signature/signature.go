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

// Package signature provides a Sigstore bundle-based signature implementation for model signing.
//
// This package wraps sigstore-go bundles to provide serialization and deserialization
// capabilities in the standard Sigstore JSON format. It implements the interfaces.Signature
// and interfaces.SignatureReader interfaces for compatibility with the model signing framework.
package signature

import (
	"fmt"
	"os"

	"github.com/sigstore/model-signing/pkg/interfaces"
	protobundle "github.com/sigstore/protobuf-specs/gen/pb-go/bundle/v1"
	"github.com/sigstore/sigstore-go/pkg/bundle"
	"google.golang.org/protobuf/encoding/protojson"
)

// Ensure Signature implements interfaces.Signature at compile time.
var _ interfaces.Signature = (*Signature)(nil)

// Ensure Signature implements interfaces.SignatureReader at compile time.
var _ interfaces.SignatureReader = (*Signature)(nil)

// Signature wraps a Sigstore bundle for model signing.
//
// It provides serialization and deserialization of Sigstore bundles
// in the standard JSON format.
type Signature struct {
	bundle *bundle.Bundle
}

// NewSignature creates a new Signature from a Sigstore bundle.
//
// The b parameter should be a valid sigstore-go Bundle containing signature data.
// Returns a new Signature instance wrapping the provided bundle.
func NewSignature(b *bundle.Bundle) *Signature {
	return &Signature{bundle: b}
}

// Bundle returns the underlying Sigstore bundle.
//
// Returns the wrapped sigstore-go Bundle instance.
func (s *Signature) Bundle() *bundle.Bundle {
	return s.bundle
}

// Write serializes the signature to a file at the given path.
//
// The signature is written in standard Sigstore JSON format with world-readable
// permissions (0644) as signatures are public artifacts.
//
// The path parameter specifies the file path where the signature will be written.
// Returns an error if marshaling or writing fails.
func (s *Signature) Write(path string) error {
	// Convert bundle to JSON
	jsonBytes, err := s.bundle.MarshalJSON()
	if err != nil {
		return fmt.Errorf("failed to marshal bundle to JSON: %w", err)
	}

	// Write to file with appropriate permissions
	// Signature files should be world-readable (0644) as they are public artifacts
	//nolint:gosec // G306: Signature files are public, 0644 is intentional
	if err := os.WriteFile(path, jsonBytes, 0644); err != nil {
		return fmt.Errorf("failed to write signature file: %w", err)
	}

	return nil
}

// Read deserializes a signature from a file at the given path.
//
// The file is expected to contain a Sigstore bundle in JSON format.
// Unknown fields in the JSON are discarded for forward compatibility.
//
// The path parameter specifies the file path to read the signature from.
// Returns a new Signature instance and an error if reading, unmarshaling, or bundle creation fails.
func (s *Signature) Read(path string) (interfaces.Signature, error) {
	// Read file
	//nolint:gosec
	jsonBytes, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read signature file: %w", err)
	}

	// Parse as protobuf bundle
	protoBundle := &protobundle.Bundle{}
	opts := protojson.UnmarshalOptions{
		// Allow unknown fields for compatibility
		DiscardUnknown: true,
	}

	if err := opts.Unmarshal(jsonBytes, protoBundle); err != nil {
		return nil, fmt.Errorf("failed to unmarshal bundle: %w", err)
	}

	// Convert to sigstore-go bundle
	b, err := bundle.NewBundle(protoBundle)
	if err != nil {
		return nil, fmt.Errorf("failed to create bundle: %w", err)
	}

	return NewSignature(b), nil
}
