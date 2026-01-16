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
func NewSignature(b *bundle.Bundle) *Signature {
	return &Signature{bundle: b}
}

// Bundle returns the underlying Sigstore bundle.
func (s *Signature) Bundle() *bundle.Bundle {
	return s.bundle
}

// Write serializes the signature to a file at the given path.
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
