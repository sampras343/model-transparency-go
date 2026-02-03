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

package pkcs11

import (
	"fmt"
	"os"

	bundle "github.com/sigstore/protobuf-specs/gen/pb-go/bundle/v1"
	"google.golang.org/protobuf/encoding/protojson"
)

// SignatureBundle wraps a Sigstore bundle as a signature.
type SignatureBundle struct {
	bundle *bundle.Bundle
}

// Write serializes the signature bundle to a file.
func (s *SignatureBundle) Write(path string) error {
	// Marshal bundle to JSON
	opts := protojson.MarshalOptions{
		Multiline:       true,
		Indent:          "  ",
		UseProtoNames:   true,
		EmitUnpopulated: false,
	}

	data, err := opts.Marshal(s.bundle)
	if err != nil {
		return fmt.Errorf("failed to marshal bundle: %w", err)
	}

	// Write to file
	if err := os.WriteFile(path, data, 0644); err != nil {
		return fmt.Errorf("failed to write signature file: %w", err)
	}

	return nil
}

// Bundle returns the underlying Sigstore bundle.
func (s *SignatureBundle) Bundle() *bundle.Bundle {
	return s.bundle
}
