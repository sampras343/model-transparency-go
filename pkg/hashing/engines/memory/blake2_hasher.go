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

package memory

import (
	"hash"

	hashengines "github.com/sigstore/model-signing/pkg/hashing/engines"
	"golang.org/x/crypto/blake2b"
)

func init() {
	// Register BLAKE2b hash engine
	hashengines.MustRegister("blake2b", func() (hashengines.StreamingHashEngine, error) {
		return NewBLAKE2(nil)
	})
}

// BLAKE2 is a type alias for GenericHashEngine configured for BLAKE2b.
//
// This maintains backward compatibility while using the generic implementation
// to eliminate code duplication.
type BLAKE2 = GenericHashEngine

// NewBLAKE2 creates a new BLAKE2b-512 engine.
//
// If initialData is non-nil and non-empty, it is hashed immediately.
func NewBLAKE2(initialData []byte) (*BLAKE2, error) {
	return NewGenericHashEngine(
		"blake2b",
		blake2b.Size,
		func() (hash.Hash, error) {
			return blake2b.New512(nil) // 512-bit BLAKE2b digest with no key
		},
		initialData,
	)
}
