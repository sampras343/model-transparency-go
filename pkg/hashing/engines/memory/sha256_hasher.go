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
	"crypto/sha256"
	"hash"

	hashengines "github.com/sigstore/model-signing/pkg/hashing/engines"
)

func init() {
	// Register SHA256 hash engine
	hashengines.MustRegister("sha256", func() (hashengines.StreamingHashEngine, error) {
		return NewSHA256Engine(nil)
	})
}

// SHA256Engine is a type alias for GenericHashEngine configured for SHA256.
//
// This maintains backward compatibility while using the generic implementation
// to eliminate code duplication.
type SHA256Engine = GenericHashEngine

// NewSHA256Engine constructs a new SHA256 engine.
//
// If initialData is non-nil, it will be written into the hash immediately.
func NewSHA256Engine(initialData []byte) (*SHA256Engine, error) {
	return NewGenericHashEngine(
		"sha256",
		sha256.Size,
		func() (hash.Hash, error) {
			return sha256.New(), nil
		},
		initialData,
	)
}
