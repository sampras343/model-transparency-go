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
	"fmt"

	"github.com/sigstore/model-signing/pkg/hashing/digests"
)

// ComputeRootDigest computes a SHA256 hash over a sequence of digests.
//
// This is used to create a single "root" digest that represents all the
// individual digests in a manifest. The root digest is computed by:
// 1. Creating a SHA256 hasher
// 2. Feeding each digest's raw bytes (in order) into the hasher
// 3. Computing the final SHA256 hash
//
// This function eliminates code duplication between payload creation
// and manifest verification where the same pattern is used.
//
// Example:
//
//	digests := []digests.Digest{digest1, digest2, digest3}
//	rootDigest, err := memory.ComputeRootDigest(digests)
func ComputeRootDigest(digestList []digests.Digest) (digests.Digest, error) {
	hasher, err := NewSHA256Engine(nil)
	if err != nil {
		return digests.Digest{}, fmt.Errorf("failed to create SHA256 hasher: %w", err)
	}

	// Update hasher with each digest's raw bytes
	for _, d := range digestList {
		hasher.Update(d.Value())
	}

	// Compute the root digest
	rootDigest, err := hasher.Compute()
	if err != nil {
		return digests.Digest{}, fmt.Errorf("failed to compute root digest: %w", err)
	}

	return rootDigest, nil
}
