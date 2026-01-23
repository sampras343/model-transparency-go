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

// Package serialization provides interfaces and implementations for serializing
// machine learning models into manifest structures. It supports both file-level
// and shard-level serialization strategies with configurable hashing and ignore rules.
package serialization

import (
	"github.com/sigstore/model-signing/pkg/manifest"
)

// Serializer is the generic ML model format serializer.
//
// Implementations are responsible for walking the model path (file or directory),
// applying ignore rules, and producing a manifest.Manifest.
type Serializer interface {
	// Serialize serializes the model located at modelPath.
	//
	//   - modelPath: the path to the model (file or directory).
	//   - ignorePaths: paths to ignore during serialization. If an entry is a
	//     directory, all of its children are ignored.
	//
	// Implementations should call CheckFileOrDirectory on modelPath before
	// proceeding, and typically also respect ShouldIgnore for each visited path.
	Serialize(
		modelPath string,
		ignorePaths []string,
	) (manifest.Manifest, error)
}
