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
