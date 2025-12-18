package interfaces

// Signature represents a cryptographic signature over a model.
//
// Implementations wrap different signature formats (e.g., Sigstore bundles).
type Signature interface {
	// Write serializes the signature to the given path.
	Write(path string) error
}

// SignatureReader reads signatures from disk.
//
// This is separate from the Signature interface because reading is a factory
// operation (creates new instances), while Write is an instance method.
type SignatureReader interface {
	// Read deserializes a signature from the given path.
	// Returns a concrete implementation of Signature.
	Read(path string) (Signature, error)
}
