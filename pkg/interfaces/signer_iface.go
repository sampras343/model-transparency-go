package interfaces

// Signer signs a payload and produces a Signature.
// Each implementation may manage key material differently.
type Signer interface {
	// Sign creates a signature over the provided payload.
	Sign(payload *Payload) (Signature, error)
}
