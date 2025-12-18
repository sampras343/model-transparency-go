package verify

import "context"

// Result represents the outcome of a verification operation.
type Result struct {
	Verified bool
	Message  string
}

// ModelVerifier performs complete model verification.
//
// This is a high-level interface that orchestrates the full verification workflow:
// 1. Read and verify signature
// 2. Hash model files
// 3. Compare manifests
//
// Unlike interfaces.SignatureVerifier which only handles cryptographic verification,
// ModelVerifier handles the complete end-to-end verification process.
type ModelVerifier interface {
	Verify(ctx context.Context) (Result, error)
}
