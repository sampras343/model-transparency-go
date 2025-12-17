package verify

import "context"

// Result represents the outcome of a verification operation.
type Result struct {
	Verified bool
	Message  string
}

type Verifier interface {
    Verify(ctx context.Context) (Result, error)
}
