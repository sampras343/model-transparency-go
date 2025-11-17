package verify

import "context"

type Result struct {
    Verified bool
    // additional metadata required ??
}

type Verifier interface {
    Verify(ctx context.Context) (Result, error)
}
