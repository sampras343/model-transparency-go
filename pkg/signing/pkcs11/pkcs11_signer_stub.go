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

//go:build !pkcs11

// This file provides stub types when the binary is built without -tags=pkcs11.
// The pkcs11-key and pkcs11-certificate commands will return a clear error.
// To enable PKCS#11 support, rebuild with: go build -tags=pkcs11

package pkcs11

import (
	"context"
	"fmt"

	"github.com/sigstore/model-signing/pkg/logging"
	"github.com/sigstore/model-signing/pkg/signing"
)

// Pkcs11SignerOptions configures a Pkcs11Signer instance.
//
//nolint:revive
type Pkcs11SignerOptions struct {
	ModelPath              string
	SignaturePath          string
	IgnorePaths            []string
	IgnoreGitPaths         bool
	AllowSymlinks          bool
	URI                    string
	ModulePaths            []string
	SigningCertificatePath string
	CertificateChain       []string
	Logger                 logging.Logger
}

// Pkcs11Signer implements ModelSigner using PKCS#11-based signing.
//
//nolint:revive
type Pkcs11Signer struct{}

// NewPkcs11Signer returns an error when built without -tags=pkcs11.
// PKCS#11 requires CGO and is only supported on Linux.
// Rebuild with: CGO_ENABLED=1 go build -tags=pkcs11
func NewPkcs11Signer(_ Pkcs11SignerOptions) (*Pkcs11Signer, error) {
	return nil, fmt.Errorf("PKCS#11 signing is not available: rebuild with -tags=pkcs11 (requires CGO, Linux only)")
}

// Sign is a stub that returns an error when built without -tags=pkcs11.
func (s *Pkcs11Signer) Sign(_ context.Context) (signing.Result, error) {
	return signing.Result{}, fmt.Errorf("PKCS#11 signing is not available: rebuild with -tags=pkcs11 (requires CGO, Linux only)")
}
