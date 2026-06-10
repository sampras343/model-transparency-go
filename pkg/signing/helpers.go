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

package signing

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/sigstore/model-signing/pkg/logging"
	"github.com/sigstore/model-signing/pkg/manifest"
	"github.com/sigstore/model-signing/pkg/modelartifact"
	protobundle "github.com/sigstore/protobuf-specs/gen/pb-go/bundle/v1"
	"github.com/sigstore/sigstore-go/pkg/bundle"
	sigstoresign "github.com/sigstore/sigstore-go/pkg/sign"
)

// WriteBundle writes a protobuf bundle to disk in sigstore JSON format.
//
// The bundle is first validated by converting it to a sigstore-go Bundle,
// then serialized to JSON with world-readable permissions (0644) as
// signature bundles are public artifacts.
func WriteBundle(protoBundle *protobundle.Bundle, path string) error {
	bndl, err := bundle.NewBundle(protoBundle)
	if err != nil {
		return fmt.Errorf("failed to create bundle: %w", err)
	}

	jsonBytes, err := bndl.MarshalJSON()
	if err != nil {
		return fmt.Errorf("failed to marshal bundle to JSON: %w", err)
	}

	// Signature files should be world-readable (0644) as they are public artifacts
	//nolint:gosec // G306: Signature files are public, 0644 is intentional
	if err := os.WriteFile(path, jsonBytes, 0644); err != nil {
		return fmt.Errorf("failed to write signature file: %w", err)
	}

	return nil
}

// ApplyTSA configures timestamp authority options on the bundle if a TSA URL is provided.
func ApplyTSA(bundleOpts *sigstoresign.BundleOptions, tsaURL string, logger logging.Logger) {
	if tsaURL != "" {
		logger.Debug("  Using RFC 3161 Timestamp Authority: %s", tsaURL)
		bundleOpts.TimestampAuthorities = []*sigstoresign.TimestampAuthority{
			sigstoresign.NewTimestampAuthority(&sigstoresign.TimestampAuthorityOptions{URL: tsaURL}),
		}
	}
}

// PreparePayload canonicalizes a model and marshals the manifest into an in-toto
// payload. This is the common first two steps of all signing flows:
// 1. Walk the model directory/OCI manifest to produce a deterministic Manifest
// 2. Marshal the Manifest into an in-toto JSON statement
//
// The signaturePath is automatically appended to the ignore list so the
// signature file itself is never included in the manifest.
func PreparePayload(modelPath, signaturePath string, opts modelartifact.Options, logger logging.Logger) (*manifest.Manifest, []byte, error) {
	// Step 1: Canonicalize the model
	logger.Debugln("\nStep 1: Canonicalizing model...")
	ignorePaths := append([]string{}, opts.IgnorePaths...)
	if relSig, err := filepath.Rel(modelPath, signaturePath); err == nil && !strings.HasPrefix(relSig, "..") {
		ignorePaths = append(ignorePaths, filepath.ToSlash(relSig))
	}
	canonOpts := opts
	canonOpts.IgnorePaths = ignorePaths
	canonOpts.Logger = logger
	m, err := modelartifact.Canonicalize(modelPath, canonOpts)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to canonicalize model: %w", err)
	}
	logger.Debug("  Hashed %d files", len(m.ResourceDescriptors()))

	// Step 2: Marshal payload
	logger.Debugln("\nStep 2: Creating signing payload...")
	payload, err := modelartifact.MarshalPayload(m)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create payload: %w", err)
	}

	return m, payload, nil
}
