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

package verify

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"

	"github.com/sigstore/model-signing/pkg/logging"
	"github.com/sigstore/model-signing/pkg/modelartifact"
	"github.com/sigstore/sigstore-go/pkg/bundle"
)

// LoadBundle reads a sigstore bundle from a JSON file on disk.
//
// Applies backward-compatible transforms for older Python-produced signatures
// before parsing via sigstore-go. This handles:
//   - Old publicKey format with rawBytes/keyDetails (v0.3.1-v1.0.1): stripped
//   - Missing tlogEntries (v0.2.0-v1.0.1): added as empty array
//   - x509CertificateChain in v0.3 bundles: converted to singular certificate
func LoadBundle(path string) (*bundle.Bundle, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read bundle file %s: %w", path, err)
	}
	return loadBundleWithCompat(data)
}

// CompareModelWithBundle extracts the expected manifest from a verified
// DSSE payload, re-canonicalizes the model, and compares the two manifests.
//
// The verifiedPayload should be the raw in-toto JSON bytes extracted from
// the DSSE envelope after cryptographic verification by sigstore-go.
//
// If ignoreUnsignedFiles is true, extra files in the model that are not
// in the signed manifest are ignored (only missing files and mismatches
// are considered errors).
func CompareModelWithBundle(verifiedPayload []byte, modelPath string, opts modelartifact.Options, ignoreUnsignedFiles bool) error {
	// Step 1: Unmarshal the verified payload into an expected manifest
	expectedManifest, err := modelartifact.UnmarshalPayload(verifiedPayload)
	if err != nil {
		return fmt.Errorf("failed to extract manifest from payload: %w", err)
	}

	// Step 2: Re-canonicalize the model to get the actual manifest
	actualManifest, err := modelartifact.Canonicalize(modelPath, opts)
	if err != nil {
		return fmt.Errorf("failed to canonicalize model: %w", err)
	}

	// Step 3: Compare manifests
	if ignoreUnsignedFiles {
		return modelartifact.CompareIgnoringExtra(actualManifest, expectedManifest)
	}

	return modelartifact.Compare(actualManifest, expectedManifest)
}

// ExtractAndCompareModel extracts the DSSE payload from a bundle and compares
// it against the re-canonicalized model. This is the common final step of all
// verification flows after cryptographic signature verification succeeds.
//
// The signaturePath is automatically appended to the ignore list so the
// signature file itself is never included in the re-canonicalized manifest.
func ExtractAndCompareModel(bndl *bundle.Bundle, modelPath, signaturePath string, opts modelartifact.Options, ignoreUnsignedFiles bool, logger logging.Logger) error {
	logger.Debugln("\nComparing model with signed manifest...")

	dsseEnvelope := bndl.GetDsseEnvelope()
	if dsseEnvelope == nil {
		return fmt.Errorf("bundle does not contain a DSSE envelope")
	}
	payloadBytes := dsseEnvelope.Payload

	ignorePaths := append(append([]string{}, opts.IgnorePaths...), signaturePath)
	compareOpts := modelartifact.Options{
		IgnorePaths:    ignorePaths,
		IgnoreGitPaths: opts.IgnoreGitPaths,
		AllowSymlinks:  opts.AllowSymlinks,
		Logger:         logger,
	}
	return CompareModelWithBundle(payloadBytes, modelPath, compareOpts, ignoreUnsignedFiles)
}

// loadBundleWithCompat applies backward-compatible transforms to bundle JSON
// before parsing via sigstore-go. The JSON dict is cleaned up before
// protobuf parsing.
func loadBundleWithCompat(data []byte) (*bundle.Bundle, error) {
	var raw map[string]interface{}
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("failed to parse bundle JSON: %w", err)
	}

	applyBundleCompat(raw)

	cleanData, err := json.Marshal(raw)
	if err != nil {
		return nil, fmt.Errorf("failed to re-marshal bundle JSON: %w", err)
	}

	bndl := &bundle.Bundle{}
	if err := bndl.UnmarshalJSON(cleanData); err != nil {
		return nil, fmt.Errorf("failed to parse bundle: %w", err)
	}
	return bndl, nil
}

// ExtractBundleCertChain reads the raw bundle JSON from a file and extracts
// any additional certificates from x509CertificateChain beyond the first
// (signing) certificate. These are typically intermediate CA certificates
// that old Python-produced bundles embedded in the chain.
//
// Returns nil (not an error) if the bundle has no x509CertificateChain or
// only contains the signing certificate. This allows the cert verifier to
// add these intermediate certs to its trust pool for chain validation.
func ExtractBundleCertChain(path string) ([]*x509.Certificate, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read bundle file %s: %w", path, err)
	}
	return extractCertChainFromJSON(data)
}

// extractCertChainFromJSON extracts intermediate certificates from raw
// bundle JSON. Returns certificates beyond the first (signing) cert in
// the x509CertificateChain, if present.
func extractCertChainFromJSON(data []byte) ([]*x509.Certificate, error) {
	var raw map[string]interface{}
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, nil //nolint:nilerr // Not a cert chain bundle, skip
	}

	vm, ok := raw["verificationMaterial"].(map[string]interface{})
	if !ok {
		return nil, nil
	}

	certChain, ok := vm["x509CertificateChain"].(map[string]interface{})
	if !ok {
		return nil, nil
	}

	certs, ok := certChain["certificates"].([]interface{})
	if !ok || len(certs) <= 1 {
		return nil, nil
	}

	// Skip the first cert (signing cert) — extract remaining as intermediates
	var intermediateCerts []*x509.Certificate
	for i := 1; i < len(certs); i++ {
		certMap, ok := certs[i].(map[string]interface{})
		if !ok {
			continue
		}
		rawBytesB64, ok := certMap["rawBytes"].(string)
		if !ok {
			continue
		}
		derBytes, err := base64.StdEncoding.DecodeString(rawBytesB64)
		if err != nil {
			continue
		}
		cert, err := x509.ParseCertificate(derBytes)
		if err != nil {
			continue
		}
		intermediateCerts = append(intermediateCerts, cert)
	}

	return intermediateCerts, nil
}

// applyBundleCompat applies in-place transforms to a raw bundle JSON map
// for backward compatibility with older Python-produced signatures.
//
// Transforms applied:
//  1. Add missing tlogEntries (pre-v1.1.0 bundles omit this field)
//  2. Strip rawBytes/keyDetails from publicKey (v0.3.1-v1.0.1 key format)
//     and set hint to empty string if missing
//  3. Convert x509CertificateChain to singular certificate field
//     (old Python bundles use the v0.2 cert chain format with a v0.3 mediaType)
func applyBundleCompat(raw map[string]interface{}) {
	vm, ok := raw["verificationMaterial"].(map[string]interface{})
	if !ok {
		return
	}

	// 1. Add missing tlogEntries
	if _, ok := vm["tlogEntries"]; !ok {
		vm["tlogEntries"] = []interface{}{}
	}

	// 2. Handle old publicKey format: strip rawBytes and keyDetails
	if pk, ok := vm["publicKey"].(map[string]interface{}); ok {
		if _, hasHint := pk["hint"]; !hasHint {
			pk["hint"] = ""
		}
		delete(pk, "rawBytes")
		delete(pk, "keyDetails")
	}

	// 3. Convert x509CertificateChain to singular certificate (v0.3 format)
	// Old Python bundles use x509CertificateChain (v0.2 verification material)
	// but declare mediaType v0.3. sigstore-go rejects this combination.
	// Convert to the v0.3 "certificate" field using the first (signing) cert.
	if certChain, ok := vm["x509CertificateChain"].(map[string]interface{}); ok {
		if certs, ok := certChain["certificates"].([]interface{}); ok && len(certs) > 0 {
			// Use the first certificate (the signing certificate)
			vm["certificate"] = certs[0]
		}
		delete(vm, "x509CertificateChain")
	}
}
