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

// Package crypto provides internal cryptographic operations for model signing.
//
// This package contains low-level cryptographic primitives used internally
// by the signing and verification implementations. External consumers should
// use the higher-level APIs in pkg/signing and pkg/verify instead.
package crypto

import "fmt"

// ComputePAE computes the Pre-Authentication Encoding for DSSE (Dead Simple Signing Envelope).
// The encoding format is: "DSSEv1" + SP + LEN(type) + SP + type + SP + LEN(payload) + SP + payload
// where SP is a space character and LEN is the ASCII decimal length.
// Returns the PAE as a byte slice.
func ComputePAE(payloadType string, payload []byte) []byte {
	pae := []byte("DSSEv1 ")
	pae = appendLength(pae, len(payloadType))
	pae = append(pae, ' ')
	pae = append(pae, []byte(payloadType)...)
	pae = append(pae, ' ')
	pae = appendLength(pae, len(payload))
	pae = append(pae, ' ')
	pae = append(pae, payload...)
	return pae
}

// appendLength appends an ASCII decimal representation of n to buf.
// Returns the extended buffer.
func appendLength(buf []byte, n int) []byte {
	return append(buf, []byte(fmt.Sprintf("%d", n))...)
}

// ComputePAECompat computes PAE for backward compatibility with model_signing v0.2.0.
// This exists because v0.2.0 had a bug in PAE computation.
func ComputePAECompat(payloadType string, payload []byte) []byte {
	// Emulate Python's bytes repr: b'...' with escape sequences
	payloadRepr := fmt.Sprintf("b'%s'", escapeBytesAsPythonRepr(payload))

	// Build buggy PAE: DSSEV1 (capital V) + payload as string repr
	paeStr := fmt.Sprintf("DSSEV1 %d %s %d %s",
		len(payloadType), payloadType, len(payload), payloadRepr)

	return []byte(paeStr)
}

// escapeBytesAsPythonRepr emulates Python package bytes repr escaping.
// This converts bytes to the same string representation Python would use
// when bytes are converted to string via str() or f-string interpolation.
func escapeBytesAsPythonRepr(data []byte) string {
	result := make([]byte, 0, len(data)*2)
	for _, b := range data {
		switch b {
		case '\'':
			result = append(result, '\\', '\'')
		case '\\':
			result = append(result, '\\', '\\')
		case '\n':
			result = append(result, '\\', 'n')
		case '\r':
			result = append(result, '\\', 'r')
		case '\t':
			result = append(result, '\\', 't')
		default:
			if b >= 32 && b < 127 {
				result = append(result, b)
			} else {
				result = append(result, fmt.Sprintf("\\x%02x", b)...)
			}
		}
	}
	return string(result)
}
