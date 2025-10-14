//
// Copyright 2025 The Sigstore Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package hashing

import (
	"crypto/sha256"
	"crypto/subtle"
	"hash"

	blake2b "golang.org/x/crypto/blake2b"
)

// sha256Streaming implements StreamingHashEngine over SHA-256.
type sha256Streaming struct {
	h hash.Hash
}

func NewSHA256() StreamingHashEngine {
	return &sha256Streaming{h: sha256.New()}
}

func (s *sha256Streaming) Update(data []byte) { _, _ = s.h.Write(data) }
func (s *sha256Streaming) Reset(data []byte) {
	s.h = sha256.New()
	if len(data) > 0 {
		_, _ = s.h.Write(data)
	}
}
func (s *sha256Streaming) Compute() Digest {
	sum := s.h.Sum(nil)
	cp := make([]byte, len(sum))
	copy(cp, sum)
	return Digest{Algorithm: s.DigestName(), DigestValue: cp}
}
func (s *sha256Streaming) DigestName() string { return "sha256" }
func (s *sha256Streaming) DigestSize() int    { return sha256.Size }

// blake2bStreaming implements StreamingHashEngine over BLAKE2b-512 (64 bytes),
type blake2bStreaming struct {
	h hash.Hash
}

func NewBLAKE2b() StreamingHashEngine {
	h, err := blake2b.New512(nil) // 64-byte digest (matches hashlib.blake2b default)
	if err != nil {
		// New512 only errors for invalid params; nil key is valid.
		panic(err)
	}
	return &blake2bStreaming{h: h}
}

func (b *blake2bStreaming) Update(data []byte) { _, _ = b.h.Write(data) }

func (b *blake2bStreaming) Reset(data []byte) {
	h, err := blake2b.New512(nil)
	if err != nil {
		panic(err)
	}
	b.h = h
	if len(data) > 0 {
		_, _ = b.h.Write(data)
	}
}

func (b *blake2bStreaming) Compute() Digest {
	sum := b.h.Sum(nil)
	cp := make([]byte, len(sum))
	copy(cp, sum)
	return Digest{Algorithm: b.DigestName(), DigestValue: cp}
}

func (b *blake2bStreaming) DigestName() string { return "blake2b" }
func (b *blake2bStreaming) DigestSize() int    { return blake2b.Size } // 64

func EqualDigests(a, b Digest) bool {
	return a.Algorithm == b.Algorithm &&
		len(a.DigestValue) == len(b.DigestValue) &&
		subtle.ConstantTimeCompare(a.DigestValue, b.DigestValue) == 1
}