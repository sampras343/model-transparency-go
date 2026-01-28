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

package utils

import "testing"

func TestMaskToken(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"empty string returns empty", "", ""},
		{"short token (<=8) masked fully", "abc123", "***"},
		{"exactly 8 chars masked fully", "abcd1234", "***"},
		{"long token masks middle", "abcdefghijkl", "abcd...ijkl"},
		{"unicode ok length>8", "αβγδεζηθικλ", "αβγδ...θικλ"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := MaskToken(tc.in)
			if got != tc.want {
				t.Fatalf("MaskToken(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}
