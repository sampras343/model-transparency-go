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

// MaskToken masks sensitive tokens for safe logging.
// Shows only the first 4 and last 4 characters, replacing the middle with "...".
// Returns "***" for tokens with 8 or fewer characters, or empty string for empty input.
func MaskToken(token string) string {
	if token == "" {
		return ""
	}
	// Convert to runes to handle Unicode characters properly
	runes := []rune(token)
	if len(runes) <= 8 {
		return "***"
	}
	return string(runes[:4]) + "..." + string(runes[len(runes)-4:])
}
