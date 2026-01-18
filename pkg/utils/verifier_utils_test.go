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
		{"unicode ok length>8", "αβγδεζηθικλ", "αβγδ...ηθικλ"},
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

func TestHexToBytes(t *testing.T) {
	cases := []struct {
		name    string
		in      string
		wantLen int
		wantErr bool
	}{
		{"odd length error", "abc", 0, true},
		{"invalid hex error", "zz", 0, true},
		{"lowercase hex ok", "0a1b", 2, false},
		{"uppercase hex ok", "0A1B", 2, false},
		{"empty string ok length 0", "", 0, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			b, err := hexToBytes(tc.in)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("hexToBytes(%q) expected error, got none", tc.in)
				}
				return
			}
			if err != nil {
				t.Fatalf("hexToBytes(%q) unexpected error: %v", tc.in, err)
			}
			if len(b) != tc.wantLen {
				t.Fatalf("hexToBytes(%q) length = %d, want %d", tc.in, len(b), tc.wantLen)
			}
		})
	}
}
