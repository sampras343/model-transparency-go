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

package manifest

import (
	"reflect"
	"testing"
)

func TestParamExtractor_GetString(t *testing.T) {
	params := map[string]interface{}{
		"valid":   "hello",
		"invalid": 123,
	}
	extractor := NewParamExtractor(params)

	tests := []struct {
		name    string
		key     string
		want    string
		wantErr bool
	}{
		{"valid string", "valid", "hello", false},
		{"missing key", "missing", "", true},
		{"wrong type", "invalid", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := extractor.GetString(tt.key)
			if (err != nil) != tt.wantErr {
				t.Errorf("GetString() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("GetString() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestParamExtractor_GetBool(t *testing.T) {
	params := map[string]interface{}{
		"valid":   true,
		"invalid": "true",
	}
	extractor := NewParamExtractor(params)

	tests := []struct {
		name    string
		key     string
		want    bool
		wantErr bool
	}{
		{"valid bool", "valid", true, false},
		{"missing key", "missing", false, true},
		{"wrong type", "invalid", false, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := extractor.GetBool(tt.key)
			if (err != nil) != tt.wantErr {
				t.Errorf("GetBool() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("GetBool() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestParamExtractor_GetInt64(t *testing.T) {
	params := map[string]interface{}{
		"int64":   int64(42),
		"int":     int(42),
		"float64": float64(42.0),
		"invalid": "42",
	}
	extractor := NewParamExtractor(params)

	tests := []struct {
		name    string
		key     string
		want    int64
		wantErr bool
	}{
		{"valid int64", "int64", 42, false},
		{"valid int", "int", 42, false},
		{"valid float64", "float64", 42, false},
		{"missing key", "missing", 0, true},
		{"wrong type", "invalid", 0, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := extractor.GetInt64(tt.key)
			if (err != nil) != tt.wantErr {
				t.Errorf("GetInt64() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("GetInt64() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestParamExtractor_GetStringSlice(t *testing.T) {
	params := map[string]interface{}{
		"string_slice": []string{"a", "b", "c"},
		"iface_slice":  []interface{}{"x", "y", "z"},
		"mixed_slice":  []interface{}{"a", 1, "c"},
		"invalid":      "not a slice",
	}
	extractor := NewParamExtractor(params)

	tests := []struct {
		name    string
		key     string
		want    []string
		wantErr bool
	}{
		{"valid []string", "string_slice", []string{"a", "b", "c"}, false},
		{"valid []interface{}", "iface_slice", []string{"x", "y", "z"}, false},
		{"missing key", "missing", nil, false}, // Optional parameter
		{"mixed types", "mixed_slice", nil, true},
		{"wrong type", "invalid", nil, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := extractor.GetStringSlice(tt.key)
			if (err != nil) != tt.wantErr {
				t.Errorf("GetStringSlice() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("GetStringSlice() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestParamExtractor_GetStringSliceOptional(t *testing.T) {
	params := map[string]interface{}{
		"valid": []string{"a", "b"},
	}
	extractor := NewParamExtractor(params)

	tests := []struct {
		name string
		key  string
		want []string
	}{
		{"valid slice", "valid", []string{"a", "b"}},
		{"missing key", "missing", []string{}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractor.GetStringSliceOptional(tt.key)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("GetStringSliceOptional() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestParamExtractor_GetOptional(t *testing.T) {
	params := map[string]interface{}{
		"string": "hello",
		"bool":   true,
		"int64":  int64(42),
	}
	extractor := NewParamExtractor(params)

	t.Run("GetStringOptional - present", func(t *testing.T) {
		got, err := extractor.GetStringOptional("string")
		if err != nil {
			t.Errorf("GetStringOptional() error = %v", err)
		}
		if got != "hello" {
			t.Errorf("GetStringOptional() = %v, want %v", got, "hello")
		}
	})

	t.Run("GetStringOptional - missing", func(t *testing.T) {
		got, err := extractor.GetStringOptional("missing")
		if err != nil {
			t.Errorf("GetStringOptional() error = %v", err)
		}
		if got != "" {
			t.Errorf("GetStringOptional() = %v, want empty string", got)
		}
	})

	t.Run("GetBoolOptional - present", func(t *testing.T) {
		got, err := extractor.GetBoolOptional("bool", false)
		if err != nil {
			t.Errorf("GetBoolOptional() error = %v", err)
		}
		if got != true {
			t.Errorf("GetBoolOptional() = %v, want %v", got, true)
		}
	})

	t.Run("GetBoolOptional - missing", func(t *testing.T) {
		got, err := extractor.GetBoolOptional("missing", true)
		if err != nil {
			t.Errorf("GetBoolOptional() error = %v", err)
		}
		if got != true {
			t.Errorf("GetBoolOptional() = %v, want %v", got, true)
		}
	})

	t.Run("GetInt64Optional - present", func(t *testing.T) {
		got, err := extractor.GetInt64Optional("int64", 0)
		if err != nil {
			t.Errorf("GetInt64Optional() error = %v", err)
		}
		if got != 42 {
			t.Errorf("GetInt64Optional() = %v, want %v", got, 42)
		}
	})

	t.Run("GetInt64Optional - missing", func(t *testing.T) {
		got, err := extractor.GetInt64Optional("missing", 100)
		if err != nil {
			t.Errorf("GetInt64Optional() error = %v", err)
		}
		if got != 100 {
			t.Errorf("GetInt64Optional() = %v, want %v", got, 100)
		}
	})
}

func TestParamExtractor_Has(t *testing.T) {
	params := map[string]interface{}{
		"present": "value",
	}
	extractor := NewParamExtractor(params)

	tests := []struct {
		name string
		key  string
		want bool
	}{
		{"present key", "present", true},
		{"missing key", "missing", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := extractor.Has(tt.key); got != tt.want {
				t.Errorf("Has() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestParamExtractor_GetRaw(t *testing.T) {
	params := map[string]interface{}{
		"custom": struct{ Value int }{Value: 42},
	}
	extractor := NewParamExtractor(params)

	t.Run("present key", func(t *testing.T) {
		got, exists := extractor.GetRaw("custom")
		if !exists {
			t.Error("GetRaw() exists = false, want true")
		}
		custom, ok := got.(struct{ Value int })
		if !ok {
			t.Errorf("GetRaw() type assertion failed")
		}
		if custom.Value != 42 {
			t.Errorf("GetRaw() value = %v, want %v", custom.Value, 42)
		}
	})

	t.Run("missing key", func(t *testing.T) {
		_, exists := extractor.GetRaw("missing")
		if exists {
			t.Error("GetRaw() exists = true, want false")
		}
	})
}
