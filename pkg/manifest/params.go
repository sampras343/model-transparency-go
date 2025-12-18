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

package manifest

import "fmt"

// ParamExtractor helps extract typed values from manifest parameters.
//
// It handles type assertions and conversions, providing consistent error
// messages when parameters are missing or have incorrect types.
type ParamExtractor struct {
	params map[string]interface{}
}

// NewParamExtractor creates a new parameter extractor.
func NewParamExtractor(params map[string]interface{}) *ParamExtractor {
	return &ParamExtractor{params: params}
}

// GetString extracts a string parameter.
//
// Returns an error if the parameter is missing or not a string.
func (e *ParamExtractor) GetString(key string) (string, error) {
	value, exists := e.params[key]
	if !exists {
		return "", fmt.Errorf("parameter %q not found", key)
	}

	str, ok := value.(string)
	if !ok {
		return "", fmt.Errorf("parameter %q is not a string (got %T)", key, value)
	}

	return str, nil
}

// GetStringOptional extracts an optional string parameter.
//
// Returns empty string if the parameter is missing, or an error if it exists
// but is not a string.
func (e *ParamExtractor) GetStringOptional(key string) (string, error) {
	value, exists := e.params[key]
	if !exists {
		return "", nil
	}

	str, ok := value.(string)
	if !ok {
		return "", fmt.Errorf("parameter %q is not a string (got %T)", key, value)
	}

	return str, nil
}

// GetBool extracts a boolean parameter.
//
// Returns an error if the parameter is missing or not a boolean.
func (e *ParamExtractor) GetBool(key string) (bool, error) {
	value, exists := e.params[key]
	if !exists {
		return false, fmt.Errorf("parameter %q not found", key)
	}

	b, ok := value.(bool)
	if !ok {
		return false, fmt.Errorf("parameter %q is not a bool (got %T)", key, value)
	}

	return b, nil
}

// GetBoolOptional extracts an optional boolean parameter.
//
// Returns the default value if the parameter is missing, or an error if it
// exists but is not a boolean.
func (e *ParamExtractor) GetBoolOptional(key string, defaultValue bool) (bool, error) {
	value, exists := e.params[key]
	if !exists {
		return defaultValue, nil
	}

	b, ok := value.(bool)
	if !ok {
		return false, fmt.Errorf("parameter %q is not a bool (got %T)", key, value)
	}

	return b, nil
}

// GetInt64 extracts an int64 parameter with automatic type conversions.
//
// Supports conversion from int, int64, and float64 types.
// Returns an error if the parameter is missing or cannot be converted.
func (e *ParamExtractor) GetInt64(key string) (int64, error) {
	value, exists := e.params[key]
	if !exists {
		return 0, fmt.Errorf("parameter %q not found", key)
	}

	switch v := value.(type) {
	case int64:
		return v, nil
	case int:
		return int64(v), nil
	case float64:
		return int64(v), nil
	default:
		return 0, fmt.Errorf("parameter %q cannot be converted to int64 (got %T)", key, value)
	}
}

// GetInt64Optional extracts an optional int64 parameter with type conversions.
//
// Returns the default value if the parameter is missing, or an error if it
// exists but cannot be converted to int64.
func (e *ParamExtractor) GetInt64Optional(key string, defaultValue int64) (int64, error) {
	value, exists := e.params[key]
	if !exists {
		return defaultValue, nil
	}

	switch v := value.(type) {
	case int64:
		return v, nil
	case int:
		return int64(v), nil
	case float64:
		return int64(v), nil
	default:
		return 0, fmt.Errorf("parameter %q cannot be converted to int64 (got %T)", key, value)
	}
}

// GetStringSlice extracts a string slice parameter.
//
// Handles both []string and []interface{} types, converting []interface{}
// to []string if all elements are strings.
// Returns nil for missing parameters (treated as optional).
func (e *ParamExtractor) GetStringSlice(key string) ([]string, error) {
	value, exists := e.params[key]
	if !exists {
		return nil, nil // Optional parameter
	}

	// Try direct []string
	if strSlice, ok := value.([]string); ok {
		return strSlice, nil
	}

	// Try []interface{} and convert
	if ifaceSlice, ok := value.([]interface{}); ok {
		result := make([]string, 0, len(ifaceSlice))
		for i, item := range ifaceSlice {
			str, ok := item.(string)
			if !ok {
				return nil, fmt.Errorf("parameter %q[%d] is not a string (got %T)", key, i, item)
			}
			result = append(result, str)
		}
		return result, nil
	}

	return nil, fmt.Errorf("parameter %q is not a string slice (got %T)", key, value)
}

// GetStringSliceOptional extracts an optional string slice parameter.
//
// Returns an empty slice (not nil) if the parameter is missing or extraction fails.
// This is useful when you want to use the result directly without nil checks.
func (e *ParamExtractor) GetStringSliceOptional(key string) []string {
	slice, err := e.GetStringSlice(key)
	if err != nil {
		return []string{}
	}
	if slice == nil {
		return []string{}
	}
	return slice
}

// Has checks if a parameter exists.
func (e *ParamExtractor) Has(key string) bool {
	_, exists := e.params[key]
	return exists
}

// GetRaw returns the raw parameter value.
//
// This is useful for custom type handling or when you need the original value.
func (e *ParamExtractor) GetRaw(key string) (interface{}, bool) {
	value, exists := e.params[key]
	return value, exists
}
