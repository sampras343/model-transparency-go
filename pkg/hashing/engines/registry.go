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

package hashengines

import (
	"fmt"
	"sort"
	"sync"
)

// HashEngineFactory is a function that creates a new hash engine.
type HashEngineFactory func() (StreamingHashEngine, error)

var (
	registry = make(map[string]HashEngineFactory)
	mu       sync.RWMutex
	initOnce sync.Once
)

// ensureDefaults registers default hash engines on first use.
// This avoids import cycles by not importing memory package at package init time.
func ensureDefaults() {
	initOnce.Do(func() {
		// Default engines will be registered by their respective packages
		// when they are imported. This allows the registry to exist without
		// creating import cycles.
	})
}

// Register registers a new hash engine factory for the given algorithm name.
//
// If an engine with the same name is already registered, an error is returned.
// Algorithm names are case-sensitive.
func Register(algorithm string, factory HashEngineFactory) error {
	mu.Lock()
	defer mu.Unlock()

	if algorithm == "" {
		return fmt.Errorf("algorithm name cannot be empty")
	}

	if factory == nil {
		return fmt.Errorf("factory cannot be nil")
	}

	if _, exists := registry[algorithm]; exists {
		return fmt.Errorf("hash algorithm %q already registered", algorithm)
	}

	registry[algorithm] = factory
	return nil
}

// MustRegister registers a hash engine factory or panics on error.
//
// This is useful for package initialization where registration failure
// indicates a programming error that should be caught immediately.
func MustRegister(algorithm string, factory HashEngineFactory) {
	if err := Register(algorithm, factory); err != nil {
		panic(fmt.Sprintf("failed to register hash algorithm %q: %v", algorithm, err))
	}
}

// Create creates a new hash engine for the given algorithm.
//
// Returns an error if the algorithm is not registered or if the factory
// fails to create the engine.
func Create(algorithm string) (StreamingHashEngine, error) {
	ensureDefaults()

	mu.RLock()
	factory, exists := registry[algorithm]
	mu.RUnlock()

	if !exists {
		supported := SupportedAlgorithms()
		return nil, fmt.Errorf("unsupported hash algorithm: %s (supported: %v)",
			algorithm, supported)
	}

	engine, err := factory()
	if err != nil {
		return nil, fmt.Errorf("failed to create hash engine for %q: %w", algorithm, err)
	}

	return engine, nil
}

// SupportedAlgorithms returns a sorted list of registered algorithm names.
func SupportedAlgorithms() []string {
	mu.RLock()
	defer mu.RUnlock()

	algorithms := make([]string, 0, len(registry))
	for algo := range registry {
		algorithms = append(algorithms, algo)
	}
	sort.Strings(algorithms)
	return algorithms
}

// IsSupported checks if an algorithm is registered.
func IsSupported(algorithm string) bool {
	mu.RLock()
	defer mu.RUnlock()

	_, exists := registry[algorithm]
	return exists
}

// Unregister removes a hash engine from the registry.
//
// This is primarily useful for testing. Returns an error if the algorithm
// is not registered.
func Unregister(algorithm string) error {
	mu.Lock()
	defer mu.Unlock()

	if _, exists := registry[algorithm]; !exists {
		return fmt.Errorf("hash algorithm %q not registered", algorithm)
	}

	delete(registry, algorithm)
	return nil
}
