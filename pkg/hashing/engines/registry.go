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

// Package hashengines provides a registry for hash engine implementations.
//
// The registry allows hash engines to be registered by algorithm name and later
// retrieved for use. This enables loose coupling between hash algorithm implementations
// and code that uses them. Registration is thread-safe and typically occurs during
// package initialization.
package hashengines

import (
	"fmt"
	"sort"
	"sync"
)

// HashEngineFactory is a function type that creates new hash engine instances.
//
// Returns a StreamingHashEngine or an error if the engine cannot be created.
type HashEngineFactory func() (StreamingHashEngine, error)

var (
	registry = make(map[string]HashEngineFactory)
	mu       sync.RWMutex
	initOnce sync.Once
)

// initRegistry is a placeholder for lazy initialization.
// Default hash engines are registered by their respective packages' init() functions
func initRegistry() {
	initOnce.Do(func() {
		// No-op: engines self-register via their init() functions.
	})
}

// Register registers a hash engine factory for the specified algorithm name.
//
// The algorithm parameter specifies the name to register (case-sensitive).
// The factory parameter is the function to create instances of this hash engine.
//
// Returns an error if the algorithm name is empty, the factory is nil, or
// an engine with this name is already registered.
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

// MustRegister registers a hash engine factory and panics if registration fails.
//
// The algorithm parameter specifies the name to register (case-sensitive).
// The factory parameter is the function to create instances of this hash engine.
//
// This function is intended for package initialization where registration failure
// indicates a programming error that should halt execution immediately.
// Panics if registration fails for any reason.
func MustRegister(algorithm string, factory HashEngineFactory) {
	if err := Register(algorithm, factory); err != nil {
		panic(fmt.Sprintf("failed to register hash algorithm %q: %v", algorithm, err))
	}
}

// Create creates a new hash engine instance for the specified algorithm.
//
// The algorithm parameter specifies the name of the hash algorithm (case-sensitive).
//
// Returns a new StreamingHashEngine instance, or an error if the algorithm is not
// registered or if the factory fails to create the engine.
func Create(algorithm string) (StreamingHashEngine, error) {
	initRegistry()

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

// SupportedAlgorithms returns a sorted list of all registered algorithm names.
//
// Returns a slice of algorithm name strings in alphabetical order.
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

// IsSupported checks whether the specified algorithm is registered.
//
// The algorithm parameter specifies the name to check (case-sensitive).
//
// Returns true if a factory for this algorithm is registered, false otherwise.
func IsSupported(algorithm string) bool {
	mu.RLock()
	defer mu.RUnlock()

	_, exists := registry[algorithm]
	return exists
}

// Unregister removes a hash engine factory from the registry.
//
// The algorithm parameter specifies the name to unregister (case-sensitive).
//
// This function is primarily useful for testing. In production code, hash engines
// should remain registered once added.
//
// Returns an error if the algorithm is not currently registered.
func Unregister(algorithm string) error {
	mu.Lock()
	defer mu.Unlock()

	if _, exists := registry[algorithm]; !exists {
		return fmt.Errorf("hash algorithm %q not registered", algorithm)
	}

	delete(registry, algorithm)
	return nil
}
