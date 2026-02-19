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

package pkcs11

import (
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

// pinValuePattern matches pin-value=... in a PKCS#11 URI query string.
var pinValuePattern = regexp.MustCompile(`(pin-value=)[^&]*`)

// SanitizeURI redacts the pin-value from a PKCS#11 URI string for safe logging.
func SanitizeURI(uri string) string {
	return pinValuePattern.ReplaceAllString(uri, "${1}***")
}

// URI represents a parsed PKCS#11 URI according to RFC 7512.
type URI struct {
	pathAttributes     map[string]string
	queryAttributes    map[string]string
	moduleDirectories  []string
	allowedModulePaths []string
	allowAnyModule     bool
}

// defaultModuleDirs lists directories where PKCS#11 modules are typically
// installed across Linux distributions and macOS. This single list is used
// both as the default search path and the default allow-list so that only
// modules in known system locations are loaded.
var defaultModuleDirs = []string{
	"/usr/lib64/pkcs11/",                 // Fedora, RHEL, openSUSE
	"/usr/lib/pkcs11/",                   // Fedora 32-bit, Arch Linux
	"/usr/lib/x86_64-linux-gnu/softhsm/", // Ubuntu/Debian x86_64
	"/usr/lib/softhsm/",                  // Ubuntu/Debian (older or 32-bit)
	"/usr/lib64/softhsm/",                // Fedora/RHEL SoftHSM2
	"/usr/local/lib/softhsm/",            // macOS Homebrew (Intel), manual installs
	"/opt/homebrew/lib/softhsm/",         // macOS Homebrew (ARM)
}

// NewURI creates a new PKCS#11 URI parser.
func NewURI() *URI {
	return &URI{
		pathAttributes:     make(map[string]string),
		queryAttributes:    make(map[string]string),
		moduleDirectories:  []string{},
		allowedModulePaths: defaultModuleDirs,
		allowAnyModule:     false,
	}
}

// Parse parses a PKCS#11 URI string.
func (p *URI) Parse(uri string) error {
	if !strings.HasPrefix(uri, "pkcs11:") {
		return fmt.Errorf("malformed pkcs11 URI: missing 'pkcs11:' prefix: %s", uri)
	}

	p.reset()

	// Remove the pkcs11: prefix
	remainder := uri[7:]

	// Split into path and query parts
	parts := strings.SplitN(remainder, "?", 2)

	// Parse path attributes
	if len(parts[0]) > 0 {
		for _, part := range strings.Split(parts[0], ";") {
			kv := strings.SplitN(part, "=", 2)
			if len(kv) != 2 {
				return fmt.Errorf("malformed pkcs11 URI: malformed path attribute")
			}
			decoded, err := url.QueryUnescape(kv[1])
			if err != nil {
				return fmt.Errorf("failed to decode path attribute value: %w", err)
			}
			p.pathAttributes[kv[0]] = decoded
		}
	}

	// Parse query attributes
	if len(parts) == 2 {
		for _, part := range strings.Split(parts[1], "&") {
			kv := strings.SplitN(part, "=", 2)
			if len(kv) != 2 {
				return fmt.Errorf("malformed pkcs11 URI: malformed query attribute")
			}
			decoded, err := url.QueryUnescape(kv[1])
			if err != nil {
				return fmt.Errorf("failed to decode query attribute value: %w", err)
			}
			p.queryAttributes[kv[0]] = decoded
		}
	}

	return p.validate()
}

// reset clears all attributes.
func (p *URI) reset() {
	p.pathAttributes = make(map[string]string)
	p.queryAttributes = make(map[string]string)
}

// validate validates the URI according to RFC 7512 rules.
func (p *URI) validate() error {
	// Validate slot-id
	if slotID, ok := p.pathAttributes["slot-id"]; ok {
		if _, err := strconv.ParseUint(slotID, 10, 32); err != nil {
			return fmt.Errorf("slot-id must be a number: %s", slotID)
		}
	}

	// Validate type
	if typ, ok := p.pathAttributes["type"]; ok {
		validTypes := map[string]bool{
			"public": true, "private": true, "cert": true,
			"secret-key": true, "data": true,
		}
		if !validTypes[typ] {
			return fmt.Errorf("invalid type '%s'", typ)
		}
	}

	// Check for conflicting PIN attributes
	_, hasPinSource := p.queryAttributes["pin-source"]
	_, hasPinValue := p.queryAttributes["pin-value"]
	if hasPinSource && hasPinValue {
		return fmt.Errorf("URI must not contain both pin-source and pin-value")
	}

	// Validate module-path is absolute
	if modulePath, ok := p.queryAttributes["module-path"]; ok {
		if !filepath.IsAbs(modulePath) {
			return fmt.Errorf("path %s of module-path attribute must be absolute", modulePath)
		}
	}

	return nil
}

// SetModuleDirectories sets directories to search for PKCS#11 modules.
func (p *URI) SetModuleDirectories(dirs []string) {
	p.moduleDirectories = dirs
}

// SetAllowedModulePaths sets the allowed paths for PKCS#11 modules.
func (p *URI) SetAllowedModulePaths(paths []string) {
	p.allowedModulePaths = paths
}

// SetAllowAnyModule sets whether any module may be loaded.
func (p *URI) SetAllowAnyModule(allow bool) {
	p.allowAnyModule = allow
}

// HasPIN checks whether a PIN has been provided.
func (p *URI) HasPIN() bool {
	_, hasPinValue := p.queryAttributes["pin-value"]
	_, hasPinSource := p.queryAttributes["pin-source"]
	return hasPinValue || hasPinSource
}

// GetPIN retrieves the PIN from the URI.
func (p *URI) GetPIN() (string, error) {
	if pinValue, ok := p.queryAttributes["pin-value"]; ok {
		return pinValue, nil
	}

	if pinSource, ok := p.queryAttributes["pin-source"]; ok {
		u, err := url.Parse(pinSource)
		if err != nil {
			return "", fmt.Errorf("failed to parse pin-source URI: %w", err)
		}

		if u.Scheme == "" || u.Scheme == "file" {
			if !filepath.IsAbs(u.Path) {
				return "", fmt.Errorf("PIN URI path '%s' is not absolute", u.Path)
			}
			data, err := os.ReadFile(u.Path)
			if err != nil {
				return "", fmt.Errorf("failed to read PIN from file: %w", err)
			}
			return strings.TrimSpace(string(data)), nil
		}

		return "", fmt.Errorf("PIN URI scheme %s is not supported", u.Scheme)
	}

	return "", fmt.Errorf("neither pin-source nor pin-value are available")
}

// GetModule returns the PKCS#11 module path to use.
//
// Resolution order:
//  1. If module-path is set to a regular file, use it directly.
//  2. If module-path is set to a directory, restrict the search to that directory.
//  3. If module-name is set, search for a file whose name contains that string.
//  4. Otherwise, return the first .so file found in the search directories.
//
// Search directories are, in order: moduleDirectories (set by the caller),
// then defaultModuleDirs.
func (p *URI) GetModule() (string, error) {
	var searchDirs []string

	// If module-path is specified, use it
	if modulePath, ok := p.queryAttributes["module-path"]; ok {
		info, err := os.Stat(modulePath)
		if err != nil {
			return "", fmt.Errorf("module-path error: %w", err)
		}

		if info.Mode().IsRegular() {
			if !p.isAllowedPath(modulePath) {
				return "", fmt.Errorf("module-path '%s' is not allowed by policy", modulePath)
			}
			return modulePath, nil
		}

		if !info.IsDir() {
			return "", fmt.Errorf("module-path '%s' points to an invalid file type", modulePath)
		}

		searchDirs = []string{modulePath}
	}

	if searchDirs == nil {
		searchDirs = p.moduleDirectories
		if len(searchDirs) == 0 {
			searchDirs = defaultModuleDirs
		}
	}

	// If module-name is specified, search for a file whose name contains it.
	if moduleName, ok := p.queryAttributes["module-name"]; ok {
		moduleName = strings.ToLower(moduleName)

		for _, dir := range searchDirs {
			entries, err := os.ReadDir(dir)
			if err != nil {
				continue
			}

			for _, entry := range entries {
				if entry.IsDir() {
					continue
				}

				fileName := strings.ToLower(entry.Name())
				if strings.Contains(fileName, moduleName) {
					fullPath := filepath.Join(dir, entry.Name())
					if !p.isAllowedPath(fullPath) {
						return "", fmt.Errorf("module '%s' is not allowed by policy", fullPath)
					}
					return fullPath, nil
				}
			}
		}

		return "", fmt.Errorf("no module '%s' could be found in %v", p.queryAttributes["module-name"], searchDirs)
	}

	// No module-name: scan search directories for any .so file.
	for _, dir := range searchDirs {
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}

		for _, entry := range entries {
			if entry.IsDir() {
				continue
			}

			if strings.HasSuffix(strings.ToLower(entry.Name()), ".so") {
				fullPath := filepath.Join(dir, entry.Name())
				if !p.isAllowedPath(fullPath) {
					continue
				}
				return fullPath, nil
			}
		}
	}

	return "", fmt.Errorf("PKCS#11 module not found; set module-path or module-name in the URI, or provide module search directories")
}

// isAllowedPath checks whether the given path is allowed.
func (p *URI) isAllowedPath(path string) bool {
	if p.allowAnyModule {
		return true
	}

	for _, allowed := range p.allowedModulePaths {
		if allowed == path {
			return true
		}
		// Check if path is in allowed directory
		if strings.HasSuffix(allowed, string(filepath.Separator)) {
			if strings.HasPrefix(path, allowed) {
				// Ensure it's a direct child, not nested
				remainder := path[len(allowed):]
				if !strings.Contains(remainder, string(filepath.Separator)) {
					return true
				}
			}
		}
	}

	return false
}

// GetKeyIDAndLabel returns the key ID and label from the URI.
func (p *URI) GetKeyIDAndLabel() ([]byte, string, error) {
	var keyID []byte
	var label string

	if idStr, ok := p.pathAttributes["id"]; ok {
		// The id attribute is already decoded during URI parsing
		keyID = []byte(idStr)
	}

	if obj, ok := p.pathAttributes["object"]; ok {
		label = obj
	}

	if keyID == nil && label == "" {
		return nil, "", fmt.Errorf("neither 'id' nor 'object' attributes were found in pkcs11 URI")
	}

	return keyID, label, nil
}

// GetSlotID returns the slot ID from the URI, or -1 if not specified.
// PKCS#11 slot IDs are CK_ULONG (32-bit unsigned integers).
func (p *URI) GetSlotID() (int64, error) {
	slotIDStr, ok := p.pathAttributes["slot-id"]
	if !ok {
		return -1, nil
	}

	slotID, err := strconv.ParseUint(slotIDStr, 10, 32)
	if err != nil {
		return -1, fmt.Errorf("invalid slot-id: %w", err)
	}

	return int64(slotID), nil
}

// GetTokenLabel returns the token label from the URI.
func (p *URI) GetTokenLabel() string {
	return p.pathAttributes["token"]
}
