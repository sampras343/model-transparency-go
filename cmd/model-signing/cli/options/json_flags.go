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

package options

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/spf13/cobra"
	flag "github.com/spf13/pflag"
)

// stdinJSONArg is the --json value that reads a JSON object from stdin.
const stdinJSONArg = "-"

// JSONModelPathKey is the reserved JSON key for the model path when no non-empty positional is given.
const JSONModelPathKey = "model"

// ErrUnknownJSONFlagKey means --json contained a key that is not a defined flag for this command.
var ErrUnknownJSONFlagKey = errors.New("unknown JSON key: not a defined flag for this command")

// errJSONObjectPayloadRequired: --json payload must be a JSON object (not key=value).
var errJSONObjectPayloadRequired = errors.New(`--json: must be a JSON object (e.g. {"flag":"value"}), ` + stdinJSONArg + ` to read from stdin, or a path to a file whose contents are a JSON object`)

// errJSONConfigFileUnreadable is returned for missing, unreadable, or non-regular --json file paths
// without distinguishing cause, to avoid leaking file existence or permission details.
var errJSONConfigFileUnreadable = errors.New("--json: could not read configuration file")

const maxJSONConfigFileBytes = 4 << 20 // 4 MiB cap for --json file payloads

// JSONFlags holds repeated --json inputs to merge into command flags.
type JSONFlags struct {
	jsonInputs []string

	// set from JSON key "model" in ParseAndApply; cleared at start of ParseAndApply.
	modelPathFromJSON string
}

// NewJSONFlags returns an empty JSONFlags.
func NewJSONFlags() *JSONFlags {
	return &JSONFlags{}
}

// AddPersistentFlags registers persistent --json on cmd.
func (o *JSONFlags) AddPersistentFlags(cmd *cobra.Command) {
	cmd.PersistentFlags().StringArrayVar(&o.jsonInputs, "json", nil,
		fmt.Sprintf(`Set flags from a JSON object (repeat --json to merge). Value may be inline JSON starting with '{', %q to read from stdin, or a path to a regular file (any readable extension; max %d MiB) whose contents are a JSON object. Only regular files are accepted. Keys must name this command's flags, plus reserved key %q for the model path when MODEL_PATH is omitted (positional wins if both are set). File paths and JSON contents are trusted input: they can set any flag the command allows. Not the same as --log-format json. CLI flags override --json.`, stdinJSONArg, maxJSONConfigFileBytes/(1<<20), JSONModelPathKey))
	_ = cmd.MarkFlagFilename("json", "json", "JSON", "txt")
}

// ResolveModelPath returns the model path: trimmed non-empty positional args[0], else JSON "model".
func (o *JSONFlags) ResolveModelPath(args []string) (string, error) {
	if len(args) > 0 {
		if p := strings.TrimSpace(args[0]); p != "" {
			return p, nil
		}
	}
	m := strings.TrimSpace(o.modelPathFromJSON)
	if m == "" {
		return "", fmt.Errorf(`model path required: pass MODEL_PATH as a positional argument or set "model" in --json`)
	}
	return m, nil
}

// ParseAndApply merges --json values into cmd flags.
func (o *JSONFlags) ParseAndApply(cmd *cobra.Command) error {
	o.modelPathFromJSON = ""
	if !o.hasJSONInput() {
		return nil
	}
	data, err := o.parseWithStdin(cmd, os.Stdin)
	if err != nil {
		return err
	}
	for k, v := range data {
		if err := applyJSONToFlag(cmd, k, v); err != nil {
			return err
		}
	}
	return nil
}

func (o *JSONFlags) hasJSONInput() bool {
	for _, s := range o.jsonInputs {
		if strings.TrimSpace(s) != "" {
			return true
		}
	}
	return false
}

func applyJSONToFlag(cmd *cobra.Command, name, value string) error {
	f := cmd.Flag(name)
	if f == nil {
		return fmt.Errorf("internal error: flag %q not found after --json parse", name)
	}
	if f.Changed {
		return nil
	}
	if err := f.Value.Set(value); err != nil {
		return fmt.Errorf("apply --json to flag %q: %w", name, err)
	}
	f.Changed = true
	return nil
}

// allowedFlagNames returns visible non-json flag long names for cmd.
func allowedFlagNames(cmd *cobra.Command) map[string]struct{} {
	names := make(map[string]struct{})
	visit := func(fs *flag.FlagSet) {
		fs.VisitAll(func(f *flag.Flag) {
			if f.Hidden {
				return
			}
			if f.Name == "json" || f.Name == helpFlagName {
				return
			}
			names[f.Name] = struct{}{}
		})
	}
	visit(cmd.Flags())
	visit(cmd.InheritedFlags())
	return names
}

const helpFlagName = "help"

func normalizeFlagKey(cmd *cobra.Command, name string) string {
	if cmd == nil {
		return name
	}
	fn := cmd.Root().GlobalNormalizationFunc()
	if fn == nil {
		return name
	}
	return string(fn(cmd.Flags(), name))
}

// parseWithStdin merges all --json inputs; rejects unknown keys and non-object payloads.
func (o *JSONFlags) parseWithStdin(cmd *cobra.Command, stdin io.Reader) (map[string]string, error) {
	allowed := allowedFlagNames(cmd)
	out := make(map[string]string)
	var stdinConsumed bool
	for _, rawIn := range o.jsonInputs {
		raw, err := materializeJSONArg(rawIn, stdin, &stdinConsumed)
		if err != nil {
			return nil, err
		}
		if raw == "" {
			continue
		}
		if !strings.HasPrefix(raw, "{") {
			return nil, errJSONObjectPayloadRequired
		}
		if err := mergeJSONObject(cmd, out, allowed, raw); err != nil {
			return nil, err
		}
	}
	if v, ok := out[JSONModelPathKey]; ok {
		o.modelPathFromJSON = strings.TrimSpace(v)
		delete(out, JSONModelPathKey)
	}
	return out, nil
}

func materializeJSONArg(rawIn string, stdin io.Reader, stdinConsumed *bool) (string, error) {
	rawIn = strings.TrimSpace(rawIn)
	if rawIn == "" {
		return "", nil
	}
	if rawIn == stdinJSONArg {
		if *stdinConsumed {
			return "", fmt.Errorf("only one --json %s can read stdin", stdinJSONArg)
		}
		b, err := io.ReadAll(stdin)
		if err != nil {
			return "", fmt.Errorf("read stdin for --json %s: %w", stdinJSONArg, err)
		}
		s := strings.TrimSpace(string(b))
		if s == "" {
			return "", fmt.Errorf("stdin for --json %s was empty", stdinJSONArg)
		}
		*stdinConsumed = true
		return s, nil
	}
	if strings.HasPrefix(rawIn, "{") {
		return rawIn, nil
	}
	b, err := readJSONConfigFile(rawIn)
	if err != nil {
		return "", err
	}
	s := strings.TrimSpace(string(b))
	if s == "" {
		return "", errors.New("--json: configuration file is empty")
	}
	return s, nil
}

// readJSONConfigFile reads a --json file path with conservative checks: clean path, reject NULs,
// require a regular file, enforce a size cap, and return generic errors on failure.
func readJSONConfigFile(userPath string) ([]byte, error) {
	if strings.IndexByte(userPath, 0) >= 0 {
		return nil, errJSONConfigFileUnreadable
	}
	path := filepath.Clean(userPath)
	fi, err := os.Stat(path)
	if err != nil {
		return nil, errJSONConfigFileUnreadable
	}
	if !fi.Mode().IsRegular() {
		return nil, errJSONConfigFileUnreadable
	}
	if fi.Size() > maxJSONConfigFileBytes {
		return nil, fmt.Errorf("--json: configuration file exceeds maximum size (%d bytes)", maxJSONConfigFileBytes)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, errJSONConfigFileUnreadable
	}
	return b, nil
}

func ensureJSONMergeKeyAllowed(nk, key string, allowed map[string]struct{}) error {
	if nk == JSONModelPathKey {
		return nil
	}
	if _, ok := allowed[nk]; !ok {
		return fmt.Errorf("%w: %q", ErrUnknownJSONFlagKey, key)
	}
	return nil
}

func mergeJSONObject(cmd *cobra.Command, dst map[string]string, allowed map[string]struct{}, raw string) error {
	var obj map[string]json.RawMessage
	if err := json.Unmarshal([]byte(raw), &obj); err != nil {
		return fmt.Errorf("invalid JSON for --json: %w", err)
	}
	if obj == nil {
		return fmt.Errorf("invalid JSON for --json: must be a JSON object")
	}
	for key, rawMsg := range obj {
		nk := normalizeFlagKey(cmd, key)
		if err := ensureJSONMergeKeyAllowed(nk, key, allowed); err != nil {
			return err
		}
		s, err := stringifyJSONValue(rawMsg)
		if err != nil {
			return fmt.Errorf("key %q: %w", key, err)
		}
		dst[nk] = s
	}
	return nil
}

func stringifyJSONValue(raw json.RawMessage) (string, error) {
	raw = json.RawMessage(bytes.TrimSpace([]byte(raw)))
	if len(raw) == 0 {
		return "", nil
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var v interface{}
	if err := dec.Decode(&v); err != nil {
		return "", err
	}
	return stringifyInterface(v)
}

func stringifyInterface(v interface{}) (string, error) {
	switch v := v.(type) {
	case string:
		return v, nil
	case json.Number:
		return v.String(), nil
	case bool:
		return strconv.FormatBool(v), nil
	case nil:
		return "", nil
	default:
		return "", fmt.Errorf("unsupported JSON value type %T", v)
	}
}
