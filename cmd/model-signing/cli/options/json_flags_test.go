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
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"
	flag "github.com/spf13/pflag"
)

func TestJSONFlags_ResolveModelPath(t *testing.T) {
	j := NewJSONFlags()
	j.modelPathFromJSON = "/from-json"
	got, err := j.ResolveModelPath(nil)
	if err != nil || got != "/from-json" {
		t.Fatalf("ResolveModelPath(nil) = %q, %v", got, err)
	}
	got, err = j.ResolveModelPath([]string{"/pos"})
	if err != nil || got != "/pos" {
		t.Fatalf("ResolveModelPath(pos) = %q, %v", got, err)
	}
	got, err = j.ResolveModelPath([]string{"  /trimmed  "})
	if err != nil || got != "/trimmed" {
		t.Fatalf("ResolveModelPath(trimmed pos) = %q, %v", got, err)
	}
	got, err = j.ResolveModelPath([]string{""})
	if err != nil || got != "/from-json" {
		t.Fatalf("ResolveModelPath(empty pos) = %q, %v; want JSON path", got, err)
	}
	got, err = j.ResolveModelPath([]string{"  \t "})
	if err != nil || got != "/from-json" {
		t.Fatalf("ResolveModelPath(whitespace pos) = %q, %v; want JSON path", got, err)
	}
	j.modelPathFromJSON = ""
	_, err = j.ResolveModelPath(nil)
	if err == nil {
		t.Fatal("expected error when no path")
	}
	_, err = j.ResolveModelPath([]string{""})
	if err == nil {
		t.Fatal("expected error when positional empty and no JSON model")
	}
}

func TestJSONFlags_ParseAndApply_satisfiesRequired(t *testing.T) {
	root := &cobra.Command{Use: "root", TraverseChildren: true, SilenceUsage: true}
	jso := NewJSONFlags()
	jso.AddPersistentFlags(root)
	sub := &cobra.Command{
		Use:          "sub",
		SilenceUsage: true,
		RunE: func(_ *cobra.Command, _ []string) error {
			return nil
		},
	}
	sub.Flags().String("signature", "", "")
	_ = sub.MarkFlagRequired("signature")
	root.AddCommand(sub)
	root.PersistentPreRunE = func(cmd *cobra.Command, _ []string) error {
		return jso.ParseAndApply(cmd)
	}
	root.SetArgs([]string{"sub", "--json", `{"signature":"/tmp/x"}`})
	if err := root.Execute(); err != nil {
		t.Fatal(err)
	}
}

func TestMaterializeJSONArg_stdin(t *testing.T) {
	var consumed bool
	got, err := materializeJSONArg("-", strings.NewReader(`  {"a": 1}  `), &consumed)
	if err != nil {
		t.Fatal(err)
	}
	if got != `{"a": 1}` {
		t.Fatalf("got %q", got)
	}
	if !consumed {
		t.Fatal("expected stdin consumed")
	}
}

func TestMaterializeJSONArg_secondStdinFails(t *testing.T) {
	var consumed bool
	_, err := materializeJSONArg("-", strings.NewReader(`{}`), &consumed)
	if err != nil {
		t.Fatal(err)
	}
	_, err = materializeJSONArg("-", strings.NewReader(`{}`), &consumed)
	if err == nil {
		t.Fatal("expected error on second --json -")
	}
}

func TestMaterializeJSONArg_emptyStdin(t *testing.T) {
	var consumed bool
	_, err := materializeJSONArg("-", strings.NewReader("  \n  "), &consumed)
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestMaterializeJSONArg_stdinExceedsMaxSize(t *testing.T) {
	var consumed bool
	big := strings.NewReader(strings.Repeat("x", int(maxJSONConfigFileBytes)+1))
	_, err := materializeJSONArg("-", big, &consumed)
	if err == nil {
		t.Fatal("expected error for oversized stdin")
	}
	if !strings.Contains(err.Error(), "exceeds maximum size") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestMaterializeJSONArg_filePath(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "opts.txt")
	if err := os.WriteFile(p, []byte(`  {"a": 1}  `), 0o600); err != nil {
		t.Fatal(err)
	}
	var consumed bool
	got, err := materializeJSONArg(p, strings.NewReader(""), &consumed)
	if err != nil {
		t.Fatal(err)
	}
	if got != `{"a": 1}` {
		t.Fatalf("got %q", got)
	}
}

func TestMaterializeJSONArg_fileMissing(t *testing.T) {
	var consumed bool
	_, err := materializeJSONArg(filepath.Join(t.TempDir(), "nope.json"), strings.NewReader(""), &consumed)
	if err == nil {
		t.Fatal("expected error")
	}
	if !errors.Is(err, errJSONConfigFileUnreadable) {
		t.Fatalf("got %v", err)
	}
}

func TestMaterializeJSONArg_fileIsDir(t *testing.T) {
	var consumed bool
	_, err := materializeJSONArg(t.TempDir(), strings.NewReader(""), &consumed)
	if err == nil {
		t.Fatal("expected error")
	}
	if !errors.Is(err, errJSONConfigFileUnreadable) {
		t.Fatalf("got %v", err)
	}
}

func TestMaterializeJSONArg_fileExceedsMaxSize(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "huge.json")
	if err := os.WriteFile(p, bytes.Repeat([]byte("a"), maxJSONConfigFileBytes+1), 0o600); err != nil {
		t.Fatal(err)
	}
	var consumed bool
	_, err := materializeJSONArg(p, strings.NewReader(""), &consumed)
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "exceeds maximum size") {
		t.Fatalf("got %v", err)
	}
}

func TestMaterializeJSONArg_fileEmpty(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "empty.json")
	if err := os.WriteFile(p, []byte("  \n  "), 0o600); err != nil {
		t.Fatal(err)
	}
	var consumed bool
	_, err := materializeJSONArg(p, strings.NewReader(""), &consumed)
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestJSONFlags_parseWithStdin_fileThenInlineMerge(t *testing.T) {
	cmd := &cobra.Command{}
	cmd.Flags().String("signature", "", "")

	dir := t.TempDir()
	p := filepath.Join(dir, "first.json")
	if err := os.WriteFile(p, []byte(`{"model":"/fromfile"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	j := &JSONFlags{jsonInputs: []string{p, `{"signature":"/inline"}`}}
	data, err := j.parseWithStdin(cmd, strings.NewReader(""))
	if err != nil {
		t.Fatal(err)
	}
	got, rerr := j.ResolveModelPath(nil)
	if rerr != nil || got != "/fromfile" {
		t.Fatalf("ResolveModelPath(nil) = %q, %v", got, rerr)
	}
	if data["signature"] != "/inline" {
		t.Fatalf("got %#v", data)
	}
}

func TestJSONFlags_parseWithStdin_fileContentNotObject(t *testing.T) {
	cmd := &cobra.Command{}
	cmd.Flags().String("signature", "", "")
	dir := t.TempDir()
	p := filepath.Join(dir, "arr.json")
	if err := os.WriteFile(p, []byte(`[1,2]`), 0o600); err != nil {
		t.Fatal(err)
	}
	j := &JSONFlags{jsonInputs: []string{p}}
	_, err := j.parseWithStdin(cmd, strings.NewReader(""))
	if err == nil {
		t.Fatal("expected error")
	}
	if !errors.Is(err, errJSONObjectPayloadRequired) {
		t.Fatalf("got %v", err)
	}
}

func TestJSONFlags_parseWithStdin_JSONObject(t *testing.T) {
	cmd := &cobra.Command{}
	cmd.Flags().String("signature", "", "sig path")

	j := &JSONFlags{jsonInputs: []string{"-"}}
	stdin := strings.NewReader(`{"signature":"/tmp/model.sig"}`)
	data, err := j.parseWithStdin(cmd, stdin)
	if err != nil {
		t.Fatal(err)
	}
	if data["signature"] != "/tmp/model.sig" {
		t.Fatalf("got %#v", data)
	}
}

func TestJSONFlags_parseWithStdin_keyValueFormRejected(t *testing.T) {
	cmd := &cobra.Command{}
	cmd.Flags().String("log_level", "", "")

	j := &JSONFlags{jsonInputs: []string{"-"}}
	stdin := strings.NewReader(`log_level=debug`)
	_, err := j.parseWithStdin(cmd, stdin)
	if err == nil {
		t.Fatal("expected error: key=value is not supported")
	}
	if !errors.Is(err, errJSONObjectPayloadRequired) {
		t.Fatalf("got %v", err)
	}
}

func TestJSONFlags_parseWithStdin_inlineUnchanged(t *testing.T) {
	cmd := &cobra.Command{}
	cmd.Flags().String("signature", "", "")

	j := &JSONFlags{jsonInputs: []string{`{"signature":"/inline"}`}}
	data, err := j.parseWithStdin(cmd, strings.NewReader(""))
	if err != nil {
		t.Fatal(err)
	}
	if data["signature"] != "/inline" {
		t.Fatalf("got %#v", data)
	}
}

func TestJSONFlags_parseWithStdin_modelKeyReserved(t *testing.T) {
	cmd := &cobra.Command{}
	cmd.Flags().String("signature", "", "")

	j := &JSONFlags{jsonInputs: []string{`{"model":"/m","signature":"/s"}`}}
	data, err := j.parseWithStdin(cmd, strings.NewReader(""))
	if err != nil {
		t.Fatal(err)
	}
	got, rerr := j.ResolveModelPath(nil)
	if rerr != nil || got != "/m" {
		t.Fatalf("ResolveModelPath(nil) = %q, %v", got, rerr)
	}
	if _, ok := data[JSONModelPathKey]; ok {
		t.Fatalf("model should not remain in data map: %#v", data)
	}
	if data["signature"] != "/s" {
		t.Fatalf("got %#v", data)
	}
}

func TestJSONFlags_parseWithStdin_mergeTwoJSONObjects(t *testing.T) {
	cmd := &cobra.Command{}
	cmd.Flags().String("signature", "", "")

	j := &JSONFlags{jsonInputs: []string{`{"model":"/fromkv"}`, `{"signature":"/sig"}`}}
	data, err := j.parseWithStdin(cmd, strings.NewReader(""))
	if err != nil {
		t.Fatal(err)
	}
	got, rerr := j.ResolveModelPath(nil)
	if rerr != nil || got != "/fromkv" {
		t.Fatalf("ResolveModelPath(nil) = %q, %v", got, rerr)
	}
	if data["signature"] != "/sig" {
		t.Fatalf("got %#v", data)
	}
}

func TestJSONFlags_parseWithStdin_unknownKeyStillFails(t *testing.T) {
	cmd := &cobra.Command{}
	j := &JSONFlags{jsonInputs: []string{`{"model":"/m","not-a-flag":1}`}}
	_, err := j.parseWithStdin(cmd, strings.NewReader(""))
	if err == nil {
		t.Fatal("expected unknown key error")
	}
	if !errors.Is(err, ErrUnknownJSONFlagKey) {
		t.Fatalf("got %v", err)
	}
}

func TestJSONFlags_parseWithStdin_arrayStringSlice(t *testing.T) {
	cmd := &cobra.Command{}
	cmd.Flags().String("ignore-paths", "", "")

	j := &JSONFlags{jsonInputs: []string{`{"ignore-paths":["/tmp/a","/tmp/b"]}`}}
	data, err := j.parseWithStdin(cmd, strings.NewReader(""))
	if err != nil {
		t.Fatal(err)
	}
	if data["ignore-paths"] != "/tmp/a,/tmp/b" {
		t.Fatalf("expected comma-joined array, got %q", data["ignore-paths"])
	}
}

func TestJSONFlags_parseWithStdin_arrayNonStringFails(t *testing.T) {
	cmd := &cobra.Command{}
	cmd.Flags().String("ignore-paths", "", "")

	j := &JSONFlags{jsonInputs: []string{`{"ignore-paths":[1, {}]}`}}
	_, err := j.parseWithStdin(cmd, strings.NewReader(""))
	if err == nil {
		t.Fatal("expected error for array with non-string element")
	}
}

func TestApplyJSONToFlag_CLIFlagWins(t *testing.T) {
	cmd := &cobra.Command{}
	cmd.Flags().String("signature", "default.sig", "sig path")
	// Simulate the user passing --signature on the CLI
	if err := cmd.Flags().Set("signature", "cli.sig"); err != nil {
		t.Fatal(err)
	}

	// applyJSONToFlag should not overwrite the CLI-set value
	if err := applyJSONToFlag(cmd, "signature", "json.sig"); err != nil {
		t.Fatal(err)
	}
	val, _ := cmd.Flags().GetString("signature")
	if val != "cli.sig" {
		t.Fatalf("expected CLI value %q to win, got %q", "cli.sig", val)
	}
}

func TestApplyJSONToFlag_JSONAppliesWhenNoExplicitCLI(t *testing.T) {
	cmd := &cobra.Command{}
	cmd.Flags().String("signature", "default.sig", "sig path")

	if err := applyJSONToFlag(cmd, "signature", "json.sig"); err != nil {
		t.Fatal(err)
	}
	val, _ := cmd.Flags().GetString("signature")
	if val != "json.sig" {
		t.Fatalf("expected JSON value %q, got %q", "json.sig", val)
	}
}

func TestNormalizeFlagKey_UnderscoreToHyphen(t *testing.T) {
	cmd := &cobra.Command{}
	cmd.SetGlobalNormalizationFunc(func(_ *flag.FlagSet, name string) flag.NormalizedName {
		return flag.NormalizedName(strings.ReplaceAll(name, "_", "-"))
	})
	cmd.Flags().String("ignore-paths", "", "")

	j := &JSONFlags{jsonInputs: []string{`{"ignore_paths":"a,b"}`}}
	data, err := j.parseWithStdin(cmd, strings.NewReader(""))
	if err != nil {
		t.Fatal(err)
	}
	if data["ignore-paths"] != "a,b" {
		t.Fatalf("expected underscore key normalized to hyphen, got %v", data)
	}
}

func TestStringifyJSONValue_Bool(t *testing.T) {
	got, err := stringifyJSONValue([]byte(`true`))
	if err != nil {
		t.Fatal(err)
	}
	if got != "true" {
		t.Fatalf("expected %q, got %q", "true", got)
	}
	got, err = stringifyJSONValue([]byte(`false`))
	if err != nil {
		t.Fatal(err)
	}
	if got != "false" {
		t.Fatalf("expected %q, got %q", "false", got)
	}
}

func TestStringifyJSONValue_Null(t *testing.T) {
	got, err := stringifyJSONValue([]byte(`null`))
	if err != nil {
		t.Fatal(err)
	}
	if got != "" {
		t.Fatalf("expected empty string for null, got %q", got)
	}
}

func TestStringifyJSONValue_UnsupportedType(t *testing.T) {
	_, err := stringifyJSONValue([]byte(`{"nested": "object"}`))
	if err == nil {
		t.Fatal("expected error for unsupported type")
	}
	if !strings.Contains(err.Error(), "unsupported JSON value type") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestJSONFlags_parseWithStdin_duplicateNormalizedKeyFails(t *testing.T) {
	cmd := &cobra.Command{}
	cmd.SetGlobalNormalizationFunc(func(_ *flag.FlagSet, name string) flag.NormalizedName {
		return flag.NormalizedName(strings.ReplaceAll(name, "_", "-"))
	})
	cmd.Flags().String("ignore-paths", "", "")

	j := &JSONFlags{jsonInputs: []string{`{"ignore_paths":"a","ignore-paths":"b"}`}}
	_, err := j.parseWithStdin(cmd, strings.NewReader(""))
	if err == nil {
		t.Fatal("expected duplicate key error")
	}
	if !errors.Is(err, ErrDuplicateJSONFlagKey) {
		t.Fatalf("expected ErrDuplicateJSONFlagKey, got: %v", err)
	}
}
