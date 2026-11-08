package promefuzz

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"autofuzz/internal/runner"
)

func writeTestFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestBuildFunctionCatalog(t *testing.T) {
	root := t.TempDir()
	pre := filepath.Join(root, "preprocessor")

	writeTestFile(t, filepath.Join(pre, "meta.json"), `{
		"classes": {}, "composites": {}, "enums": {}, "typedefs": {},
		"functions": {
			"/src/lib.c:100:1": {"name": "public_fn", "declLoc": "/include/lib.h:5:1"},
			"/src/lib.c:200:1": {"name": "internal_fn", "declLoc": ""},
			"/src/lib.c:300:1": {"name": "another_public", "declLoc": "/include/lib.h:9:1"}
		}
	}`)
	writeTestFile(t, filepath.Join(pre, "api.json"), `{
		"/include/lib.h": {
			"public_fn": [{"loc": "/src/lib.c:100:1", "decl_loc": "/include/lib.h:5:1"}],
			"another_public": [{"loc": "/src/lib.c:300:1", "decl_loc": "/include/lib.h:9:1"}]
		}
	}`)
	writeTestFile(t, filepath.Join(pre, "info.json"), `{
		"function_infos": {
			"/src/lib.c:100:1": {"signature": "void public_fn(void);"},
			"/src/lib.c:200:1": {"signature": "static void internal_fn(int);"}
		}
	}`)

	catalog, err := BuildFunctionCatalog(root)
	if err != nil {
		t.Fatal(err)
	}
	if catalog.Count != 3 || catalog.PublicCount != 2 || catalog.InternalCount != 1 {
		t.Fatalf("unexpected counts: %+v", catalog)
	}
	// public functions sort first, then alphabetically by name
	names := make([]string, 0, len(catalog.Functions))
	for _, item := range catalog.Functions {
		names = append(names, item.Name)
	}
	wantFirst := []string{"another_public", "public_fn", "internal_fn"}
	for i, want := range wantFirst {
		if names[i] != want {
			t.Fatalf("function order mismatch at %d: got %v want first %v", i, names, wantFirst)
		}
	}
	internal := catalog.Functions[2]
	if internal.File != "/src/lib.c" || internal.Loc != "/src/lib.c:200:1" || internal.Signature != "static void internal_fn(int);" {
		t.Fatalf("internal entry wrong: %+v", internal)
	}
}

func TestLocFile(t *testing.T) {
	cases := map[string]string{
		"/src/cJSON.c:1050:19": "/src/cJSON.c",
		"relative/x.c:7:2":     "relative/x.c",
		"no-colon-at-all":      "no-colon-at-all",
	}
	for input, want := range cases {
		if got := locFile(input); got != want {
			t.Fatalf("locFile(%q) = %q, want %q", input, got, want)
		}
	}
}

func TestGenerateGivenArguments(t *testing.T) {
	root := t.TempDir()
	fakePython := filepath.Join(root, "fake-python")
	if err := os.WriteFile(fakePython, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	client := Client{
		Root: root, Python: fakePython, ConfigPath: filepath.Join(root, "config.toml"),
		Runner: runner.Runner{}, LogsDir: filepath.Join(root, "logs"),
	}
	if err := client.GenerateGiven(context.Background(), filepath.Join(root, "library.toml"), 5, []string{"parse_value", "skip_utf8_bom"}, true); err != nil {
		t.Fatal(err)
	}
	commandLog, err := os.ReadFile(filepath.Join(root, "logs", "generate-given", "promefuzz.command.log"))
	if err != nil {
		t.Fatal(err)
	}
	command := string(commandLog)
	for _, expected := range []string{`"--task"`, `"given"`, `"--pool-size"`, `"5"`, `"--clear-state"`, `"parse_value"`, `"skip_utf8_bom"`} {
		if !strings.Contains(command, expected) {
			t.Fatalf("given command is missing %s: %s", expected, command)
		}
	}
}
