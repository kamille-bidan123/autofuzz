package configagent

import (
	"os"
	"path/filepath"
	"testing"
)

func TestValidateConfig(t *testing.T) {
	root := t.TempDir()
	include := filepath.Join(root, "source", "include")
	if err := os.MkdirAll(include, 0o755); err != nil {
		t.Fatal(err)
	}
	library := filepath.Join(root, "libsample.a")
	compile := filepath.Join(root, "compile_commands.json")
	if err := os.WriteFile(library, []byte("archive"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(compile, []byte("[]"), 0o644); err != nil {
		t.Fatal(err)
	}
	config := filepath.Join(root, "library.toml")
	content := "[sample]\nlanguage = \"c\"\ncompile_commands_path = \"" + compile + "\"\ndocument_paths = []\ndocument_has_api_usage = false\noutput_path = \"" + filepath.Join(root, "out") + "\"\nheader_paths = [\"" + include + "\"]\ndriver_build_args = [\"" + library + "\"]\nconsumer_case_paths = []\nconsumer_build_args = []\nsource_paths = []\nexclude_paths = []\ndriver_headers = []\napi_hints_path = \"\"\napi_ban_list_path = \"\"\n"
	if err := os.WriteFile(config, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	result, err := ValidateConfig(Report{LibraryConfigPath: "library.toml"}, Request{Name: "sample", TargetDir: root, CompileCommands: compile, StaticLibraries: []string{library}})
	if err != nil {
		t.Fatal(err)
	}
	if result.Language != "c" || len(result.HeaderPaths) != 1 {
		t.Fatalf("unexpected result: %#v", result)
	}
}
