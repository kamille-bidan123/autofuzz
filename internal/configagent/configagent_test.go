package configagent

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestValidateConfigToleratesTrailingCommas(t *testing.T) {
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
	// Trailing commas after every array's last element — Codex emits these
	// regularly. A real TOML parser accepts them; the old JSON-based hack did not.
	content := "[sample]\nlanguage = \"c\"\ncompile_commands_path = \"" + compile + "\"\ndocument_paths = [\"" + include + "\",]\ndocument_has_api_usage = true\noutput_path = \"" + filepath.Join(root, "out") + "\"\nheader_paths = [\"" + include + "\",]\ndriver_build_args = [\"" + library + "\",]\nconsumer_case_paths = [\"" + root + "\",]\n"
	if err := os.WriteFile(config, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	result, err := ValidateConfig(Report{LibraryConfigPath: "library.toml"}, Request{Name: "sample", TargetDir: root, CompileCommands: compile, StaticLibraries: []string{library}})
	if err != nil {
		t.Fatalf("ValidateConfig rejected valid TOML with trailing commas: %v", err)
	}
	if len(result.HeaderPaths) != 1 || len(result.ConsumerPaths) != 1 {
		t.Fatalf("unexpected result: %#v", result)
	}
}

func TestValidateConfigRejectsInvalidTOML(t *testing.T) {
	root := t.TempDir()
	config := filepath.Join(root, "library.toml")
	if err := os.WriteFile(config, []byte("[sample\nlanguage = c\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := ValidateConfig(Report{LibraryConfigPath: "library.toml"}, Request{Name: "sample", TargetDir: root})
	if err == nil {
		t.Fatal("expected malformed TOML to be rejected")
	}
}

func TestValidateConfigRejectsEmptyDocumentFiles(t *testing.T) {
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
	emptyDoc := filepath.Join(root, "source", "pending_code_changes.txt")
	if err := os.WriteFile(emptyDoc, []byte("\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	config := filepath.Join(root, "library.toml")
	content := "[sample]\nlanguage = \"c\"\ncompile_commands_path = \"" + compile + "\"\ndocument_paths = [\"" + emptyDoc + "\"]\ndocument_has_api_usage = true\noutput_path = \"" + filepath.Join(root, "out") + "\"\nheader_paths = [\"" + include + "\"]\ndriver_build_args = [\"" + library + "\"]\nconsumer_case_paths = []\n"
	if err := os.WriteFile(config, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := ValidateConfig(Report{LibraryConfigPath: "library.toml"}, Request{Name: "sample", TargetDir: root, CompileCommands: compile, StaticLibraries: []string{library}})
	if err == nil || !strings.Contains(err.Error(), "empty document file") {
		t.Fatalf("expected empty document file rejection, got: %v", err)
	}
}

func TestValidateConfigBanListPath(t *testing.T) {
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
	emptyBan := filepath.Join(root, "ban_empty.json")
	if err := os.WriteFile(emptyBan, []byte(""), 0o644); err != nil {
		t.Fatal(err)
	}
	validBan := filepath.Join(root, "ban_valid.json")
	if err := os.WriteFile(validBan, []byte(`["source/header.h:42:6"]`), 0o644); err != nil {
		t.Fatal(err)
	}
	malformedBan := filepath.Join(root, "ban_bad.json")
	if err := os.WriteFile(malformedBan, []byte("not json"), 0o644); err != nil {
		t.Fatal(err)
	}

	base := func(banPath string) string {
		return "[sample]\nlanguage = \"c\"\ncompile_commands_path = \"" + compile + "\"\ndocument_paths = []\ndocument_has_api_usage = false\noutput_path = \"" + filepath.Join(root, "out") + "\"\nheader_paths = [\"" + include + "\"]\ndriver_build_args = [\"" + library + "\"]\nconsumer_case_paths = []\napi_ban_list_path = \"" + banPath + "\"\napi_hints_path = \"\"\n"
	}
	req := func() (Report, Request) {
		return Report{LibraryConfigPath: "library.toml"}, Request{Name: "sample", TargetDir: root, CompileCommands: compile, StaticLibraries: []string{library}}
	}

	cases := map[string]struct {
		banPath string
		wantErr bool
	}{
		"empty_file":     {emptyBan, true},
		"malformed_json": {malformedBan, true},
		"valid_array":    {validBan, false},
	}
	for name, tc := range cases {
		config := filepath.Join(root, "library_"+name+".toml")
		if err := os.WriteFile(config, []byte(base(tc.banPath)), 0o644); err != nil {
			t.Fatal(err)
		}
		r, q := req()
		_, err := ValidateConfig(Report{LibraryConfigPath: "library_" + name + ".toml"}, q)
		if tc.wantErr && err == nil {
			t.Fatalf("%s: expected rejection, got nil", name)
		}
		if !tc.wantErr && err != nil {
			t.Fatalf("%s: expected acceptance, got: %v", name, err)
		}
		_ = r
	}
}

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

func TestBuildPromptDescribesHeaderPathsAsAPIScope(t *testing.T) {
	prompt := buildPrompt(Request{
		Name:                "sample",
		TargetDir:           t.TempDir(),
		PromeFuzzConfigPath: "/tmp/promefuzz/config.toml",
		CompileCommands:     "/tmp/sample/compile_commands.json",
		StaticLibraries:     []string{"/tmp/sample/libsample.a"},
	})

	for _, want := range []string{
		"header_paths 是 PromeFuzz 的 API 提取范围，不是普通编译 -I 列表",
		"优先列出具体 public header 文件",
		"仅用于编译的 include 搜索路径放入 header_paths",
		"编译 driver 所需的 -I 路径应放入 driver_build_args 或 consumer_build_args",
		"driver_headers 只用于生成 driver 时额外 include，不决定 API 提取范围",
	} {
		if !strings.Contains(prompt, want) {
			t.Fatalf("prompt missing %q:\n%s", want, prompt)
		}
	}
	if strings.Contains(prompt, "header_paths 必须是编译器观察到的源码/构建头文件位置") {
		t.Fatalf("prompt still contains the old include-path-oriented header_paths instruction:\n%s", prompt)
	}
}
