package buildagent

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"autofuzz/internal/codex"
	"autofuzz/internal/runner"
)

type Report struct {
	AnalysisSummary     string   `json:"analysis_summary"`
	BuildSystem         string   `json:"build_system"`
	Language            string   `json:"language"`
	BuildDir            string   `json:"build_dir"`
	InstallDir          string   `json:"install_dir"`
	CompileCommandsPath string   `json:"compile_commands_path"`
	StaticLibraries     []string `json:"static_libraries"`
	Evidence            []string `json:"evidence"`
}

type Result struct {
	Report          Report
	BuildDir        string
	InstallDir      string
	CompileCommands string
	StaticLibraries []string
}

type Request struct {
	SourceDir string
	TargetDir string
	Jobs      int
	LogDir    string
	CrashFixContext string
}

type Client struct {
	Command   string
	Model     string
	Profile   string
	Timeout   time.Duration
	Runner    runner.Runner
	EventSink func(json.RawMessage)
}

func (c Client) Build(ctx context.Context, request Request) (Result, error) {
	if c.Command == "" {
		c.Command = "codex"
	}
	if c.Timeout <= 0 {
		c.Timeout = 90 * time.Minute
	}
	if err := os.MkdirAll(request.LogDir, 0o755); err != nil {
		return Result{}, err
	}
	schemaPath := filepath.Join(request.LogDir, "response.schema.json")
	responsePath := filepath.Join(request.LogDir, "response.json")
	if err := os.WriteFile(schemaPath, []byte(responseSchema), 0o644); err != nil {
		return Result{}, err
	}
	prompt := buildPrompt(request)
	if err := os.WriteFile(filepath.Join(request.LogDir, "prompt.txt"), []byte(prompt), 0o644); err != nil {
		return Result{}, err
	}
	args := codex.CommandArgv(c.Command, "exec", "--ephemeral", "--sandbox", "workspace-write", "--ignore-rules", "--json",
		"--skip-git-repo-check", "--color", "never", "--output-schema", schemaPath,
		"--output-last-message", responsePath, "-C", request.TargetDir)
	if c.Model != "" {
		args = append(args, "--model", c.Model)
	}
	if c.Profile != "" {
		args = append(args, "--profile", c.Profile)
	}
	args = append(args, "-")
	commandCtx, cancel := context.WithTimeout(ctx, c.Timeout)
	defer cancel()
	onStdout := codex.JSONLineSink(c.EventSink)
	if _, err := c.Runner.RunInputStreaming(commandCtx, request.LogDir, "codex", request.TargetDir, nil, prompt, onStdout, nil, args...); err != nil {
		return Result{}, fmt.Errorf("Codex autonomous build failed: %w", err)
	}
	data, err := os.ReadFile(responsePath)
	if err != nil {
		return Result{}, fmt.Errorf("read Codex build report: %w", err)
	}
	payload := data
	if !json.Valid(payload) {
		if extracted := codex.ExtractJSONObject(payload); extracted != nil {
			payload = extracted
		}
	}
	var report Report
	if err := json.Unmarshal(payload, &report); err != nil {
		return Result{}, fmt.Errorf("decode Codex build report: %w", err)
	}
	return ValidateReport(report, request.TargetDir)
}

func SaveReport(path string, report Report) error {
	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(data, '\n'), 0o644)
}

func ValidateReport(report Report, targetDir string) (Result, error) {
	if report.Language != "c" && report.Language != "c++" {
		return Result{}, fmt.Errorf("unsupported language %q", report.Language)
	}
	if report.BuildSystem == "" {
		return Result{}, fmt.Errorf("build system is empty")
	}
	buildDir, err := resolveWithin(targetDir, report.BuildDir)
	if err != nil {
		return Result{}, fmt.Errorf("build_dir: %w", err)
	}
	installDir, err := resolveWithin(targetDir, report.InstallDir)
	if err != nil {
		return Result{}, fmt.Errorf("install_dir: %w", err)
	}
	compileCommands, err := resolveWithin(targetDir, report.CompileCommandsPath)
	if err != nil {
		return Result{}, fmt.Errorf("compile_commands_path: %w", err)
	}
	data, err := os.ReadFile(compileCommands)
	if err != nil || len(data) == 0 {
		return Result{}, fmt.Errorf("compile_commands.json is missing or empty")
	}
	var commands []struct {
		Command   string   `json:"command"`
		Arguments []string `json:"arguments"`
	}
	if json.Unmarshal(data, &commands) != nil || len(commands) == 0 {
		return Result{}, fmt.Errorf("compile_commands.json is invalid")
	}
	hasASan := false
	for _, command := range commands {
		if strings.Contains(command.Command+" "+strings.Join(command.Arguments, " "), "-fsanitize=address") {
			hasASan = true
			break
		}
	}
	if !hasASan {
		return Result{}, fmt.Errorf("compile_commands.json does not contain AddressSanitizer flags")
	}
	if len(report.StaticLibraries) == 0 {
		return Result{}, fmt.Errorf("no static libraries reported")
	}
	var libraries []string
	for _, value := range report.StaticLibraries {
		path, err := resolveWithin(targetDir, value)
		if err != nil {
			return Result{}, fmt.Errorf("static library: %w", err)
		}
		info, err := os.Stat(path)
		if err != nil || info.IsDir() || info.Size() == 0 || filepath.Ext(path) != ".a" {
			return Result{}, fmt.Errorf("invalid static library %s", path)
		}
		libraries = append(libraries, path)
	}
	return Result{Report: report, BuildDir: buildDir, InstallDir: installDir,
		CompileCommands: compileCommands, StaticLibraries: libraries}, nil
}

func resolveWithin(root, value string) (string, error) {
	path := value
	if !filepath.IsAbs(path) {
		path = filepath.Join(root, filepath.Clean(path))
	}
	absolute, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	relative, err := filepath.Rel(root, absolute)
	if err != nil || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("path escapes target workspace: %q", value)
	}
	if _, err := os.Stat(absolute); err != nil {
		return "", fmt.Errorf("path does not exist: %s", absolute)
	}
	return absolute, nil
}

func buildPrompt(request Request) string {
	crashFix := ""
	if strings.TrimSpace(request.CrashFixContext) != "" {
		crashFix = fmt.Sprintf(`

本次构建是 crash 修复子任务。请先根据以下 crash 上下文修改目标库源码副本，修复根因后再完成构建。必须只修改当前工作区内的源码和构建文件，不要修改 fuzz driver。

Crash 修复上下文：
%s
`, request.CrashFixContext)
	}
	return fmt.Sprintf(`你是 Autofuzz 的自主构建负责人。不可信的目标源码副本位于 %s（在你可写的工作区 %s 内）。

全权负责分析并构建这个 C/C++ 库。查阅 README、CI、构建文件、源码、测试与示例。运行任何必要的本地构建命令，自行诊断失败、调整选项并重试，直到构建成功。你只能修改这个一次性目标工作区。绝不要访问网络、安装软件包，或触碰工作区之外的路径。
%s

结果要求：
- 使用 clang/clang++；
- 库代码用 AddressSanitizer、调试信息和帧指针编译；优先用 fuzzer-no-link；必须加 -fprofile-instr-generate -fcoverage-mapping（LLVM source-based coverage，供后续 fuzzing 阶段的 llvm-cov 分析使用）；
- 产出非空的 compile_commands.json，内容为 ASan 编译命令；
- 至少产出一个非测试用途的静态 .a 库；
- 支持时优先使用 out-of-tree 构建，并安装到工作区自有目录；
- 除非为了理解或打通库构建，否则不要构建测试、示例、benchmark 和共享库；
- 最多使用 %d 个并行任务。

不要只提出命令：自己执行构建、检查错误并验证产物。所有产物路径都须相对工作区根目录。只报告确实存在的产物。

最后，你的最终回复必须是且仅是一个 JSON 对象（不要在 JSON 之外输出任何文字、不要用 markdown 代码块包裹），字段为：analysis_summary（字符串，概述你做了什么）、build_system（字符串，如 cmake/make/meson/autotools）、language（字符串，"c" 或 "c++"）、build_dir（字符串，相对工作区根目录）、install_dir（字符串，相对工作区根目录）、compile_commands_path（字符串，相对工作区根目录）、static_libraries（字符串数组，至少一个相对工作区根目录的 .a 路径）、evidence（字符串数组，关键证据/校验结果）。`, request.SourceDir, request.TargetDir, crashFix, request.Jobs)
}

const responseSchema = `{
  "type":"object","additionalProperties":false,
  "required":["analysis_summary","build_system","language","build_dir","install_dir","compile_commands_path","static_libraries","evidence"],
  "properties":{
    "analysis_summary":{"type":"string"},
    "build_system":{"type":"string"},
    "language":{"type":"string","enum":["c","c++"]},
    "build_dir":{"type":"string"},
    "install_dir":{"type":"string"},
    "compile_commands_path":{"type":"string"},
    "static_libraries":{"type":"array","minItems":1,"items":{"type":"string"}},
    "evidence":{"type":"array","items":{"type":"string"}}
  }
}`
