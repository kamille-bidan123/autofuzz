package configagent

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"autofuzz/internal/runner"
)

type Report struct {
	AnalysisSummary   string   `json:"analysis_summary"`
	LibraryConfigPath string   `json:"library_config_path"`
	Evidence          []string `json:"evidence"`
}

type Result struct {
	ConfigPath    string
	Language      string
	HeaderPaths   []string
	ConsumerPaths []string
	OutputPath    string
}

type Request struct {
	Name            string
	SourceDir       string
	BuildDir        string
	InstallDir      string
	TargetDir       string
	CompileCommands string
	StaticLibraries []string
	FailureSummary  string
	LogDir          string
}

type Client struct {
	Command   string
	Model     string
	Profile   string
	Timeout   time.Duration
	Runner    runner.Runner
	EventSink func(json.RawMessage)
}

func (c Client) Generate(ctx context.Context, request Request) (Report, Result, error) {
	if c.Command == "" {
		c.Command = "codex"
	}
	if c.Timeout <= 0 {
		c.Timeout = 30 * time.Minute
	}
	if err := os.MkdirAll(request.LogDir, 0o755); err != nil {
		return Report{}, Result{}, err
	}
	schemaPath := filepath.Join(request.LogDir, "response.schema.json")
	responsePath := filepath.Join(request.LogDir, "response.json")
	if err := os.WriteFile(schemaPath, []byte(responseSchema), 0o644); err != nil {
		return Report{}, Result{}, err
	}
	prompt := buildPrompt(request)
	if err := os.WriteFile(filepath.Join(request.LogDir, "prompt.txt"), []byte(prompt), 0o644); err != nil {
		return Report{}, Result{}, err
	}
	args := []string{c.Command, "exec", "--ephemeral", "--sandbox", "workspace-write", "--ignore-rules", "--json",
		"--skip-git-repo-check", "--color", "never", "--output-schema", schemaPath,
		"--output-last-message", responsePath, "-C", request.TargetDir}
	if c.Model != "" {
		args = append(args, "--model", c.Model)
	}
	if c.Profile != "" {
		args = append(args, "--profile", c.Profile)
	}
	args = append(args, "-")
	commandCtx, cancel := context.WithTimeout(ctx, c.Timeout)
	defer cancel()
	onStdout := jsonLineSink(c.EventSink)
	if _, err := c.Runner.RunInputStreaming(commandCtx, request.LogDir, "codex", request.TargetDir, nil, prompt, onStdout, nil, args...); err != nil {
		return Report{}, Result{}, fmt.Errorf("Codex library.toml generation failed: %w", err)
	}
	data, err := os.ReadFile(responsePath)
	if err != nil {
		return Report{}, Result{}, err
	}
	var report Report
	if err := json.Unmarshal(data, &report); err != nil {
		return Report{}, Result{}, fmt.Errorf("decode Codex library report: %w", err)
	}
	result, err := ValidateConfig(report, request)
	if err != nil {
		return report, Result{}, err
	}
	return report, result, nil
}

func jsonLineSink(sink func(json.RawMessage)) func(string) {
	if sink == nil {
		return nil
	}
	return func(line string) {
		raw := json.RawMessage(strings.TrimSpace(line))
		if !json.Valid(raw) {
			return
		}
		copyOfRaw := append(json.RawMessage(nil), raw...)
		sink(copyOfRaw)
	}
}

func SaveReport(path string, report Report) error {
	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(data, '\n'), 0o644)
}

func ValidateConfig(report Report, request Request) (Result, error) {
	configPath := report.LibraryConfigPath
	if !filepath.IsAbs(configPath) {
		configPath = filepath.Join(request.TargetDir, filepath.Clean(configPath))
	}
	absolute, err := filepath.Abs(configPath)
	if err != nil {
		return Result{}, err
	}
	relative, err := filepath.Rel(request.TargetDir, absolute)
	if err != nil || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return Result{}, fmt.Errorf("library config escapes target workspace")
	}
	data, err := os.ReadFile(absolute)
	if err != nil || len(data) == 0 {
		return Result{}, fmt.Errorf("Codex did not create a nonempty library.toml")
	}
	text := string(data)
	if !strings.Contains(text, "["+request.Name+"]") && !strings.Contains(text, "[\""+request.Name+"\"]") {
		return Result{}, fmt.Errorf("library.toml has no section for %s", request.Name)
	}
	language, err := stringValue(text, "language")
	if err != nil || (language != "c" && language != "c++") {
		return Result{}, fmt.Errorf("library.toml has invalid language")
	}
	compileCommands, err := stringValue(text, "compile_commands_path")
	if err != nil || !samePath(compileCommands, request.CompileCommands) {
		return Result{}, fmt.Errorf("library.toml does not use the validated compile_commands.json")
	}
	if !regexp.MustCompile(`(?m)^document_paths\s*=\s*\[\s*\]\s*$`).MatchString(text) ||
		!regexp.MustCompile(`(?m)^document_has_api_usage\s*=\s*false\s*$`).MatchString(text) {
		return Result{}, fmt.Errorf("library.toml must disable document API usage")
	}
	outputPath, err := stringValue(text, "output_path")
	if err != nil || !within(request.TargetDir, outputPath) {
		return Result{}, fmt.Errorf("library.toml output_path is invalid")
	}
	headers, err := arrayValue(text, "header_paths")
	if err != nil || len(headers) == 0 {
		return Result{}, fmt.Errorf("library.toml needs header_paths")
	}
	for _, path := range headers {
		if _, err := os.Stat(path); err != nil {
			return Result{}, fmt.Errorf("header path does not exist: %s", path)
		}
	}
	buildArgs, err := arrayValue(text, "driver_build_args")
	if err != nil {
		return Result{}, fmt.Errorf("invalid driver_build_args")
	}
	foundLibrary := false
	for _, arg := range buildArgs {
		for _, library := range request.StaticLibraries {
			if samePath(arg, library) {
				foundLibrary = true
			}
		}
	}
	if !foundLibrary {
		return Result{}, fmt.Errorf("driver_build_args does not contain a validated static library")
	}
	consumers, err := arrayValue(text, "consumer_case_paths")
	if err != nil {
		return Result{}, fmt.Errorf("invalid consumer_case_paths")
	}
	for _, path := range consumers {
		info, err := os.Stat(path)
		if err != nil || !info.IsDir() {
			return Result{}, fmt.Errorf("consumer path is not a directory: %s", path)
		}
	}
	return Result{ConfigPath: absolute, Language: language, HeaderPaths: headers,
		ConsumerPaths: consumers, OutputPath: outputPath}, nil
}

func assignment(text, key string) (string, error) {
	pattern := regexp.MustCompile(`(?m)^` + regexp.QuoteMeta(key) + `\s*=\s*(.+?)\s*$`)
	match := pattern.FindStringSubmatch(text)
	if len(match) != 2 {
		return "", fmt.Errorf("missing %s", key)
	}
	return match[1], nil
}

func stringValue(text, key string) (string, error) {
	value, err := assignment(text, key)
	if err != nil {
		return "", err
	}
	return strconv.Unquote(value)
}

func arrayValue(text, key string) ([]string, error) {
	value, err := assignment(text, key)
	if err != nil {
		return nil, err
	}
	var result []string
	if err := json.Unmarshal([]byte(value), &result); err != nil {
		return nil, err
	}
	return result, nil
}

func samePath(left, right string) bool {
	a, errA := filepath.Abs(left)
	b, errB := filepath.Abs(right)
	return errA == nil && errB == nil && a == b
}

func within(root, path string) bool {
	absolute, err := filepath.Abs(path)
	if err != nil {
		return false
	}
	relative, err := filepath.Rel(root, absolute)
	return err == nil && relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator))
}

func buildPrompt(request Request) string {
	previous := ""
	configPath := filepath.Join(request.TargetDir, "library.toml")
	if data, err := os.ReadFile(configPath); err == nil {
		previous = string(data)
	}
	artifacts, _ := json.MarshalIndent(struct {
		CompileCommands string   `json:"compile_commands_path"`
		StaticLibraries []string `json:"static_libraries"`
		BuildDir        string   `json:"build_dir"`
		InstallDir      string   `json:"install_dir"`
	}{request.CompileCommands, request.StaticLibraries, request.BuildDir, request.InstallDir}, "", "  ")
	return fmt.Sprintf(`你负责为项目 %q 生成 PromeFuzz 的库配置。在可写目标工作区内自主工作。查阅源码、compile_commands.json、构建/安装树、公开 API、测试/示例与链接元信息，然后直接创建或修复 %s。

不要只在聊天里返回 TOML：把实际文件写出来。使用绝对路径。该文件必须包含一个 [%s] 段，以及全部 PromeFuzz 字段：language、compile_commands_path、document_paths、document_has_api_usage、output_path、header_paths、driver_build_args、consumer_case_paths、consumer_build_args、source_paths、exclude_paths、driver_headers、api_hints_path 和 api_ban_list_path。

要求：
- document_paths=[] 且 document_has_api_usage=false；
- compile_commands_path 必须严格等于下方已校验的路径；
- output_path 必须在目标工作区内；
- header_paths 必须是编译器观察到的源码/构建头文件位置，而非 AST 不一致的已安装副本；
- driver_build_args 必须至少包含下方一个已校验的静态库，外加任何真正需要的链接标志；
- consumer_case_paths 必须是包含真实 API 用法的目录；
- 其余字段由你根据证据自行决定。

已校验产物：
%s

之前的文件（若有）：
%s

最近的拒绝或预处理错误：
%s

写完文件后，自查它，并报告其相对目标工作区的路径。`, request.Name, configPath, request.Name, string(artifacts), previous, request.FailureSummary)
}

const responseSchema = `{
  "type":"object","additionalProperties":false,
  "required":["analysis_summary","library_config_path","evidence"],
  "properties":{
    "analysis_summary":{"type":"string"},
    "library_config_path":{"type":"string"},
    "evidence":{"type":"array","items":{"type":"string"}}
  }
}`
