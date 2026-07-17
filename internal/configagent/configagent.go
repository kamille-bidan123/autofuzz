package configagent

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
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
	Name                string
	SourceDir           string
	BuildDir            string
	InstallDir          string
	TargetDir           string
	CompileCommands     string
	StaticLibraries     []string
	FailureSummary      string
	LogDir              string
	PromeFuzzConfigPath string // path to PromeFuzz config.toml (for the embed model config)
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
	args := []string{c.Command, "exec", "--ephemeral", "--sandbox", "workspace-write",
		"-c", "sandbox_workspace_write.network_access=true",
		"--ignore-rules", "--json",
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
	hasDocUsage, err := boolValue(text, "document_has_api_usage")
	if err != nil {
		return Result{}, fmt.Errorf("library.toml has invalid document_has_api_usage")
	}
	docPaths, err := arrayValue(text, "document_paths")
	if err != nil {
		return Result{}, fmt.Errorf("library.toml has invalid document_paths")
	}
	if hasDocUsage {
		if len(docPaths) == 0 {
			return Result{}, fmt.Errorf("library.toml has document_has_api_usage=true but document_paths is empty")
		}
		for _, p := range docPaths {
			if !validDocPath(p) {
				return Result{}, fmt.Errorf("document_paths entry is neither an existing local path nor a valid URL: %s", p)
			}
		}
	} else if len(docPaths) > 0 {
		return Result{}, fmt.Errorf("library.toml has document_has_api_usage=false but document_paths is non-empty")
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
	re := regexp.MustCompile(`(?m)^` + regexp.QuoteMeta(key) + `\s*=\s*`)
	loc := re.FindStringIndex(text)
	if loc == nil {
		return nil, fmt.Errorf("missing %s", key)
	}
	rest := text[loc[1]:]
	start := strings.IndexByte(rest, '[')
	if start < 0 {
		return nil, fmt.Errorf("missing '[' for %s", key)
	}
	// Scan for the matching ']', respecting double-quoted strings so a ']'
	// inside a path/URL does not end the array prematurely. This also handles
	// multi-line TOML arrays.
	inStr, esc, end := false, false, -1
	for i := start + 1; i < len(rest); i++ {
		c := rest[i]
		if inStr {
			if esc {
				esc = false
			} else if c == '\\' {
				esc = true
			} else if c == '"' {
				inStr = false
			}
		} else if c == '"' {
			inStr = true
		} else if c == ']' {
			end = i
			break
		}
	}
	if end < 0 {
		return nil, fmt.Errorf("missing ']' for %s", key)
	}
	var result []string
	if err := json.Unmarshal([]byte(rest[start:end+1]), &result); err != nil {
		return nil, err
	}
	return result, nil
}

func boolValue(text, key string) (bool, error) {
	value, err := assignment(text, key)
	if err != nil {
		return false, err
	}
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "true":
		return true, nil
	case "false":
		return false, nil
	}
	return false, fmt.Errorf("invalid boolean value %q for %s", value, key)
}

// validDocPath accepts an http(s) URL or an existing local file/directory.
func validDocPath(p string) bool {
	if u, err := url.Parse(p); err == nil && u.Scheme != "" && u.Host != "" {
		return true
	}
	if _, err := os.Stat(p); err == nil {
		return true
	}
	return false
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
- 关于文档检索（document_paths / document_has_api_usage）按以下流程决定：
  1) 读取 PromeFuzz 配置 %s，找到 [comprehender] 段的 embedding_llm=<名>，再找到对应的 [llm.<名>] 段（含 llm_type / base_url / model / api_key / max_tokens）。
  2) 若没有 embed 模型配置（embedding_llm 为空，或对应的 [llm.*] 段缺失）：保持 document_paths=[] 且 document_has_api_usage=false。
  3) 若有 embed 配置：在工作区写一个 curl 脚本，向 <base_url>/embeddings 发 POST 请求，body 为 {"model":"<model>","input":"test"}，按需带 Authorization/api_key 头，并运行它。
     - 若返回 HTTP 200 且响应体是合法的 OpenAI embeddings 格式（含 embedding 向量数组）：设 document_has_api_usage=true，并填充 document_paths——须同时包含源码目录里已有的本地文档（README*、docs/、*.md、*.txt、*.rst、*.html、*.pdf 等的绝对路径，可递归整目录），以及用 web_search 工具找到的该库官方文档 URL。
     - 否则（连接失败 / 非 200 / 响应格式错误）：回退 document_paths=[] 且 document_has_api_usage=false，并在 analysis 里简述失败原因。
  document_paths 的每一项必须是已存在的本地文件/目录，或合法的 http(s) URL。
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

写完文件后，自查它，并报告其相对目标工作区的路径。

最后，你的最终回复必须是且仅是一个 JSON 对象（不要在 JSON 之外输出任何文字、不要用 markdown 代码块包裹），字段为：analysis_summary（字符串，概述你做了什么，须包含 embed 测试结果与 document_paths / document_has_api_usage 的决定依据）、library_config_path（字符串，所写 library.toml 相对目标工作区的路径）、evidence（字符串数组，关键证据/校验结果）。`, request.Name, configPath, request.Name, request.PromeFuzzConfigPath, string(artifacts), previous, request.FailureSummary)
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
