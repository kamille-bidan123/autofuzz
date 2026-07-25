package configagent

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/pelletier/go-toml/v2"

	"autofuzz/internal/codex"
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
	args := codex.CommandArgv(c.Command, "exec", "--ephemeral", "--sandbox", "workspace-write",
		"-c", "sandbox_workspace_write.network_access=true",
		"--ignore-rules", "--json",
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
		return Report{}, Result{}, fmt.Errorf("Codex library.toml generation failed: %w", err)
	}
	data, err := os.ReadFile(responsePath)
	if err != nil {
		return Report{}, Result{}, err
	}
	payload := data
	if !json.Valid(payload) {
		if extracted := codex.ExtractJSONObject(payload); extracted != nil {
			payload = extracted
		}
	}
	var report Report
	if err := json.Unmarshal(payload, &report); err != nil {
		return Report{}, Result{}, fmt.Errorf("decode Codex library report: %w", err)
	}
	result, err := ValidateConfig(report, request)
	if err != nil {
		return report, Result{}, err
	}
	return report, result, nil
}

func SaveReport(path string, report Report) error {
	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(data, '\n'), 0o644)
}

// libraryConfigTable mirrors the [<project>] section of a PromeFuzz
// library.toml. Only the fields Autofuzz validates are modeled; the decoder
// ignores unknown keys such as consumer_build_args or source_paths.
type libraryConfigTable struct {
	Language            string   `toml:"language"`
	CompileCommandsPath string   `toml:"compile_commands_path"`
	DocumentPaths       []string `toml:"document_paths"`
	DocumentHasAPIUsage bool     `toml:"document_has_api_usage"`
	OutputPath          string   `toml:"output_path"`
	HeaderPaths         []string `toml:"header_paths"`
	DriverBuildArgs     []string `toml:"driver_build_args"`
	ConsumerCasePaths   []string `toml:"consumer_case_paths"`
	ExcludePaths        []string `toml:"exclude_paths"`
	APIBanListPath      string   `toml:"api_ban_list_path"`
	APIHintsPath        string   `toml:"api_hints_path"`
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
	var tables map[string]libraryConfigTable
	if err := toml.Unmarshal(data, &tables); err != nil {
		return Result{}, fmt.Errorf("library.toml is not valid TOML: %w", err)
	}
	cfg, ok := tables[request.Name]
	if !ok {
		return Result{}, fmt.Errorf("library.toml has no section for %s", request.Name)
	}
	if cfg.Language != "c" && cfg.Language != "c++" {
		return Result{}, fmt.Errorf("library.toml has invalid language")
	}
	if !samePath(cfg.CompileCommandsPath, request.CompileCommands) {
		return Result{}, fmt.Errorf("library.toml does not use the validated compile_commands.json")
	}
	if cfg.DocumentHasAPIUsage {
		if len(cfg.DocumentPaths) == 0 {
			return Result{}, fmt.Errorf("library.toml has document_has_api_usage=true but document_paths is empty")
		}
		for _, p := range cfg.DocumentPaths {
			if err := validateDocPath(p, cfg.ExcludePaths); err != nil {
				return Result{}, fmt.Errorf("document_paths entry is invalid: %w", err)
			}
		}
	} else if len(cfg.DocumentPaths) > 0 {
		return Result{}, fmt.Errorf("library.toml has document_has_api_usage=false but document_paths is non-empty")
	}
	if !within(request.TargetDir, cfg.OutputPath) {
		return Result{}, fmt.Errorf("library.toml output_path is invalid")
	}
	if len(cfg.HeaderPaths) == 0 {
		return Result{}, fmt.Errorf("library.toml needs header_paths")
	}
	for _, path := range cfg.HeaderPaths {
		if _, err := os.Stat(path); err != nil {
			return Result{}, fmt.Errorf("header path does not exist: %s", path)
		}
	}
	foundLibrary := false
	for _, arg := range cfg.DriverBuildArgs {
		for _, library := range request.StaticLibraries {
			if samePath(arg, library) {
				foundLibrary = true
			}
		}
	}
	if !foundLibrary {
		return Result{}, fmt.Errorf("driver_build_args does not contain a validated static library")
	}
	for _, path := range cfg.ConsumerCasePaths {
		info, err := os.Stat(path)
		if err != nil || !info.IsDir() {
			return Result{}, fmt.Errorf("consumer path is not a directory: %s", path)
		}
	}
	if cfg.APIBanListPath != "" {
		var banList []string
		if err := validateJSONFile(cfg.APIBanListPath, &banList); err != nil {
			return Result{}, fmt.Errorf("api_ban_list_path points to %w", err)
		}
	}
	if cfg.APIHintsPath != "" {
		var hints map[string]any
		if err := validateJSONFile(cfg.APIHintsPath, &hints); err != nil {
			return Result{}, fmt.Errorf("api_hints_path points to %w", err)
		}
	}
	return Result{ConfigPath: absolute, Language: cfg.Language, HeaderPaths: cfg.HeaderPaths,
		ConsumerPaths: cfg.ConsumerCasePaths, OutputPath: cfg.OutputPath}, nil
}

// validateJSONFile ensures path points to an existing file whose content is
// valid JSON decodable into target. PromeFuzz json.load's api_ban_list_path
// and api_hints_path with no graceful handling for empty/invalid files, so an
// empty placeholder file crashes the whole preprocess stage. The empty-string
// sentinel (the PromeFuzz convention for "unused") is handled by the caller.
func validateJSONFile(path string, target interface{}) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("a missing or unreadable file (%s): %w", path, err)
	}
	if len(bytes.TrimSpace(data)) == 0 {
		return fmt.Errorf("an empty file (%s); set the path to \"\" when unused, or write valid JSON", path)
	}
	if err := json.Unmarshal(data, target); err != nil {
		return fmt.Errorf("invalid JSON (%s): %w", path, err)
	}
	return nil
}

// validateDocPath accepts a URL or an existing local file/directory, and rejects
// empty local documents that PromeFuzz's RAG loader cannot embed.
func validateDocPath(p string, excludePaths []string) error {
	if u, err := url.Parse(p); err == nil && u.Scheme != "" && u.Host != "" {
		return nil
	}
	info, err := os.Stat(p)
	if err != nil {
		return fmt.Errorf("neither an existing local path nor a valid URL: %s", p)
	}
	if !info.IsDir() {
		return validateNonEmptyDocumentFile(p)
	}
	return filepath.WalkDir(p, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			return nil
		}
		if !isPromeFuzzDocumentFile(entry.Name()) || pathExcluded(path, excludePaths) {
			return nil
		}
		if err := validateNonEmptyDocumentFile(path); err != nil {
			return fmt.Errorf("directory %s contains %w", p, err)
		}
		return nil
	})
}

func validateNonEmptyDocumentFile(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("unreadable document file %s: %w", path, err)
	}
	if len(bytes.TrimSpace(data)) == 0 {
		return fmt.Errorf("empty document file %s", path)
	}
	return nil
}

func isPromeFuzzDocumentFile(name string) bool {
	switch strings.ToLower(filepath.Ext(name)) {
	case ".md", ".txt", ".html", ".htm", ".pdf", ".adoc", ".rst":
		return true
	}
	switch name {
	case "README", "readme", "USAGE", "usage":
		return true
	}
	return false
}

func pathExcluded(path string, excludePaths []string) bool {
	absolute, err := filepath.Abs(path)
	if err != nil {
		return false
	}
	for _, excludePath := range excludePaths {
		excludeAbs, err := filepath.Abs(excludePath)
		if err != nil {
			continue
		}
		relative, err := filepath.Rel(excludeAbs, absolute)
		if err == nil && relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
			return true
		}
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
  document_paths 的每一项必须是已存在的本地文件/目录，或合法的 http(s) URL；不要包含空文件或只有空白字符的本地文档（如空的 *.txt/README），PromeFuzz RAG 无法为这类文档生成 embedding。
- compile_commands_path 必须严格等于下方已校验的路径；
- output_path 必须在目标工作区内；
- header_paths 是 PromeFuzz 的 API 提取范围，不是普通编译 -I 列表。只填写声明公开、外部可用、值得 fuzz 的 API 的头文件或最小公开头目录。优先列出具体 public header 文件；只有当目录下几乎全是公开 API 头时才填写目录。不要把源码根目录、build/config 目录、compat 目录、私有/internal 头目录、仅用于编译的 include 搜索路径放入 header_paths。若源码头和 install/include 头内容一致，优先使用与 compile_commands/AST 对应的源码或构建树头；不要使用 AST 路径不一致的安装副本；
- driver_build_args 必须至少包含下方一个已校验的静态库，外加任何真正需要的链接标志；编译 driver 所需的 -I 路径应放入 driver_build_args 或 consumer_build_args，而不是 header_paths；
- driver_headers 只用于生成 driver 时额外 include，不决定 API 提取范围；可填聚合头或必要公共依赖头，优先使用绝对路径，不要放私有/internal 头；
- consumer_case_paths 必须是包含真实 API 用法的目录；
- api_ban_list_path 和 api_hints_path：不用时必须设为空字符串 ""（PromeFuzz 的约定，会跳过加载）；使用时必须指向一个已存在、内容为合法 JSON 的文件。绝不要创建空占位文件——空文件不是合法 JSON，会让 PromeFuzz 在 json.load 时崩溃。api_ban_list_path 必须是字符串数组（形如 ["source/header.h:42:6"]，表示被禁函数定位）；api_hints_path 必须是对象（函数名→提示字符串）。
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
