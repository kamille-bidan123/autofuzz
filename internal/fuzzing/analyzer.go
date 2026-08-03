package fuzzing

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

// AnalysisRequest is the data sent to Codex for fuzz analysis.
type AnalysisRequest struct {
	FuzzStatus     FuzzStatus           `json:"fuzz_status"`
	CoverageStatus CorpusCoverageStatus `json:"coverage_status"`
	SourceDir      string               `json:"source_dir"` // library source (read-only)
	DriverDir      string               `json:"driver_dir"` // fuzz driver dir (Codex has read+write access)
}

// AnalysisResponse is the structured output from Codex. Codex edits driver
// files directly (it has write access to DriverDir), so it does NOT report a
// driver ID or suggestion text — only whether it made edits (needs_update).
type AnalysisResponse struct {
	PlateauReached bool   `json:"plateau_reached"`
	Analysis       string `json:"analysis"`
	NeedsUpdate    bool   `json:"needs_update"`
}

type TargetBranch struct {
	File     string `json:"file"`
	Function string `json:"function"`
	Line     int    `json:"line"`
	Column   int    `json:"column"`
	Missing  string `json:"missing"`
}

type TargetAnalysisRequest struct {
	DriverID       int                  `json:"driver_id"`
	FuzzStatus     FuzzStatus           `json:"fuzz_status"`
	CoverageStatus CorpusCoverageStatus `json:"coverage_status"`
	SourceDir      string               `json:"source_dir"`
	WorkDir        string               `json:"work_dir"`
	BuildScript    string               `json:"build_script"`
	BinaryPath     string               `json:"binary_path"`
}

type TargetAnalysisResponse struct {
	NeedsUpdate   bool         `json:"needs_update"`
	TargetBranch  TargetBranch `json:"target_branch"`
	ChangedFiles  []string     `json:"changed_files"`
	ProofSeed     string       `json:"proof_seed"`
	CompilePassed bool         `json:"compile_passed"`
	BranchCovered bool         `json:"branch_covered"`
	Analysis      string       `json:"analysis"`
}

type CrashAnalysisRequest struct {
	SnapshotDir     string `json:"snapshot_dir"`
	SourceDir       string `json:"source_dir"`
	BinaryPath      string `json:"binary_path"`
	CrashPath       string `json:"crash_path"`
	UniqueCrashPath string `json:"unique_crash_path"`
	CrashFile       string `json:"crash_file"`
	CrashType       string `json:"crash_type"`
	Stack           string `json:"stack"`
	ASanReport      string `json:"asan_report"`
}

type CrashLLMReport struct {
	Classification string `json:"classification"`
	Analysis       string `json:"analysis"`
}

type DriverCrashFixRequest struct {
	DriverID       int    `json:"driver_id"`
	SourceDir      string `json:"source_dir"`
	WorkDir        string `json:"work_dir"`
	BuildScript    string `json:"build_script"`
	BinaryPath     string `json:"binary_path"`
	CrashFile      string `json:"crash_file"`
	CrashType      string `json:"crash_type"`
	UniqueCrash    string `json:"unique_crash"`
	ASanReport     string `json:"asan_report"`
	CrashAnalysis  string `json:"crash_analysis"`
}

type DriverCrashFixResponse struct {
	NeedsUpdate   bool     `json:"needs_update"`
	ChangedFiles  []string `json:"changed_files"`
	CompilePassed bool     `json:"compile_passed"`
	CrashResolved bool     `json:"crash_resolved"`
	Analysis      string   `json:"analysis"`
}

// analysisSchema defines the JSON schema for Codex output.
const analysisSchema = `{
  "type":"object","additionalProperties":false,
  "required":["plateau_reached","analysis","needs_update"],
  "properties":{
    "plateau_reached":{"type":"boolean"},
    "analysis":{"type":"string","description":"必须使用简体中文描述本轮判断、driver 修改内容、修改原因、目标分支和编译验证结果；函数名、文件名、API 名及代码标识符可保留英文"},
    "needs_update":{"type":"boolean"}
  }
}`

const targetAnalysisSchema = `{
  "type":"object","additionalProperties":false,
  "required":["needs_update","target_branch","changed_files","proof_seed","compile_passed","branch_covered","analysis"],
  "properties":{
    "needs_update":{"type":"boolean"},
    "target_branch":{
      "type":"object","additionalProperties":false,
      "required":["file","function","line","column","missing"],
      "properties":{
        "file":{"type":"string"},
        "function":{"type":"string"},
        "line":{"type":"integer"},
        "column":{"type":"integer"},
        "missing":{"type":"string"}
      }
    },
    "changed_files":{"type":"array","items":{"type":"string"}},
    "proof_seed":{"type":"string"},
    "compile_passed":{"type":"boolean"},
    "branch_covered":{"type":"boolean"},
    "analysis":{"type":"string","description":"必须使用简体中文说明平台期判断、目标未覆盖分支、driver 修改、proof seed 验证命令和结果；函数名、文件名、API 名和代码标识符可保留英文"}
  }
}`

const crashAnalysisSchema = `{
  "type":"object","additionalProperties":false,
  "required":["classification","analysis"],
  "properties":{
    "classification":{"type":"string","enum":["fuzz_driver_bug","library_bug","unknown"]},
    "analysis":{"type":"string","description":"必须使用简体中文 Markdown 文本说明复现结果、根因判断和证据；如果 classification 为 fuzz_driver_bug，必须写清楚 fuzz driver 的错误位置、错误原因以及具体修改建议；如果 classification 为 library_bug，必须包含“漏洞分析”“库代码现场”“复现程序”“修复建议”四个 Markdown 章节，且复现程序必须是单个 C 语言程序代码块"}
  }
}`

const driverCrashFixSchema = `{
  "type":"object","additionalProperties":false,
  "required":["needs_update","changed_files","compile_passed","crash_resolved","analysis"],
  "properties":{
    "needs_update":{"type":"boolean"},
    "changed_files":{"type":"array","items":{"type":"string"}},
    "compile_passed":{"type":"boolean"},
    "crash_resolved":{"type":"boolean"},
    "analysis":{"type":"string","description":"必须使用简体中文说明 fuzz driver 根因、修改点、编译命令和 replay 结果；函数名、文件名、API 名和代码标识符可保留英文"}
  }
}`

var crashAnalysisRequiredFields = []string{
	"classification",
	"analysis",
}

// CodexAnalyzer wraps the Codex CLI to analyze fuzz status.
type CodexAnalyzer struct {
	Command   string
	Model     string
	Profile   string
	Timeout   time.Duration
	Runner    runner.Runner
	EventSink func(json.RawMessage)
	LogSink   func(message string)
}

// Analyze sends fuzz status and coverage status to Codex for analysis and
// returns the structured response. Codex reads the driver sources directly
// from DriverDir (it has read access there); the entry source is NOT inlined
// into the prompt.
func (c CodexAnalyzer) Analyze(ctx context.Context, req AnalysisRequest, logDir string) (AnalysisResponse, error) {
	if c.Command == "" {
		c.Command = "codex"
	}
	if c.Timeout <= 0 {
		c.Timeout = 30 * time.Minute
	}
	if err := os.MkdirAll(logDir, 0o755); err != nil {
		return AnalysisResponse{}, err
	}

	schemaPath := filepath.Join(logDir, "response.schema.json")
	responsePath := filepath.Join(logDir, "response.json")
	if err := os.WriteFile(schemaPath, []byte(analysisSchema), 0o644); err != nil {
		return AnalysisResponse{}, err
	}

	prompt := buildAnalysisPrompt(req)
	if err := os.WriteFile(filepath.Join(logDir, "prompt.txt"), []byte(prompt), 0o644); err != nil {
		return AnalysisResponse{}, err
	}

	c.logf("[fuzzing] ===== prompt sent to Codex CLI =====\n%s\n[fuzzing] ===== end of prompt =====", prompt)

	args := codex.CommandArgv(c.Command, "exec", "--ephemeral", "--sandbox", "workspace-write",
		"--ignore-rules", "--json", "--skip-git-repo-check", "--color", "never",
		"--output-schema", schemaPath, "--output-last-message", responsePath)
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
	// Run Codex with cwd = DriverDir so its workspace-write sandbox can edit the
	// driver sources directly. The library source (SourceDir) is read via its
	// absolute path in the prompt.
	if _, err := c.Runner.RunInputStreaming(commandCtx, logDir, "codex", req.DriverDir, nil, prompt, onStdout, nil, args...); err != nil {
		return AnalysisResponse{}, fmt.Errorf("Codex fuzz analysis failed: %w", err)
	}

	data, err := os.ReadFile(responsePath)
	if err != nil {
		return AnalysisResponse{}, fmt.Errorf("read Codex analysis response: %w", err)
	}

	// Codex has no CLI flag that forces pure-JSON final-message output (the
	// configured provider does not support OpenAI strict structured outputs),
	// so despite --output-schema the model sometimes wraps the JSON in a
	// "## Analysis" heading and a ```json code fence. Extract defensively.
	payload := data
	if !json.Valid(payload) {
		if extracted := codex.ExtractJSONObject(payload); extracted != nil {
			payload = extracted
		}
	}
	var resp AnalysisResponse
	if err := json.Unmarshal(payload, &resp); err != nil {
		return AnalysisResponse{}, fmt.Errorf("decode Codex analysis response: %w", err)
	}

	return resp, nil
}

func (c CodexAnalyzer) AnalyzeTarget(ctx context.Context, req TargetAnalysisRequest, logDir string) (TargetAnalysisResponse, error) {
	if c.Command == "" {
		c.Command = "codex"
	}
	if c.Timeout <= 0 {
		c.Timeout = 30 * time.Minute
	}
	if err := os.MkdirAll(logDir, 0o755); err != nil {
		return TargetAnalysisResponse{}, err
	}

	schemaPath := filepath.Join(logDir, "response.schema.json")
	responsePath := filepath.Join(logDir, "response.json")
	if err := os.WriteFile(schemaPath, []byte(targetAnalysisSchema), 0o644); err != nil {
		return TargetAnalysisResponse{}, err
	}

	prompt := buildTargetAnalysisPrompt(req)
	if err := os.WriteFile(filepath.Join(logDir, "prompt.txt"), []byte(prompt), 0o644); err != nil {
		return TargetAnalysisResponse{}, err
	}

	c.logf("[fuzzing] ===== target prompt sent to Codex CLI =====\n%s\n[fuzzing] ===== end of target prompt =====", prompt)

	args := codex.CommandArgv(c.Command, "exec", "--ephemeral", "--sandbox", "workspace-write",
		"--ignore-rules", "--json", "--skip-git-repo-check", "--color", "never",
		"--output-schema", schemaPath, "--output-last-message", responsePath)
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
	if _, err := c.Runner.RunInputStreaming(commandCtx, logDir, "codex", req.WorkDir, nil, prompt, onStdout, nil, args...); err != nil {
		return TargetAnalysisResponse{}, fmt.Errorf("Codex target fuzz analysis failed: %w", err)
	}

	data, err := os.ReadFile(responsePath)
	if err != nil {
		return TargetAnalysisResponse{}, fmt.Errorf("read Codex target analysis response: %w", err)
	}
	payload := data
	if !json.Valid(payload) {
		if extracted := codex.ExtractJSONObject(payload); extracted != nil {
			payload = extracted
		}
	}
	var resp TargetAnalysisResponse
	if err := json.Unmarshal(payload, &resp); err != nil {
		return TargetAnalysisResponse{}, fmt.Errorf("decode Codex target analysis response: %w", err)
	}
	return resp, nil
}

func (c CodexAnalyzer) AnalyzeCrash(ctx context.Context, req CrashAnalysisRequest, logDir string) (CrashLLMReport, error) {
	if c.Command == "" {
		c.Command = "codex"
	}
	if c.Timeout <= 0 {
		c.Timeout = 30 * time.Minute
	}
	if err := os.MkdirAll(logDir, 0o755); err != nil {
		return CrashLLMReport{}, err
	}

	schemaPath := filepath.Join(logDir, "response.schema.json")
	responsePath := filepath.Join(logDir, "response.json")
	if err := os.WriteFile(schemaPath, []byte(crashAnalysisSchema), 0o644); err != nil {
		return CrashLLMReport{}, err
	}

	prompt := buildCrashAnalysisPrompt(req)
	if err := os.WriteFile(filepath.Join(logDir, "prompt.txt"), []byte(prompt), 0o644); err != nil {
		return CrashLLMReport{}, err
	}

	c.logf("[fuzzing] ===== crash prompt sent to Codex CLI =====\n%s\n[fuzzing] ===== end of crash prompt =====", prompt)

	args := codex.CommandArgv(c.Command, "exec", "--ephemeral", "--sandbox", "danger-full-access",
		"--ignore-rules", "--json", "--skip-git-repo-check", "--color", "never",
		"--output-schema", schemaPath, "--output-last-message", responsePath)
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
	if _, err := c.Runner.RunInputStreaming(commandCtx, logDir, "codex-crash", req.SnapshotDir, nil, prompt, onStdout, nil, args...); err != nil {
		return CrashLLMReport{}, fmt.Errorf("Codex crash analysis failed: %w", err)
	}

	data, err := os.ReadFile(responsePath)
	if err != nil {
		return CrashLLMReport{}, fmt.Errorf("read Codex crash analysis response: %w", err)
	}
	payload := data
	if !json.Valid(payload) {
		if extracted := codex.ExtractJSONObject(payload); extracted != nil {
			payload = extracted
		}
	}
	if err := validateCrashAnalysisPayload(payload); err != nil {
		return CrashLLMReport{}, fmt.Errorf("validate Codex crash analysis response: %w", err)
	}
	var resp CrashLLMReport
	if err := json.Unmarshal(payload, &resp); err != nil {
		return CrashLLMReport{}, fmt.Errorf("decode Codex crash analysis response: %w", err)
	}
	if err := validateCrashLLMReport(resp); err != nil {
		return CrashLLMReport{}, fmt.Errorf("validate Codex crash analysis response: %w", err)
	}
	return resp, nil
}

func (c CodexAnalyzer) AnalyzeDriverCrashFix(ctx context.Context, req DriverCrashFixRequest, logDir string) (DriverCrashFixResponse, error) {
	if c.Command == "" {
		c.Command = "codex"
	}
	if c.Timeout <= 0 {
		c.Timeout = 30 * time.Minute
	}
	if err := os.MkdirAll(logDir, 0o755); err != nil {
		return DriverCrashFixResponse{}, err
	}

	schemaPath := filepath.Join(logDir, "response.schema.json")
	responsePath := filepath.Join(logDir, "response.json")
	if err := os.WriteFile(schemaPath, []byte(driverCrashFixSchema), 0o644); err != nil {
		return DriverCrashFixResponse{}, err
	}

	prompt := buildDriverCrashFixPrompt(req)
	if err := os.WriteFile(filepath.Join(logDir, "prompt.txt"), []byte(prompt), 0o644); err != nil {
		return DriverCrashFixResponse{}, err
	}

	c.logf("[fuzzing] ===== driver crash-fix prompt sent to Codex CLI =====\n%s\n[fuzzing] ===== end of driver crash-fix prompt =====", prompt)

	args := codex.CommandArgv(c.Command, "exec", "--ephemeral", "--sandbox", "workspace-write",
		"--ignore-rules", "--json", "--skip-git-repo-check", "--color", "never",
		"--output-schema", schemaPath, "--output-last-message", responsePath)
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
	if _, err := c.Runner.RunInputStreaming(commandCtx, logDir, "codex-driver-fix", req.WorkDir, nil, prompt, onStdout, nil, args...); err != nil {
		return DriverCrashFixResponse{}, fmt.Errorf("Codex driver crash fix failed: %w", err)
	}

	data, err := os.ReadFile(responsePath)
	if err != nil {
		return DriverCrashFixResponse{}, fmt.Errorf("read Codex driver crash fix response: %w", err)
	}
	payload := data
	if !json.Valid(payload) {
		if extracted := codex.ExtractJSONObject(payload); extracted != nil {
			payload = extracted
		}
	}
	var resp DriverCrashFixResponse
	if err := json.Unmarshal(payload, &resp); err != nil {
		return DriverCrashFixResponse{}, fmt.Errorf("decode Codex driver crash fix response: %w", err)
	}
	return resp, nil
}

func validateCrashAnalysisPayload(payload []byte) error {
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(payload, &obj); err != nil {
		return err
	}
	if obj == nil {
		return fmt.Errorf("response is not a JSON object")
	}
	allowed := make(map[string]bool, len(crashAnalysisRequiredFields))
	for _, field := range crashAnalysisRequiredFields {
		allowed[field] = true
	}
	for field := range obj {
		if !allowed[field] {
			return fmt.Errorf("unexpected field %q", field)
		}
	}
	for _, field := range crashAnalysisRequiredFields {
		raw, ok := obj[field]
		if !ok {
			return fmt.Errorf("missing required field %q", field)
		}
		if strings.TrimSpace(string(raw)) == "null" {
			return fmt.Errorf("required field %q is null", field)
		}
	}
	return nil
}

func validateCrashLLMReport(resp CrashLLMReport) error {
	switch resp.Classification {
	case "fuzz_driver_bug", "library_bug", "unknown":
	default:
		return fmt.Errorf("invalid classification %q", resp.Classification)
	}
	if strings.TrimSpace(resp.Analysis) == "" {
		return fmt.Errorf("analysis is empty")
	}
	if !strings.Contains(resp.Analysis, "#") {
		return fmt.Errorf("analysis is not Markdown-formatted")
	}
	if resp.Classification == "library_bug" {
		for _, section := range []string{
			"## 漏洞分析",
			"## 库代码现场",
			"## 复现程序",
			"## 修复建议",
		} {
			if !strings.Contains(resp.Analysis, section) {
				return fmt.Errorf("library_bug analysis is missing required section %q", section)
			}
		}
		if !strings.Contains(resp.Analysis, "```c") {
			return fmt.Errorf("library_bug analysis is missing a C code block reproduction program")
		}
	}
	return nil
}

func buildAnalysisPrompt(req AnalysisRequest) string {
	coverageJSON, _ := json.MarshalIndent(req.CoverageStatus, "", "  ")
	fuzzJSON, _ := json.MarshalIndent(req.FuzzStatus, "", "  ")

	return fmt.Sprintf(`你是一位 fuzz 测试分析专家。

你对目标库源码 %s 有读权限。
你对 fuzz driver 目录 %s 有写权限（具体是 %s/synthesized/*.c：各个子 driver 源码 1.c、2.c …… 以及 entry.c/entry.cpp 分派器；你还可以运行该目录下的 build_cov_synthesized_driver.sh 编译脚本验证你的修改能否编译成功）。

下方的覆盖数据来自运行期 LLVM aggregate coverage。"uncovered" 列出的是已执行函数中仍未覆盖的分支；每条包含 file、function、line、column、condition、missing 和 counts（哪一侧为 0）。只关注 driver 已经触达但还没覆盖完整的函数/分支：分析为何该分支条件从未被满足。

步骤：
1. 判断 fuzz 是否已到达平台期（覆盖在较长时间内停滞）。无论结论如何，fuzzer 都会继续运行；该信号仅用于决定本轮是否需要改 driver。
2. 若是，阅读库源码（%s）和该 fuzz driver 目录下 synthesized/ 里的 entry.c/entry.cpp 分派器及各子 driver 源码（1.c、2.c ……），理解各 API 实现以及每个 driver 如何构造输入。
3. 选择一条你想覆盖的未覆盖分支，想清楚改进理由：当前 driver 的输入构造 / API 调用顺序为什么走不到那条分支？你要怎么改？改完后预计能让哪条未覆盖分支（给出 function + line）变成覆盖？把这个因果推理想清楚，在最终回复的 "analysis" 字段里用简体中文写明。
4. 用你的文件写入工具直接编辑 %s/synthesized/ 下的相关源文件（如 1.c）——编辑前先把原文件复制一份 .bak 备份（如 cp 1.c 1.c.bak），然后再修改。调整输入构造 / API 调用顺序，使输入能走到你选定的未覆盖分支。不要输出 driver 号或建议文本，自己把代码改掉。
5. 编译验证：编辑完后，运行 %s/build_cov_synthesized_driver.sh 验证能否编译成功。如果编译失败，读错误信息、修改源码、重试。如果多次重试仍编译不通过，用 .bak 文件回退你的修改（如 cp 1.c.bak 1.c），确保源码恢复到修改前的状态，设 needs_update=false，在 "analysis" 里说明编译失败的原因和回退操作。不要留下编译不过的改动。
6. 仅当你确实编辑了 driver 文件且编译通过时才设 needs_update=true（harness 会保留当前 synthesized 目录，直接重新编译并重启 fuzzer；不会运行 synthesize_into_one）。若没改动、编译没通过（已回退）、或判断不该改，needs_update=false。

## Fuzz 运行状态
%s

## 覆盖状态（aggregate coverage）
%s

若 fuzz 未到达平台期：plateau_reached=false 且 needs_update=false，并在 "analysis" 里用简体中文说明尚未到达平台期的判断依据。
若已到达平台期但你判断当前改 driver 也无济于事：plateau_reached=true 且 needs_update=false，并在 "analysis" 里用简体中文说明不修改的原因（fuzzer 会继续运行，下一轮分析时再次评估）。
否则（到达平台期且你编辑了 driver 并编译通过）：plateau_reached=true 且 needs_update=true，并在 "analysis" 里用简体中文概述：改了哪个 driver、为什么改（理由）、预计覆盖哪条未覆盖分支（function + line）、编译验证结果。

"analysis" 字段必须使用简体中文完整描述本轮判断和实际改动；函数名、文件名、API 名、分支条件以及代码标识符可以保留英文。不要把整段 analysis 写成英文。

最后，你的最终回复必须是且仅是一个 JSON 对象（不要在 JSON 之外输出任何文字、不要用 markdown 代码块包裹、不要写 "## Analysis" 之类的标题）。harness 会用 json.Unmarshal 直接解析你的最终消息，任何 JSON 之外的文字都会导致解析失败、你的改动不会被 rebuild。字段为：plateau_reached（布尔）、analysis（简体中文字符串）、needs_update（布尔）。`,
		req.SourceDir, req.DriverDir, req.DriverDir,
		req.SourceDir, req.DriverDir, req.DriverDir,
		string(fuzzJSON), string(coverageJSON))
}

func buildCrashAnalysisPrompt(req CrashAnalysisRequest) string {
	return fmt.Sprintf(`你是一位 crash 根因分析专家，任务是分析一个 libFuzzer unique crash。

你对 fuzz 快照目录 %s 有读权限和执行权限。当前工作目录就是这个快照目录。
你对目标库源码 %s 有读权限。不要修改库源码，不要修改 fuzz driver，不要修改 corpus/crash 输入。

快照中的关键文件：
- fuzz driver 二进制：%s
- 原始 crash 输入：%s
- dedup 后 unique crash 输入：%s
- 快照内 driver 源码通常在 driver/ 或 synthesized/ 下
- 构建脚本通常在当前快照目录下

Go 侧已经做过一次快速复现、栈去重，并把 ASan report 组装如下；默认以这些材料为准：
- crash_file: %s
- crash_type: %s
- stack_signature: %s
- asan_report:
%s

	你的任务：
	1. 直接根据上方已提供的 asan_report、crash_type、stack_signature，以及目标库源码目录和快照内 driver 源码进行根因判断；不要把重新复现作为默认步骤。
	2. 阅读快照内 fuzz driver 源码和目标库源码，确认 crash 是 fuzz_driver 使用 API/构造对象不当导致，还是库在合理输入/API 调用下的真实缺陷。
	3. 只有当 ASan report 和源码证据不足、必须补充验证时，才在当前快照目录复现 crash。复现时运行二进制加 -runs=1 和 unique crash 输入，设置 LLVM_PROFILE_FILE=/dev/null，并像 Go 侧 replay 一样先 unset DEBUGINFOD_URLS，避免 llvm-symbolizer 访问 debuginfod/debugd 导致卡顿。注意 ASan/LSan 符号化会显著拖慢运行：快速确认可用 ASAN_OPTIONS=symbolize=0；若需要符号化 top stack frames 和 SUMMARY，再切到 ASAN_OPTIONS=symbolize=1，并给 timeout 留出更长等待时间。
4. 分类只能是：
   - fuzz_driver_bug：driver 违反 API 前置条件、构造了不可能由真实调用方产生的非法对象、生命周期/回调/内存归属明显错误，或 crash 发生在 driver 自身逻辑。
   - library_bug：输入通过目标库公开/预期 API 到达库代码，driver 没有明显违反前置条件，crash 根因在库代码。
   - unknown：证据不足，无法可靠判断。
5. analysis 必须是完整的简体中文 Markdown 文本，包含 Go 侧 ASan report 的复现信息、关键证据、根因判断，以及为什么分类为 fuzz_driver_bug / library_bug / unknown。
6. 如果 classification 为 fuzz_driver_bug，analysis 必须用 Markdown 写清楚 fuzz driver 的错误位置、错误原因、为什么不是库漏洞，以及具体修改建议。
7. 如果 classification 为 library_bug，analysis 必须写成 Markdown 形式的库漏洞报告，并且必须严格包含以下二级章节：
   - ## 漏洞分析
   - ## 库代码现场
   - ## 复现程序
   - ## 修复建议
   其中“复现程序”章节必须给出一个单文件、可直接编译运行的 C 语言最小复现程序，并放在 c 代码块里（即三个反引号后跟字母 c 的 Markdown fenced code block）。
8. 如果 classification 为 unknown，analysis 必须用 Markdown 明确缺失哪些证据以及下一步需要什么验证。

	最后回复必须是且仅是一个 JSON 对象，不能有 markdown 代码块或其他文字。字段只能为：
	classification、analysis。
	不要输出 crash_file、reproduced、confidence、crash_type、asan_report、root_cause、trigger_mechanism、affected_file、affected_function、affected_line、fuzz_driver_assessment、library_vulnerability_report、evidence、recommended_action、severity、impact、title 等额外字段。analysis 必须使用简体中文 Markdown。`,
		req.SnapshotDir, req.SourceDir, req.BinaryPath, req.CrashPath, req.UniqueCrashPath,
		req.CrashFile, req.CrashType, req.Stack, req.ASanReport)
}

func buildTargetAnalysisPrompt(req TargetAnalysisRequest) string {
	coverageJSON, _ := json.MarshalIndent(req.CoverageStatus, "", "  ")
	fuzzJSON, _ := json.MarshalIndent(req.FuzzStatus, "", "  ")

	return fmt.Sprintf(`你是一位 fuzz driver 优化专家。你这次只能优化一个子 driver：driver_id=%d。

你对目标库源码 %s 有读权限。
你的工作目录是 %s。当前子 driver 源码在该目录的 driver/ 子目录下，文件名保持 PromeFuzz 原始输出形式（如 fuzz_driver_N.c/fuzz_driver_N.cpp）。你只能修改 driver/ 下的当前子 driver 源码以及当前目录的构建脚本，不要修改其他 task 文件、不要修改库源码。

当前 target 的构建脚本是 %s，编译产物必须是 %s。

下方覆盖数据只属于当前 driver，不是全局合一 driver。uncovered 列表中的每条分支包含 file、function、line、column、condition、missing 和 counts。

你的任务：
1. 判断当前 driver 是否到达平台期。本轮 Go 侧已经用硬策略选择了它，你仍需在 analysis 里说明依据。
2. 如果你判断不应该修改，直接返回 needs_update=false。
3. 如果需要修改，选择一个明确的未覆盖分支作为目标，必须填写 target_branch：file、function、line、column、missing。column 直接使用 coverage 中该分支的 column。
4. 修改 driver/ 下的当前子 driver 源码，使输入构造/API 调用顺序有机会覆盖该分支；不要新建合一 dispatcher，不要引用已经演进过的旧 synthesized driver。
5. 运行构建脚本验证编译通过。
6. 自己创建一个 proof seed 文件。proof seed 必须放在当前工作目录 %s 内，可以放在当前目录或其子目录；不要放到 /tmp、源码目录、库构建目录或其他目录。
7. 用编译后的 fuzz driver 运行 proof seed；然后用 llvm-profdata/llvm-cov 或等价命令确认 target_branch 的 missing direction 已覆盖。
8. 只有在编译通过且 proof seed 覆盖目标分支时，才能返回 needs_update=true、compile_passed=true、branch_covered=true，并填写 proof_seed 路径。proof_seed 字段必须填写当前工作目录内实际存在的 seed 文件路径，建议使用相对路径，如 proof_seed.bin 或 proofs/proof_seed.bin。
9. changed_files 字段只能列出本轮真正要推广的目标文件：driver/ 下的当前子 driver 源码文件，以及只有在确实修改过时才列出 build_cov_driver.sh。不要把 proof seed、profraw、profdata、日志、coverage 输出、临时文件或任何验证产物写入 changed_files。

如果编译失败、无法构造 proof seed、无法证明目标分支覆盖，必须回滚自己的修改并返回 needs_update=false。

## Fuzz 运行状态
%s

## 当前 Driver 覆盖状态
%s

最后回复必须是且仅是一个 JSON 对象，不能有 markdown 代码块或其他文字。不要输出 driver_id；当前 driver 已由 Go 侧固定为 driver_id=%d。analysis 必须使用简体中文。`,
		req.DriverID, req.SourceDir, req.WorkDir, req.BuildScript, req.BinaryPath, req.WorkDir,
		string(fuzzJSON), string(coverageJSON), req.DriverID)
}

func buildDriverCrashFixPrompt(req DriverCrashFixRequest) string {
	return fmt.Sprintf(`你是一位 fuzz driver 修复专家。当前只能修复一个子 driver：driver_id=%d。

你对目标库源码 %s 有读权限。
你的工作目录是 %s。当前子 driver 源码在 workdir/driver/ 下，构建脚本是 %s，编译产物必须是 %s。
你只能修改当前 workdir/driver/ 下的该子 driver 源码，以及当前目录的 build_cov_driver.sh；不要修改库源码，不要修改 crash 输入，不要修改其他 task 文件。

当前这个 unique crash 已经被上游分析为 fuzz_driver_bug。你需要根据 crash 分析、ASan 报告和 driver 源码，修复 driver 违反 API 前置条件/对象生命周期/调用顺序的问题。

已知信息：
- crash_file: %s
- crash_type: %s
- unique crash 输入: %s
- ASan report:
%s

- 上游 crash 分析（Markdown）：
%s

你的任务：
1. 阅读当前 workdir/driver/ 下的 driver 源码、构建脚本，以及必要的目标库源码，确认 fuzz_driver_bug 的根因。
2. 如果你认为无需修改，返回 needs_update=false，并在 analysis 中说明原因。
3. 如果需要修改，只能改当前 driver 文件和 build_cov_driver.sh。
4. 修改后运行构建脚本验证编译通过。
5. 用编译后的 fuzz driver 运行：<binary> -runs=1 <unique crash 输入>，确认该 crash 不再复现。
6. 只有在你确实修改了允许的文件、编译通过、并且 replay 不再 crash 时，才能返回 needs_update=true、compile_passed=true、crash_resolved=true。
7. changed_files 只能列出真正修改过的 driver 源码文件，以及只有在确实修改过时才列出 build_cov_driver.sh。不要把日志、profraw、profdata、临时文件写入 changed_files。
8. 如果编译失败，或者 replay 仍然 crash，或者你无法稳定修复，必须回滚自己的修改并返回 needs_update=false；analysis 中写清楚失败原因。

最后回复必须是且仅是一个 JSON 对象，不能有 markdown 代码块或其他文字。字段只能为：
needs_update、changed_files、compile_passed、crash_resolved、analysis。
analysis 必须使用简体中文。`,
		req.DriverID, req.SourceDir, req.WorkDir, req.BuildScript, req.BinaryPath,
		req.CrashFile, req.CrashType, req.UniqueCrash, req.ASanReport, req.CrashAnalysis)
}

func (c CodexAnalyzer) logf(format string, args ...any) {
	msg := fmt.Sprintf(format, args...)
	if c.LogSink != nil {
		c.LogSink(msg)
	}
	fmt.Println(msg)
}
