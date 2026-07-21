package fuzzing

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
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

	args := []string{c.Command, "exec", "--ephemeral", "--sandbox", "workspace-write",
		"--ignore-rules", "--json", "--skip-git-repo-check", "--color", "never",
		"--output-schema", schemaPath, "--output-last-message", responsePath}
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
	// synthesized driver sources directly. The library source (SourceDir) is
	// read via its absolute path in the prompt.
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

func buildAnalysisPrompt(req AnalysisRequest) string {
	coverageJSON, _ := json.MarshalIndent(req.CoverageStatus, "", "  ")
	fuzzJSON, _ := json.MarshalIndent(req.FuzzStatus, "", "  ")

	return fmt.Sprintf(`你是一位 fuzz 测试分析专家。

你对目标库源码 %s 有读权限。
你对 fuzz driver 目录 %s 有写权限（具体是 %s/synthesized/*.c：各个子 driver 源码 1.c、2.c …… 以及 entry.c/entry.cpp 分派器；你还可以运行该目录下的 build_cov_synthesized_driver.sh 编译脚本验证你的修改能否编译成功）。

下方的覆盖数据是 PER-CORPUS-SEED 的：fuzzer 没有被停止，而是把每个已保存的 corpus 输入逐个 replay 跑过带覆盖插桩的 driver。"uncovered" 列出的是从未被走过的分支；每条包含 line（行号）、function（所属函数）、condition（条件）、missing（缺失的方向）、counts（哪一侧为 0）以及 reaching_seeds：replay 时真正执行到该分支点（控制流评估过该分支）的 seed，即最接近这条卡点分支的输入。只关注 driver 已经到达却触发不了的分支：分析为何该分支条件从未被满足。

步骤：
1. 判断 fuzz 是否已到达平台期（覆盖在较长时间内停滞）。无论结论如何，fuzzer 都会继续运行；该信号仅用于决定本轮是否需要改 driver。
2. 若是，阅读库源码（%s）和该 fuzz driver 目录下 synthesized/ 里的 entry.c/entry.cpp 分派器及各子 driver 源码（1.c、2.c ……），理解各 API 实现以及每个 driver 如何构造输入。
3. 选择一条你想覆盖的未覆盖分支，想清楚改进理由：当前 driver 的输入构造 / API 调用顺序为什么走不到那条分支？你要怎么改？改完后预计能让哪条未覆盖分支（给出 function + line）变成覆盖？把这个因果推理想清楚，在最终回复的 "analysis" 字段里用简体中文写明。
4. 用你的文件写入工具直接编辑 %s/synthesized/ 下的相关源文件（如 1.c）——编辑前先把原文件复制一份 .bak 备份（如 cp 1.c 1.c.bak），然后再修改。调整输入构造 / API 调用顺序，使输入能走到你选定的未覆盖分支。不要输出 driver 号或建议文本，自己把代码改掉。
5. 编译验证：编辑完后，运行 %s/build_cov_synthesized_driver.sh 验证能否编译成功。如果编译失败，读错误信息、修改源码、重试。如果多次重试仍编译不通过，用 .bak 文件回退你的修改（如 cp 1.c.bak 1.c），确保源码恢复到修改前的状态，设 needs_update=false，在 "analysis" 里说明编译失败的原因和回退操作。不要留下编译不过的改动。
6. 仅当你确实编辑了 driver 文件且编译通过时才设 needs_update=true（harness 会保留当前 synthesized 目录，直接重新编译并重启 fuzzer；不会运行 synthesize_into_one）。若没改动、编译没通过（已回退）、或判断不该改，needs_update=false。

## Fuzz 运行状态
%s

## 覆盖状态（逐 seed replay）
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

func (c CodexAnalyzer) logf(format string, args ...any) {
	msg := fmt.Sprintf(format, args...)
	if c.LogSink != nil {
		c.LogSink(msg)
	}
	fmt.Println(msg)
}
