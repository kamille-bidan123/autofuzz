package fuzzing

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"autofuzz/internal/runner"
)

// AnalysisRequest is the data sent to Codex for fuzz analysis.
type AnalysisRequest struct {
	FuzzStatus     FuzzStatus           `json:"fuzz_status"`
	CoverageStatus CorpusCoverageStatus `json:"coverage_status"`
	DriverSource   string               `json:"driver_source"`
	SourceDir      string               `json:"source_dir"` // library source (read-only)
	DriverDir      string               `json:"driver_dir"` // fuzz driver dir (Codex has write access)
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
    "analysis":{"type":"string"},
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

// Analyze sends fuzz status, coverage status, and driver source to Codex
// for analysis and returns the structured response.
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
	onStdout := jsonLineSink(c.EventSink)
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

	var resp AnalysisResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return AnalysisResponse{}, fmt.Errorf("decode Codex analysis response: %w", err)
	}

	return resp, nil
}

func buildAnalysisPrompt(req AnalysisRequest) string {
	coverageJSON, _ := json.MarshalIndent(req.CoverageStatus, "", "  ")
	fuzzJSON, _ := json.MarshalIndent(req.FuzzStatus, "", "  ")

	return fmt.Sprintf(`你是一位 fuzz 测试分析专家。

你对目标库源码 %s 有读权限。
你对 fuzz driver 目录 %s 有写权限（具体是 %s/synthesized/*.c：各个子 driver 源码 1.c、2.c …… 以及 entry.c/entry.cpp 分派器）。

下方的覆盖数据是 PER-CORPUS-SEED 的：fuzzer 没有被停止，而是把每个已保存的 corpus 输入逐个 replay 跑过带覆盖插桩的 driver。"uncovered" 列出的是从未被走过的分支；每条包含 line（行号）、function（所属函数）、condition（条件）、missing（缺失的方向）、counts（哪一侧为 0）以及 reaching_seeds：replay 时真正执行到该分支点（控制流评估过该分支）的 seed，即最接近这条卡点分支的输入。只关注 driver 已经到达却触发不了的分支：分析为何该分支条件从未被满足。

步骤：
1. 判断 fuzz 是否已到达平台期（覆盖在较长时间内停滞）。
2. 若是，阅读库源码（%s）和合一 driver（下方的 entry 文件），理解各 API 实现以及每个 driver 如何构造输入。
3. 若某个 fuzz driver 需要改进，用你的文件写入工具直接编辑 %s/synthesized/ 下的相关源文件（如 1.c）——调整输入构造 / API 调用顺序，使输入能走到未覆盖分支。不要输出 driver 号或建议文本，自己把代码改掉。
4. 仅当你确实编辑了 driver 文件时才设 needs_update=true（harness 会重新合并 entry.c 并 rebuild + 重启 fuzzer）。若没改动，needs_update=false。

## Fuzz 运行状态
%s

## 覆盖状态（逐 seed replay）
%s

## 合一 fuzz driver 源码（entry 文件）
%s

若 fuzz 未到达平台期：plateau_reached=false 且 needs_update=false。
若已到达平台期但你判断改 driver 也无济于事：plateau_reached=true 且 needs_update=false。
否则（到达平台期且你编辑了 driver）：plateau_reached=true 且 needs_update=true，并在 "analysis" 里概述你改了什么。`,
		req.SourceDir, req.DriverDir, req.DriverDir,
		req.SourceDir, req.DriverDir,
		string(fuzzJSON), string(coverageJSON), req.DriverSource)
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

func (c CodexAnalyzer) logf(format string, args ...any) {
	msg := fmt.Sprintf(format, args...)
	if c.LogSink != nil {
		c.LogSink(msg)
	}
	fmt.Println(msg)
}
