package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"autofuzz/internal/buildagent"
	"autofuzz/internal/configagent"
	"autofuzz/internal/fuzzing"
	"autofuzz/internal/promefuzz"
	"autofuzz/internal/runevent"
	"autofuzz/internal/state"
)

func (a *Agent) runRemaining(ctx context.Context) error {
	if !a.State.Stage.AtLeast(state.StageBuilt) || !validBuildArtifacts(a.State) {
		a.stageStarted(state.StageBuilt, "Codex 正在自主分析并构建目标库")
		started := time.Now()
		logDir := filepath.Join(a.LogsDir, "autonomous-build-agent")
		result, err := a.buildAgent().Build(ctx, buildagent.Request{
			SourceDir: a.State.SourceDir, TargetDir: a.TargetDir,
			Jobs: a.Options.Jobs, LogDir: logDir,
		})
		attempt := state.BuildAttempt{Name: "codex-autonomous-build", Builder: "codex", StartedAt: started, FinishedAt: time.Now(), Success: err == nil, LogDir: logDir}
		if err != nil {
			attempt.Error = err.Error()
			a.State.BuildAttempts = append(a.State.BuildAttempts, attempt)
			return a.block(state.StageBuilt, err)
		}
		a.State.BuildAttempts = append(a.State.BuildAttempts, attempt)
		reportPath := filepath.Join(a.TargetDir, "build-report.json")
		if err := buildagent.SaveReport(reportPath, result.Report); err != nil {
			return a.fail(state.StageBuilt, err)
		}
		a.State.BuildReportPath = reportPath
		a.State.BuildMethod = "codex-autonomous"
		a.State.BuildSystem = result.Report.BuildSystem
		a.State.Language = result.Report.Language
		a.State.BuildDir = result.BuildDir
		a.State.InstallDir = result.InstallDir
		a.State.CompileCommandsPath = result.CompileCommands
		a.State.StaticLibraries = result.StaticLibraries
		a.State.Stage = state.StageBuilt
		if err := a.State.Save(a.StatePath); err != nil {
			return err
		}
		a.stageCompleted(state.StageBuilt, "Codex 自主构建及产物校验完成")
		fmt.Printf("Codex autonomous build ready: %s (%d static libraries): %s\n", result.CompileCommands, len(result.StaticLibraries), result.Report.AnalysisSummary)
	}
	if a.Options.StopAfter == state.StageBuilt {
		return nil
	}
	if !a.State.Stage.AtLeast(state.StageConfigured) || !fileExists(a.State.LibraryConfigPath) {
		if err := a.configureWithCodex(ctx, 1, ""); err != nil {
			return a.fail(state.StageConfigured, err)
		}
	}
	if a.Options.StopAfter == state.StageConfigured {
		return nil
	}
	if !a.State.Stage.AtLeast(state.StagePreprocessed) || !fileExists(filepath.Join(a.State.OutputPath, "preprocessor", "api.json")) {
		a.stageStarted(state.StagePreprocessed, "PromeFuzz 正在提取 API")
		client := a.promeFuzzClient()
		assessment, err := client.Preprocess(ctx, a.State.LibraryConfigPath, min(a.Options.Jobs, 8), 1)
		if err != nil && strings.Contains(err.Error(), "zero API") {
			fmt.Printf("PromeFuzz extracted zero APIs; asking Codex to correct library.toml: %v\n", err)
			if configureErr := a.configureWithCodex(ctx, 3, err.Error()); configureErr != nil {
				return a.fail(state.StageConfigured, configureErr)
			}
			a.stageStarted(state.StagePreprocessed, "配置已修复，重新提取 API")
			assessment, err = client.Preprocess(ctx, a.State.LibraryConfigPath, min(a.Options.Jobs, 8), 2)
		}
		if err != nil {
			return a.fail(state.StagePreprocessed, err)
		}
		if assessment.Count > 1000 {
			return a.block(state.StagePreprocessed, fmt.Errorf("extracted %d APIs; header scope is too broad for safe automatic refinement", assessment.Count))
		}
		a.State.Stage = state.StagePreprocessed
		if err := a.State.Save(a.StatePath); err != nil {
			return err
		}
		a.stageCompleted(state.StagePreprocessed, fmt.Sprintf("API 预处理完成，共 %d 个 API", assessment.Count))
		fmt.Printf("PromeFuzz preprocess complete: %d APIs\n", assessment.Count)
	}
	if a.Options.StopAfter == state.StagePreprocessed {
		return nil
	}
	apiAssessment, err := promefuzz.AssessAPI(filepath.Join(a.State.OutputPath, "preprocessor", "api.json"))
	if err != nil {
		return a.fail(state.StagePreprocessed, err)
	}
	if !a.State.Stage.AtLeast(state.StageComprehended) || !fileExists(filepath.Join(a.State.OutputPath, "comprehender", "semantic_relev.pkl")) {
		a.stageStarted(state.StageComprehended, "PromeFuzz 正在执行 funcpurp 和 funcrel")
		if apiAssessment.Count > 300 {
			return a.block(state.StageComprehended, fmt.Errorf("%d APIs would make semantic relevance too expensive; narrow public headers", apiAssessment.Count))
		}
		if err := a.promeFuzzClient().Comprehend(ctx, a.State.LibraryConfigPath, a.Options.PoolSize); err != nil {
			return a.fail(state.StageComprehended, err)
		}
		a.State.Stage = state.StageComprehended
		if err := a.State.Save(a.StatePath); err != nil {
			return err
		}
		a.stageCompleted(state.StageComprehended, "API 用途和关系理解完成")
		fmt.Println("PromeFuzz comprehension complete")
	}
	if a.Options.StopAfter == state.StageComprehended {
		return nil
	}
	if a.State.GenerationTask != "allcover" || !a.State.Stage.AtLeast(state.StageGenerated) || len(findDrivers(a.State.OutputPath)) == 0 {
		a.stageStarted(state.StageGenerated, "PromeFuzz 正在调度全部 API 并生成 fuzz driver")
		clearState := a.State.GenerationTask != "allcover"
		a.State.GenerationTask = "allcover"
		a.State.GeneratedDrivers = nil
		if err := a.State.Save(a.StatePath); err != nil {
			return err
		}
		if err := a.promeFuzzClient().GenerateAllCover(ctx, a.State.LibraryConfigPath, a.Options.PoolSize, clearState); err != nil {
			return a.fail(state.StageGenerated, err)
		}
		a.State.GeneratedDrivers = findDrivers(a.State.OutputPath)
		if len(a.State.GeneratedDrivers) == 0 {
			return a.fail(state.StageGenerated, fmt.Errorf("generate returned successfully but produced no fuzz driver"))
		}
		a.State.Stage = state.StageGenerated
		if err := a.State.Save(a.StatePath); err != nil {
			return err
		}
		a.stageCompleted(state.StageGenerated, fmt.Sprintf("allcover 完成，已生成 %d 个 fuzz driver", len(a.State.GeneratedDrivers)))
		fmt.Printf("allcover generated %d fuzz driver source file(s)\n", len(a.State.GeneratedDrivers))
	}
	if a.Options.StopAfter == state.StageGenerated {
		return nil
	}
	if !a.State.Stage.AtLeast(state.StageVerified) {
		a.stageStarted(state.StageVerified, "正在验证全部 fuzz driver")
		if err := a.verifyDriver(ctx); err != nil {
			return a.fail(state.StageVerified, err)
		}
		a.State.Stage = state.StageVerified
		if err := a.State.Save(a.StatePath); err != nil {
			return err
		}
		a.stageCompleted(state.StageVerified, "全部 fuzz driver 的编译和冒烟测试通过")
		fmt.Println("all fuzz driver builds and 10-run smoke tests succeeded")
	}
	if a.Options.StopAfter == state.StageVerified {
		return nil
	}
	if !a.State.Stage.AtLeast(state.StageFuzzing) {
		a.stageStarted(state.StageFuzzing, "正在执行持续 fuzz 测试与覆盖分析")
		if err := a.runFuzzing(ctx); err != nil {
			return a.fail(state.StageFuzzing, err)
		}
		a.State.Stage = state.StageFuzzing
		if err := a.State.Save(a.StatePath); err != nil {
			return err
		}
		a.stageCompleted(state.StageFuzzing, "fuzz 测试完成")
		fmt.Println("fuzzing phase completed")
	}
	return nil
}

func (a *Agent) buildAgent() buildagent.Client {
	return buildagent.Client{
		Command: a.Options.CodexCommand, Model: a.Options.CodexModel,
		Profile: a.Options.CodexProfile, Timeout: 90 * time.Minute, Runner: a.Runner,
		EventSink: a.codexEventSink(state.StageBuilt),
	}
}

func (a *Agent) configPlanner() configagent.Client {
	return configagent.Client{
		Command: a.Options.CodexCommand, Model: a.Options.CodexModel,
		Profile: a.Options.CodexProfile, Timeout: 20 * time.Minute, Runner: a.Runner,
		EventSink: a.codexEventSink(state.StageConfigured),
	}
}

func (a *Agent) configureWithCodex(ctx context.Context, firstAttempt int, failure string) error {
	a.stageStarted(state.StageConfigured, "Codex 正在分析并直接生成 library.toml")
	var lastErr error
	for attempt := firstAttempt; attempt < firstAttempt+2; attempt++ {
		report, result, err := a.configPlanner().Generate(ctx, configagent.Request{
			Name: a.State.ProjectName, SourceDir: a.State.SourceDir,
			BuildDir: a.State.BuildDir, InstallDir: a.State.InstallDir, TargetDir: a.TargetDir,
			CompileCommands: a.State.CompileCommandsPath, StaticLibraries: a.State.StaticLibraries,
			FailureSummary: failure,
			LogDir:         filepath.Join(a.LogsDir, fmt.Sprintf("configure-agent-%02d", attempt)),
		})
		if err != nil {
			lastErr = err
			failure = err.Error()
			continue
		}
		reportPath := filepath.Join(a.TargetDir, "library-report.json")
		if err := configagent.SaveReport(reportPath, report); err != nil {
			return err
		}
		a.State.HeaderPaths = result.HeaderPaths
		a.State.ConsumerPaths = result.ConsumerPaths
		a.State.Language = result.Language
		a.State.LibraryReportPath = reportPath
		a.State.LibraryConfigPath = result.ConfigPath
		a.State.OutputPath = result.OutputPath
		a.State.Stage = state.StageConfigured
		if err := a.State.Save(a.StatePath); err != nil {
			return err
		}
		a.stageCompleted(state.StageConfigured, "library.toml 已生成并通过 Go 校验")
		fmt.Printf("Codex wrote library configuration: %s: %s\n", result.ConfigPath, report.AnalysisSummary)
		return nil
	}
	return lastErr
}

func (a *Agent) fail(stage state.Stage, err error) error {
	a.State.Stage = state.StageFailed
	a.State.RecordError(stage, err)
	_ = a.State.Save(a.StatePath)
	a.stageFailed(stage, err.Error())
	return err
}

func (a *Agent) block(stage state.Stage, err error) error {
	a.State.Stage = state.StageBlocked
	a.State.RecordError(stage, err)
	_ = a.State.Save(a.StatePath)
	a.stageFailed(stage, err.Error())
	return err
}

func validBuildArtifacts(s *state.RunState) bool {
	if info, err := os.Stat(s.CompileCommandsPath); err != nil || info.Size() == 0 {
		return false
	}
	for _, library := range s.StaticLibraries {
		if info, err := os.Stat(library); err == nil && info.Size() > 0 {
			return true
		}
	}
	return false
}

func fileExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.Size() > 0
}

func (a *Agent) promeFuzzClient() promefuzz.Client {
	return promefuzz.Client{
		Root: a.Options.PromeFuzzRoot, Python: a.Options.PythonPath,
		ConfigPath: a.Options.ConfigPath, Runner: a.Runner, LogsDir: a.LogsDir,
	}
}

func findDrivers(outputPath string) []string {
	patterns := []string{
		filepath.Join(outputPath, "fuzz_driver", "fuzz_driver_*.c"),
		filepath.Join(outputPath, "fuzz_driver", "fuzz_driver_*.cpp"),
	}
	var result []string
	for _, pattern := range patterns {
		matches, _ := filepath.Glob(pattern)
		result = append(result, matches...)
	}
	sort.Strings(result)
	return result
}

func (a *Agent) verifyDriver(ctx context.Context) error {
	driverDir := filepath.Join(a.State.OutputPath, "fuzz_driver")
	scripts, _ := filepath.Glob(filepath.Join(driverDir, "build_fuzz_driver_*.sh"))
	if len(scripts) == 0 {
		return fmt.Errorf("no generated driver build script found")
	}
	sort.Strings(scripts)
	for index, script := range scripts {
		buildLogName := fmt.Sprintf("build-%03d", index+1)
		verifyCtx, cancel := context.WithTimeout(ctx, 10*time.Minute)
		_, err := a.Runner.Run(verifyCtx, filepath.Join(a.LogsDir, "verify"), buildLogName, driverDir, nil, script)
		cancel()
		if err != nil {
			return fmt.Errorf("rebuild generated driver %s: %w", filepath.Base(script), err)
		}
		binary := strings.TrimSuffix(strings.TrimPrefix(filepath.Base(script), "build_"), ".sh")
		binaryPath := filepath.Join(driverDir, binary)
		if !fileExists(binaryPath) {
			return fmt.Errorf("driver build script %s did not produce %s", filepath.Base(script), binaryPath)
		}
		runLogName := fmt.Sprintf("smoke-%03d", index+1)
		runCtx, runCancel := context.WithTimeout(ctx, 2*time.Minute)
		_, err = a.Runner.Run(runCtx, filepath.Join(a.LogsDir, "verify"), runLogName, driverDir, nil, binaryPath, "-runs=10")
		runCancel()
		if err != nil {
			return fmt.Errorf("driver smoke test %s: %w", binary, err)
		}
	}
	return nil
}

func (a *Agent) runFuzzing(ctx context.Context) error {
	driverDir := filepath.Join(a.State.OutputPath, "fuzz_driver")
	buildScript := filepath.Join(driverDir, "build_cov_synthesized_driver.sh")
	if !fileExists(buildScript) {
		return fmt.Errorf("build_cov_synthesized_driver.sh not found in %s", driverDir)
	}
	binaryPath := filepath.Join(driverDir, "cov_synthesized_driver")
	corpusDir := filepath.Join(driverDir, "corpus")
	fuzzLogsDir := filepath.Join(a.LogsDir, "fuzzing")

	cfg := fuzzing.FuzzConfig{
		DriverDir:    driverDir,
		SourceDir:    a.State.SourceDir,
		BuildScript:  buildScript,
		BinaryPath:   binaryPath,
		CorpusDir:    corpusDir,
		Interval:     a.Options.FuzzInterval,
		CodexCommand: a.Options.CodexCommand,
		CodexModel:   a.Options.CodexModel,
		CodexProfile: a.Options.CodexProfile,
		Runner:       a.Runner,
		LogsDir:      fuzzLogsDir,
		EventSink:    a.codexEventSinkFuzzing(),
		PythonPath:   a.Options.PythonPath,
		LogSink: func(message string) {
			a.emit(runevent.New("log", string(state.StageFuzzing), "", "autofuzz", message))
		},
	}

	if cfg.Interval <= 0 {
		cfg.Interval = 30 * time.Minute
	}

	ctrl := fuzzing.StartFuzzingPhase(ctx, cfg)
	a.fuzzController = &ctrl
	err := <-ctrl.Done
	a.fuzzController = nil
	return err
}
func (a *Agent) codexEventSinkFuzzing() func(json.RawMessage) {
	return func(raw json.RawMessage) {
		message := "Codex fuzz analysis event"
		var envelope struct {
			Type string `json:"type"`
		}
		if json.Unmarshal(raw, &envelope) == nil && envelope.Type != "" {
			message = envelope.Type
		}
		event := runevent.New("codex", string(state.StageFuzzing), "", "codex-cli", message)
		event.Data = append(json.RawMessage(nil), raw...)
		a.emit(event)
	}
}

func (a *Agent) TriggerFuzzAnalysis() {
	if a.fuzzController != nil {
		a.fuzzController.TriggerAnalysis()
	}
}
