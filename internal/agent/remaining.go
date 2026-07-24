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
	if a.Options.TaskKind == "crash_fix_child" {
		return a.runCrashFixChild(ctx)
	}
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
		if apiAssessment.Count > 2000 {
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

func (a *Agent) runCrashFixChild(ctx context.Context) error {
	if !a.State.Stage.AtLeast(state.StageBuilt) || !validBuildArtifacts(a.State) {
		a.stageStarted(state.StageBuilt, "Codex 正在修复 crash 并编译目标库")
		started := time.Now()
		logDir := filepath.Join(a.LogsDir, "crash-fix-build-agent")
		result, err := a.buildAgent().Build(ctx, buildagent.Request{
			SourceDir: a.State.SourceDir, TargetDir: a.TargetDir,
			Jobs: a.Options.Jobs, LogDir: logDir,
			CrashFixContext: a.Options.Origin.Context,
		})
		attempt := state.BuildAttempt{Name: "codex-crash-fix-build", Builder: "codex", StartedAt: started, FinishedAt: time.Now(), Success: err == nil, LogDir: logDir}
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
		a.State.BuildMethod = "codex-crash-fix"
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
		a.stageCompleted(state.StageBuilt, "修复版库已编译完成")
	}
	if a.Options.StopAfter == state.StageBuilt {
		return nil
	}
	if !a.State.Stage.AtLeast(state.StageGenerated) || len(findDrivers(a.State.OutputPath)) == 0 {
		a.stageStarted(state.StageGenerated, "正在复用父 task 子 driver 并链接修复版库")
		if err := a.prepareCrashFixChildDriver(ctx); err != nil {
			return a.fail(state.StageGenerated, err)
		}
		a.State.GenerationTask = "crash_fix_child"
		a.State.GeneratedDrivers = findDrivers(a.State.OutputPath)
		if len(a.State.GeneratedDrivers) == 0 {
			return a.fail(state.StageGenerated, fmt.Errorf("crash fix child task produced no fuzz driver"))
		}
		a.State.Stage = state.StageGenerated
		if err := a.State.Save(a.StatePath); err != nil {
			return err
		}
		a.stageCompleted(state.StageGenerated, fmt.Sprintf("已生成修复版子 driver，共 %d 个", len(a.State.GeneratedDrivers)))
	}
	if a.Options.StopAfter == state.StageGenerated {
		return nil
	}
	if !a.State.Stage.AtLeast(state.StageFuzzing) {
		a.stageStarted(state.StageFuzzing, "正在执行修复版子 task fuzz 测试与覆盖分析")
		if err := a.runFuzzing(ctx); err != nil {
			return a.fail(state.StageFuzzing, err)
		}
		a.State.Stage = state.StageFuzzing
		if err := a.State.Save(a.StatePath); err != nil {
			return err
		}
		a.stageCompleted(state.StageFuzzing, "修复版子 task fuzz 测试完成")
	}
	return nil
}

func (a *Agent) prepareCrashFixChildDriver(ctx context.Context) error {
	origin := a.Options.Origin
	if origin.DriverID <= 0 {
		return fmt.Errorf("origin driver id is required")
	}
	if origin.SnapshotDir == "" {
		return fmt.Errorf("origin snapshot dir is required")
	}
	if len(a.State.StaticLibraries) == 0 {
		return fmt.Errorf("crash fix child task has no rebuilt static libraries")
	}
	outputPath := filepath.Join(a.TargetDir, "crash-fix-output")
	driverDir := filepath.Join(outputPath, "fuzz_driver")
	if err := os.MkdirAll(driverDir, 0o755); err != nil {
		return err
	}
	originSource, err := findOriginDriverSource(filepath.Join(origin.SnapshotDir, "driver"), origin.DriverID)
	if err != nil {
		return err
	}
	targetSource := filepath.Join(driverDir, filepath.Base(originSource))
	if err := copyFileContents(originSource, targetSource); err != nil {
		return err
	}
	scriptData, err := os.ReadFile(filepath.Join(origin.SnapshotDir, "build_cov_driver.sh"))
	if err != nil {
		return err
	}
	script := string(scriptData)
	script = replacePathSpellings(script, origin.SourceDir, a.State.SourceDir)
	script = replacePathSpellings(script, origin.BuildDir, a.State.BuildDir)
	script = replacePathSpellings(script, origin.InstallDir, a.State.InstallDir)
	script = replacePathSpellings(script, originSource, targetSource)
	script = replacePathSpellings(script, filepath.Join(origin.SnapshotDir, "cov_driver"), filepath.Join(driverDir, fmt.Sprintf("cov_fuzz_driver_%d", origin.DriverID)))
	script = rewriteStaticLibraries(script, origin.StaticLibraries, a.State.StaticLibraries)
	buildScript := filepath.Join(driverDir, fmt.Sprintf("build_fuzz_driver_%d.sh", origin.DriverID))
	if err := os.WriteFile(buildScript, []byte(script), 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(driverDir, "build_cov_synthesized_driver.sh"), []byte(script), 0o755); err != nil {
		return err
	}
	if err := copyCrashFixCorpus(origin.SnapshotDir, driverDir, origin.Crashes); err != nil {
		return err
	}
	a.State.OutputPath = outputPath
	binaryPath := filepath.Join(driverDir, fmt.Sprintf("cov_fuzz_driver_%d", origin.DriverID))
	return a.validateCrashFixChildDriver(ctx, driverDir, buildScript, binaryPath, origin.Crashes)
}

func findOriginDriverSource(driverSourceDir string, driverID int) (string, error) {
	for _, ext := range []string{".c", ".cc", ".cpp", ".cxx"} {
		path := filepath.Join(driverSourceDir, fmt.Sprintf("fuzz_driver_%d%s", driverID, ext))
		if fileExists(path) {
			return path, nil
		}
	}
	matches, _ := filepath.Glob(filepath.Join(driverSourceDir, "fuzz_driver_*"))
	sort.Strings(matches)
	for _, path := range matches {
		if info, err := os.Stat(path); err == nil && !info.IsDir() {
			return path, nil
		}
	}
	return "", fmt.Errorf("origin driver source not found in %s", driverSourceDir)
}

func replacePathSpellings(content, oldPath, newPath string) string {
	if strings.TrimSpace(oldPath) == "" || strings.TrimSpace(newPath) == "" || oldPath == newPath {
		return content
	}
	for _, old := range []string{oldPath, shellQuote(oldPath), doubleQuote(oldPath)} {
		for _, replacement := range []string{newPath, shellQuote(newPath), doubleQuote(newPath)} {
			if strings.HasPrefix(old, "'") && !strings.HasPrefix(replacement, "'") {
				continue
			}
			if strings.HasPrefix(old, "\"") && !strings.HasPrefix(replacement, "\"") {
				continue
			}
			if !strings.HasPrefix(old, "'") && !strings.HasPrefix(old, "\"") && (strings.HasPrefix(replacement, "'") || strings.HasPrefix(replacement, "\"")) {
				continue
			}
			content = strings.ReplaceAll(content, old, replacement)
		}
	}
	return content
}

func rewriteStaticLibraries(content string, oldLibraries, newLibraries []string) string {
	if len(newLibraries) == 0 {
		return content
	}
	if len(oldLibraries) == 0 {
		return content
	}
	for _, oldLibrary := range oldLibraries {
		replacement := newLibraries[0]
		for _, candidate := range newLibraries {
			if filepath.Base(candidate) == filepath.Base(oldLibrary) {
				replacement = candidate
				break
			}
		}
		content = replacePathSpellings(content, oldLibrary, replacement)
	}
	return content
}

func copyCrashFixCorpus(originSnapshotDir, driverDir string, crashes []string) error {
	corpusDir := filepath.Join(driverDir, "corpus")
	if err := os.MkdirAll(corpusDir, 0o755); err != nil {
		return err
	}
	if entries, err := os.ReadDir(filepath.Join(originSnapshotDir, "corpus")); err == nil {
		for _, entry := range entries {
			if entry.IsDir() {
				continue
			}
			_ = copyFileContents(filepath.Join(originSnapshotDir, "corpus", entry.Name()), filepath.Join(corpusDir, entry.Name()))
		}
	}
	for _, crash := range crashes {
		name := filepath.Base(crash)
		if name == "." || name == string(filepath.Separator) || strings.TrimSpace(name) == "" {
			continue
		}
		copied := false
		for _, dir := range []string{"unique_crashes", "crashes"} {
			src := filepath.Join(originSnapshotDir, dir, name)
			if pathExists(src) {
				if err := copyFileContents(src, filepath.Join(corpusDir, "regression-"+name)); err != nil {
					return err
				}
				copied = true
				break
			}
		}
		if !copied {
			return fmt.Errorf("selected crash artifact not found: %s", name)
		}
	}
	return nil
}

func (a *Agent) validateCrashFixChildDriver(ctx context.Context, driverDir, buildScript, binaryPath string, crashes []string) error {
	logDir := filepath.Join(a.LogsDir, "crash-fix-driver-validation")
	buildCtx, cancelBuild := context.WithTimeout(ctx, 10*time.Minute)
	defer cancelBuild()
	if _, err := a.Runner.Run(buildCtx, logDir, "build-driver", driverDir, nil, buildScript); err != nil {
		return fmt.Errorf("build crash-fix fuzz driver: %w", err)
	}
	if !fileExists(binaryPath) {
		return fmt.Errorf("build script did not produce %s", binaryPath)
	}
	for _, crash := range crashes {
		name := filepath.Base(crash)
		if name == "." || name == string(filepath.Separator) || strings.TrimSpace(name) == "" {
			continue
		}
		crashPath := filepath.Join(driverDir, "corpus", "regression-"+name)
		if !pathExists(crashPath) {
			return fmt.Errorf("selected crash artifact not prepared: %s", name)
		}
		replayCtx, cancelReplay := context.WithTimeout(ctx, 30*time.Second)
		_, err := a.Runner.Run(replayCtx, logDir, "replay-"+safeLogName(name), driverDir, nil, binaryPath, "-runs=1", crashPath)
		cancelReplay()
		if err != nil {
			return fmt.Errorf("selected crash still reproduces after fix (%s): %w", name, err)
		}
	}
	return nil
}

func copyFileContents(src, dst string) error {
	info, err := os.Stat(src)
	if err != nil {
		return err
	}
	data, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return err
	}
	return os.WriteFile(dst, data, info.Mode().Perm())
}

func shellQuote(path string) string {
	return "'" + strings.ReplaceAll(path, "'", "'\\''") + "'"
}

func doubleQuote(path string) string {
	return `"` + strings.ReplaceAll(path, `"`, `\"`) + `"`
}

func pathExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func safeLogName(name string) string {
	var b strings.Builder
	for _, ch := range name {
		if (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || (ch >= '0' && ch <= '9') || ch == '-' || ch == '_' || ch == '.' {
			b.WriteRune(ch)
		} else {
			b.WriteByte('_')
		}
	}
	out := strings.Trim(b.String(), "._-")
	if out == "" {
		return "crash"
	}
	if len(out) > 80 {
		out = out[:80]
	}
	return out
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
			FailureSummary:      failure,
			LogDir:              filepath.Join(a.LogsDir, fmt.Sprintf("configure-agent-%02d", attempt)),
			PromeFuzzConfigPath: a.Options.ConfigPath,
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
		DriverDir:          driverDir,
		SourceDir:          a.State.SourceDir,
		BuildDir:           a.State.BuildDir,
		BuildScript:        buildScript,
		BinaryPath:         binaryPath,
		CorpusDir:          corpusDir,
		Interval:           a.Options.FuzzInterval,
		CodexCommand:       a.Options.CodexCommand,
		CodexModel:         a.Options.CodexModel,
		CodexProfile:       a.Options.CodexProfile,
		Runner:             a.Runner,
		LogsDir:            fuzzLogsDir,
		MaxParallelDrivers: a.Options.MaxFuzzDrivers,
		DriverLocalCorpus:  a.Options.TaskKind == "crash_fix_child",
		EventSink:          a.codexEventSinkFuzzing(),
		FlowSink: func(snapshot fuzzing.FuzzFlowSnapshot) {
			data, err := json.Marshal(snapshot)
			if err != nil {
				return
			}
			event := runevent.New("fuzz_flow", string(state.StageFuzzing), snapshot.Status, "fuzz-loop", snapshot.Message)
			event.Data = data
			a.emit(event)
		},
		LogSink: func(message string) {
			a.emit(runevent.New("log", string(state.StageFuzzing), "", "autofuzz", message))
		},
		OnMonitorChanged:  a.setCorpusMonitor,
		OnCoverageChanged: a.setCoverageData,
	}

	if cfg.Interval <= 0 {
		cfg.Interval = 30 * time.Minute
	}

	ctrl := fuzzing.StartMultiFuzzingPhase(ctx, cfg)
	a.fuzzControllerMu.Lock()
	a.fuzzController = &ctrl
	a.fuzzControllerMu.Unlock()
	err := <-ctrl.Done
	a.fuzzControllerMu.Lock()
	a.fuzzController = nil
	a.fuzzControllerMu.Unlock()
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

func (a *Agent) TriggerFuzzAnalysis() bool {
	a.fuzzControllerMu.RLock()
	controller := a.fuzzController
	a.fuzzControllerMu.RUnlock()
	if controller != nil {
		return controller.TriggerAnalysis()
	}
	return false
}
