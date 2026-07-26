package fuzzing

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestAnalysisPromptRequiresSimplifiedChineseAnalysis(t *testing.T) {
	prompt := buildAnalysisPrompt(AnalysisRequest{})
	for _, requirement := range []string{
		`"analysis" 字段必须使用简体中文完整描述本轮判断和实际改动`,
		`analysis（简体中文字符串）`,
		`尚未到达平台期的判断依据`,
		`不修改的原因`,
		`保留当前 synthesized 目录`,
		`不会运行 synthesize_into_one`,
	} {
		if !strings.Contains(prompt, requirement) {
			t.Fatalf("prompt is missing Chinese analysis requirement %q", requirement)
		}
	}
	if !strings.Contains(analysisSchema, `必须使用简体中文描述`) {
		t.Fatal("analysis schema does not require a Simplified Chinese description")
	}
}

func TestCrashAnalysisPromptRequiresCrashClassification(t *testing.T) {
	prompt := buildCrashAnalysisPrompt(CrashAnalysisRequest{
		SnapshotDir:     "/task/logs/fuzzing/driver-targets/driver-0003/v001",
		SourceDir:       "/task/source/lib",
		BinaryPath:      "/task/logs/fuzzing/driver-targets/driver-0003/v001/cov_driver",
		CrashPath:       "/task/logs/fuzzing/driver-targets/driver-0003/v001/crashes/crash-a",
		UniqueCrashPath: "/task/logs/fuzzing/driver-targets/driver-0003/v001/unique_crashes/crash-a",
		CrashFile:       "crash-a",
		CrashType:       "heap-buffer-overflow",
		Stack:           "stack: lib_fn <- LLVMFuzzerTestOneInput",
		ASanReport:      "ERROR: AddressSanitizer: heap-buffer-overflow\nSUMMARY: AddressSanitizer: heap-buffer-overflow lib.c:42",
	})
	for _, requirement := range []string{
		`有读权限和执行权限`,
		`asan_report`,
		`默认以这些材料为准`,
		`不要把重新复现作为默认步骤`,
		`必须补充验证时`,
		`unset DEBUGINFOD_URLS`,
		`fuzz_driver_bug`,
		`library_bug`,
		`unknown`,
		`ASAN_OPTIONS=symbolize=0`,
		`ASAN_OPTIONS=symbolize=1`,
		`给 timeout 留出更长等待时间`,
		`如果 classification 为 fuzz_driver_bug`,
		`analysis 必须是完整的简体中文 Markdown 文本`,
		`## 漏洞分析`,
		`## 库代码现场`,
		`## 复现程序`,
		`## 修复建议`,
		`三个反引号后跟字母 c`,
		`具体修改建议`,
		`最后回复必须是且仅是一个 JSON 对象`,
		`classification、analysis`,
		`不要输出 crash_file`,
	} {
		if !strings.Contains(prompt, requirement) {
			t.Fatalf("crash prompt is missing requirement %q", requirement)
		}
	}
	for _, field := range []string{
		`crash_file`,
		`reproduced`,
		`confidence`,
		`crash_type`,
		`asan_report`,
		`root_cause`,
		`trigger_mechanism`,
		`affected_file`,
		`affected_function`,
		`affected_line`,
		`fuzz_driver_assessment`,
		`library_vulnerability_report`,
		`reproduction_steps`,
		`evidence`,
		`recommended_action`,
	} {
		if strings.Contains(crashAnalysisSchema, field) {
			t.Fatalf("crash schema should not include %s", field)
		}
	}
	if !strings.Contains(crashAnalysisSchema, `"classification"`) || !strings.Contains(crashAnalysisSchema, `"library_bug"`) || !strings.Contains(crashAnalysisSchema, `"analysis"`) {
		t.Fatal("crash schema does not require a classification enum")
	}
	if !strings.Contains(crashAnalysisSchema, `Markdown`) || !strings.Contains(crashAnalysisSchema, `漏洞分析`) {
		t.Fatal("crash schema does not require Markdown library bug sections")
	}
}

func TestValidateCrashAnalysisPayloadRejectsPartialResponse(t *testing.T) {
	payload := []byte(`{
		"analysis":"只返回分析正文"
	}`)

	err := validateCrashAnalysisPayload(payload)
	if err == nil || !strings.Contains(err.Error(), `missing required field "classification"`) {
		t.Fatalf("validateCrashAnalysisPayload() error = %v, want missing classification", err)
	}
}

func TestValidateCrashAnalysisPayloadAcceptsCompleteResponse(t *testing.T) {
	payload := []byte("{\n" +
		"  \"classification\":\"library_bug\",\n" +
		"  \"analysis\":\"## 漏洞分析\\n这是库缺陷。\\n\\n## 库代码现场\\n问题出在边界检查缺失。\\n\\n## 复现程序\\n```c\\nint main(void) { return 0; }\\n```\\n\\n## 修复建议\\n补充边界检查。\"\n" +
		"}")

	if err := validateCrashAnalysisPayload(payload); err != nil {
		t.Fatalf("validateCrashAnalysisPayload(): %v", err)
	}
	var report CrashLLMReport
	if err := json.Unmarshal(payload, &report); err != nil {
		t.Fatalf("unmarshal report: %v", err)
	}
	if err := validateCrashLLMReport(report); err != nil {
		t.Fatalf("validateCrashLLMReport(): %v", err)
	}
}

func TestValidateCrashLLMReportRejectsNonMarkdownAnalysis(t *testing.T) {
	report := CrashLLMReport{
		Classification: "unknown",
		Analysis:       "这是纯文本，没有 markdown 标题。",
	}
	err := validateCrashLLMReport(report)
	if err == nil || !strings.Contains(err.Error(), "Markdown") {
		t.Fatalf("validateCrashLLMReport() error = %v, want Markdown rejection", err)
	}
}

func TestValidateCrashLLMReportRejectsLibraryBugMissingSections(t *testing.T) {
	report := CrashLLMReport{
		Classification: "library_bug",
		Analysis:       "## 漏洞分析\n有漏洞。\n\n## 修复建议\n修复它。",
	}
	err := validateCrashLLMReport(report)
	if err == nil || !strings.Contains(err.Error(), "## 库代码现场") {
		t.Fatalf("validateCrashLLMReport() error = %v, want missing section rejection", err)
	}
}

func TestValidateCrashAnalysisPayloadRejectsExtraFields(t *testing.T) {
	payload := []byte(`{
		"classification":"library_bug",
		"asan_report":"SUMMARY: AddressSanitizer: stack-buffer-overflow",
		"analysis":"这是库缺陷。"
	}`)

	err := validateCrashAnalysisPayload(payload)
	if err == nil || !strings.Contains(err.Error(), `unexpected field "asan_report"`) {
		t.Fatalf("validateCrashAnalysisPayload() error = %v, want unexpected asan_report", err)
	}
}
