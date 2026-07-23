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
		`fuzz_driver_bug`,
		`library_bug`,
		`unknown`,
		`library_vulnerability_report 必须写成详细漏洞报告`,
		`ASAN_OPTIONS=symbolize=0`,
		`ASAN_OPTIONS=symbolize=1`,
		`先用 ASAN_OPTIONS=symbolize=0 快速确认`,
		`给 timeout 留出更长等待时间`,
		`最后回复必须是且仅是一个 JSON 对象`,
		`不要输出 severity`,
	} {
		if !strings.Contains(prompt, requirement) {
			t.Fatalf("crash prompt is missing requirement %q", requirement)
		}
	}
	if !strings.Contains(crashAnalysisSchema, `"classification"`) || !strings.Contains(crashAnalysisSchema, `"library_bug"`) || !strings.Contains(crashAnalysisSchema, `"asan_report"`) {
		t.Fatal("crash schema does not require a classification enum")
	}
}

func TestValidateCrashAnalysisPayloadRejectsPartialResponse(t *testing.T) {
	payload := []byte(`{
		"analysis":"只返回分析正文",
		"crash_type":"leak",
		"asan_report":"SUMMARY: AddressSanitizer: leaked",
		"fuzz_driver_assessment":"",
		"library_vulnerability_report":"report"
	}`)

	err := validateCrashAnalysisPayload(payload)
	if err == nil || !strings.Contains(err.Error(), `missing required field "crash_file"`) {
		t.Fatalf("validateCrashAnalysisPayload() error = %v, want missing crash_file", err)
	}
}

func TestValidateCrashAnalysisPayloadAcceptsCompleteResponse(t *testing.T) {
	payload := []byte(`{
		"crash_file":"leak-a",
		"reproduced":true,
		"classification":"library_bug",
		"confidence":"high",
		"crash_type":"leak",
		"asan_report":"SUMMARY: AddressSanitizer: leaked",
		"root_cause":"library leaks an entry",
		"trigger_mechanism":"load/save/unref",
		"affected_file":"exif-data.c",
		"affected_function":"exif_data_save_data_content",
		"affected_line":788,
		"fuzz_driver_assessment":"",
		"library_vulnerability_report":"detailed report",
		"reproduction_steps":["run the binary"],
		"evidence":["LSan report"],
		"recommended_action":"fix count handling",
		"analysis":"这是库缺陷。"
	}`)

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

func TestValidateCrashAnalysisPayloadIgnoresExtraFields(t *testing.T) {
	payload := []byte(`{
		"crash_file":"leak-a",
		"reproduced":true,
		"classification":"library_bug",
		"confidence":"medium",
		"crash_type":"leak",
		"asan_report":"SUMMARY: AddressSanitizer: leaked",
		"root_cause":"library leaks an entry",
		"trigger_mechanism":"load/save/unref",
		"affected_file":"exif-data.c",
		"affected_function":"exif_data_save_data_content",
		"affected_line":788,
		"fuzz_driver_assessment":"",
		"library_vulnerability_report":"detailed report",
		"reproduction_steps":["run the binary"],
		"evidence":["LSan report"],
		"recommended_action":"fix count handling",
		"analysis":"这是库缺陷。",
		"severity":"high"
	}`)

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
