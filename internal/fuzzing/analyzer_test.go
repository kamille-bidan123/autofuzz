package fuzzing

import (
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
