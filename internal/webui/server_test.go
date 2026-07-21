package webui

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"autofuzz/internal/fuzzing"
	"autofuzz/internal/runevent"
)

func TestDefaultsEndpoint(t *testing.T) {
	request := httptest.NewRequest(http.MethodGet, "/api/defaults", nil)
	response := httptest.NewRecorder()
	NewServer(NewManager(context.Background())).ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d", response.Code)
	}
	var defaults RunRequest
	if err := json.Unmarshal(response.Body.Bytes(), &defaults); err != nil {
		t.Fatal(err)
	}
	if defaults.CodexCommand != "codex" || defaults.StopAfter != "fuzzing" {
		t.Fatalf("unexpected defaults: %#v", defaults)
	}
}

func TestIndexShowsTaskListBeforeTaskDetails(t *testing.T) {
	request := httptest.NewRequest(http.MethodGet, "/", nil)
	response := httptest.NewRecorder()
	NewServer(NewManager(context.Background())).ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d", response.Code)
	}
	body := response.Body.String()
	for _, marker := range []string{`id="taskListView"`, `id="createModal"`, `id="taskDetailView"`, `id="resumeButton"`, `id="fuzzFlowHistory"`, `id="codexEventPanel" class="panel stream"`, `id="runtimeLogPanel" class="panel stream"`, `stage-cycle`, `event.kind === 'fuzz_flow'`, `snap-version-button`, `/start`} {
		if !strings.Contains(body, marker) {
			t.Fatalf("index is missing %s", marker)
		}
	}
	if strings.Contains(body, `id="taskSelBtn"`) || strings.Contains(body, "localStorage") {
		t.Fatal("index still contains the old task auto-selection UI")
	}
	if strings.Contains(body, "waitingForAnalysis") || strings.Contains(body, "m.includes('plateau=')") {
		t.Fatal("index still infers LLM flow state from runtime log strings")
	}
}

func TestFuzzFlowEndpointRestoresCurrentAndLimitsHistory(t *testing.T) {
	targetDir := t.TempDir()
	logsDir := filepath.Join(targetDir, "logs", "fuzzing")
	flow := &fuzzing.FuzzFlowSnapshot{Iteration: 3, DriverSeq: 2, Phase: fuzzing.FuzzFlowAnalyzing, Status: "running", Trigger: "manual", Message: "Codex 正在分析"}
	if err := flow.Save(filepath.Join(logsDir, "fuzz-flow.json")); err != nil {
		t.Fatal(err)
	}
	history := "" +
		`{"iteration":1,"seq":1,"trigger":"interval","analysis":{"analysis":"第一轮"},"started_at":"2026-07-21T00:00:00Z","finished_at":"2026-07-21T00:00:01Z"}` + "\n" +
		`{"iteration":2,"seq":1,"trigger":"manual","analysis":{"analysis":"第二轮","plateau_reached":true,"needs_update":true},"regenerated":true,"started_at":"2026-07-21T00:01:00Z","finished_at":"2026-07-21T00:01:02Z"}` + "\n"
	if err := os.WriteFile(filepath.Join(logsDir, "fuzzing-history.jsonl"), []byte(history), 0o644); err != nil {
		t.Fatal(err)
	}
	task := &Task{id: "test", status: "running", createdAt: time.Now(), targetDir: targetDir, stages: map[string]string{}, subscribers: map[chan runevent.Event]struct{}{}}
	manager := NewManager(context.Background())
	manager.tasks[task.id] = task

	request := httptest.NewRequest(http.MethodGet, "/api/runs/test/fuzz-flow?limit=1", nil)
	response := httptest.NewRecorder()
	NewServer(manager).ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", response.Code, response.Body.String())
	}
	var got FuzzFlowResponse
	if err := json.Unmarshal(response.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got.Current == nil || got.Current.Phase != fuzzing.FuzzFlowAnalyzing || len(got.History) != 1 || got.History[0].Iteration != 2 || got.History[0].Trigger != "manual" {
		t.Fatalf("unexpected fuzz flow response: %#v", got)
	}
}

func TestSSEIncludesCodexJSONData(t *testing.T) {
	task := &Task{
		id: "test", status: "completed", createdAt: time.Now(), stages: map[string]string{},
		subscribers: map[chan runevent.Event]struct{}{},
	}
	raw := json.RawMessage(`{"type":"item.completed","item":{"type":"agent_message","text":"done"}}`)
	event := runevent.New("codex", "built", "", "codex-cli", "item.completed")
	event.Data = raw
	task.publish(event)
	now := time.Now()
	task.finishedAt = &now
	manager := NewManager(context.Background())
	manager.tasks[task.id] = task

	request := httptest.NewRequest(http.MethodGet, "/api/runs/test/events", nil)
	request.SetPathValue("id", "test")
	response := httptest.NewRecorder()
	NewServer(manager).runEvents(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d", response.Code)
	}
	body := response.Body.String()
	if !strings.Contains(body, "event: autofuzz") || !strings.Contains(body, `"item.completed"`) {
		t.Fatalf("unexpected SSE body: %s", body)
	}

	request = httptest.NewRequest(http.MethodGet, "/api/runs/test/events", nil)
	request.SetPathValue("id", "test")
	request.Header.Set("Last-Event-ID", "1")
	response = httptest.NewRecorder()
	NewServer(manager).runEvents(response, request)
	if strings.Contains(response.Body.String(), "event: autofuzz") {
		t.Fatalf("reconnect replayed an acknowledged event: %s", response.Body.String())
	}
}

func TestSSEIncludesStructuredFuzzFlow(t *testing.T) {
	task := &Task{
		id: "flow", status: "completed", createdAt: time.Now(), stages: map[string]string{},
		subscribers: map[chan runevent.Event]struct{}{},
	}
	raw := json.RawMessage(`{"iteration":7,"driver_seq":3,"phase":"analyzing","status":"running","trigger":"manual","message":"Codex 正在分析","updated_at":"2026-07-21T00:00:00Z"}`)
	event := runevent.New("fuzz_flow", "fuzzing", "running", "fuzz-loop", "Codex 正在分析")
	event.Data = raw
	task.publish(event)
	now := time.Now()
	task.finishedAt = &now
	manager := NewManager(context.Background())
	manager.tasks[task.id] = task

	request := httptest.NewRequest(http.MethodGet, "/api/runs/flow/events", nil)
	request.SetPathValue("id", "flow")
	response := httptest.NewRecorder()
	NewServer(manager).runEvents(response, request)
	body := response.Body.String()
	if !strings.Contains(body, `"kind":"fuzz_flow"`) || !strings.Contains(body, `"phase":"analyzing"`) || !strings.Contains(body, `"trigger":"manual"`) {
		t.Fatalf("unexpected SSE flow body: %s", body)
	}
}
