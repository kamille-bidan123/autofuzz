package webui

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

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
	for _, marker := range []string{`id="taskListView"`, `id="createModal"`, `id="taskDetailView"`, `snap-version-button`, `/start`} {
		if !strings.Contains(body, marker) {
			t.Fatalf("index is missing %s", marker)
		}
	}
	if strings.Contains(body, `id="taskSelBtn"`) || strings.Contains(body, "localStorage") {
		t.Fatal("index still contains the old task auto-selection UI")
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
