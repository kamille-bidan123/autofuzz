package agent

import (
	"encoding/json"
	"strings"

	"autofuzz/internal/runevent"
	"autofuzz/internal/state"
)

// SetEventSink attaches a live observer. It is intended to be called before
// Run starts; replacing it during a run is also safe.
func (a *Agent) SetEventSink(sink runevent.Sink) {
	a.eventMu.Lock()
	a.eventSink = sink
	a.eventMu.Unlock()
}

func (a *Agent) emit(event runevent.Event) {
	a.eventMu.RLock()
	sink := a.eventSink
	a.eventMu.RUnlock()
	if sink != nil {
		sink(event)
	}
}

func (a *Agent) stageStarted(stage state.Stage, message string) {
	a.eventMu.Lock()
	a.activeStage = stage
	sink := a.eventSink
	a.eventMu.Unlock()
	if sink != nil {
		sink(runevent.New("stage", string(stage), "running", "autofuzz", message))
	}
}

func (a *Agent) stageCompleted(stage state.Stage, message string) {
	a.eventMu.Lock()
	if a.activeStage == stage {
		a.activeStage = ""
	}
	sink := a.eventSink
	a.eventMu.Unlock()
	if sink != nil {
		sink(runevent.New("stage", string(stage), "completed", "autofuzz", message))
	}
}

func (a *Agent) stageFailed(stage state.Stage, message string) {
	a.eventMu.Lock()
	a.activeStage = ""
	sink := a.eventSink
	a.eventMu.Unlock()
	if sink != nil {
		sink(runevent.New("stage", string(stage), "failed", "autofuzz", message))
	}
}

func (a *Agent) onCommandLine(command, stream, line string) {
	if strings.TrimSpace(line) == "" {
		return
	}
	// Codex stdout is JSONL and is published as a structured codex event.
	if command == "codex" && stream == "stdout" && json.Valid([]byte(line)) {
		return
	}
	a.eventMu.RLock()
	stage := a.activeStage
	a.eventMu.RUnlock()
	a.emit(runevent.New("log", string(stage), "", command+"/"+stream, line))
}

func (a *Agent) codexEventSink(stage state.Stage) func(json.RawMessage) {
	return func(raw json.RawMessage) {
		message := "Codex event"
		var envelope struct {
			Type string `json:"type"`
		}
		if json.Unmarshal(raw, &envelope) == nil && envelope.Type != "" {
			message = envelope.Type
		}
		event := runevent.New("codex", string(stage), "", "codex-cli", message)
		event.Data = append(json.RawMessage(nil), raw...)
		a.emit(event)
	}
}
