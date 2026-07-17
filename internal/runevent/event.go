package runevent

import (
	"encoding/json"
	"time"
)

// Event is the common event envelope emitted by an Autofuzz run. Data contains
// the untouched Codex JSONL object for kind=codex events.
type Event struct {
	Sequence uint64          `json:"sequence,omitempty"`
	Time     time.Time       `json:"time"`
	Kind     string          `json:"kind"`
	Stage    string          `json:"stage,omitempty"`
	Status   string          `json:"status,omitempty"`
	Source   string          `json:"source,omitempty"`
	Message  string          `json:"message,omitempty"`
	Data     json.RawMessage `json:"data,omitempty"`
}

type Sink func(Event)

func New(kind, stage, status, source, message string) Event {
	return Event{
		Time: time.Now(), Kind: kind, Stage: stage, Status: status,
		Source: source, Message: message,
	}
}
