package codex

import (
	"encoding/json"
	"reflect"
	"testing"
)

func TestCommandArgv(t *testing.T) {
	tests := []struct {
		name    string
		command string
		args    []string
		want    []string
	}{
		{
			name:    "default",
			command: "",
			args:    []string{"exec", "--json"},
			want:    []string{"codex", "exec", "--json"},
		},
		{
			name:    "profile prefix",
			command: "codex -p off",
			args:    []string{"exec", "--json"},
			want:    []string{"codex", "-p", "off", "exec", "--json"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := CommandArgv(tt.command, tt.args...); !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("CommandArgv() = %#v, want %#v", got, tt.want)
			}
		})
	}
}

func TestExtractJSONObject(t *testing.T) {
	object := `{"build_system":"Makefile","language":"c","static_libraries":["libbz2.a"]}`
	tests := map[string]string{
		object: object,
		"Build completed. Here's the report: ```json\n" + object + "\n```": object,
		"Build completed. ```\n" + object + "\n```":                        object,
		"Prose before. " + object + " prose after":                         object,
	}
	for input, expected := range tests {
		got := ExtractJSONObject([]byte(input))
		if string(got) != expected {
			t.Fatalf("ExtractJSONObject(%q) = %q, want %q", input, got, expected)
		}
	}
	if got := ExtractJSONObject([]byte("no json here")); got != nil {
		t.Fatalf("expected nil for non-JSON input, got %q", got)
	}
	if got := ExtractJSONObject([]byte("```\n{never closed")); got != nil {
		t.Fatalf("expected nil for unbalanced braces, got %q", got)
	}
}

// TestExtractJSONObjectDecodes verifies the extracted bytes are usable by
// encoding/json (the actual consumer pattern in buildagent/configagent/analyzer).
func TestExtractJSONObjectDecodes(t *testing.T) {
	object := `{"plateau_reached":true,"needs_update":true,"analysis":"edited 1.c and 10.c"}`
	wrapped := "## Analysis\n\nSome prose.\n\n```json\n" + object + "\n```\n"
	var resp struct {
		PlateauReached bool   `json:"plateau_reached"`
		NeedsUpdate    bool   `json:"needs_update"`
		Analysis       string `json:"analysis"`
	}
	if err := json.Unmarshal(ExtractJSONObject([]byte(wrapped)), &resp); err != nil {
		t.Fatalf("extracted object did not decode: %v", err)
	}
	if !resp.NeedsUpdate || resp.Analysis != "edited 1.c and 10.c" {
		t.Fatalf("unexpected decoded response: %#v", resp)
	}
}

// TestExtractJSONObjectBraceInString ensures a '}' inside a string value does
// not prematurely close the object (regression guard for path/URL values).
func TestExtractJSONObjectBraceInString(t *testing.T) {
	input := `prose {"url":"https://example.com/a}b","x":1} trailing`
	got := ExtractJSONObject([]byte(input))
	var m map[string]any
	if err := json.Unmarshal(got, &m); err != nil {
		t.Fatalf("brace-in-string case did not decode: %v (got %q)", err, got)
	}
	if m["url"] != "https://example.com/a}b" {
		t.Fatalf("url value corrupted: %v", m["url"])
	}
}

func TestJSONLineSink(t *testing.T) {
	var collected []json.RawMessage
	sink := JSONLineSink(func(raw json.RawMessage) { collected = append(collected, raw) })
	if sink == nil {
		t.Fatal("sink should not be nil for non-nil callback")
	}
	// valid JSON lines are emitted; non-JSON / blank lines are skipped
	sink(`{"type":"thread.started","thread_id":"t1"}`)
	sink(`not json`)
	sink(``)
	sink(`  {"type":"item.completed"}  `)
	if len(collected) != 2 {
		t.Fatalf("expected 2 valid lines, got %d", len(collected))
	}
	if string(collected[0]) != `{"type":"thread.started","thread_id":"t1"}` {
		t.Fatalf("first line mismatch: %s", collected[0])
	}
	if string(collected[1]) != `{"type":"item.completed"}` {
		t.Fatalf("second line mismatch: %s", collected[1])
	}
}

func TestJSONLineSinkNilCallback(t *testing.T) {
	if got := JSONLineSink(nil); got != nil {
		t.Fatalf("expected nil for nil callback, got a non-nil callback")
	}
}
