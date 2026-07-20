// Package codex holds helpers for parsing output from the Codex CLI: the
// JSONL event stream (--json stdout) and the final agent message
// (--output-last-message), which Codex may wrap in prose and markdown code
// fences despite an --output-schema contract. There is no Codex CLI flag
// that forces pure-JSON final-message output (the configured provider does
// not support OpenAI strict structured outputs), so callers must both
// instruct the model to emit JSON only and defensively extract the JSON
// object from a possibly-wrapped message.
package codex

import (
	"bytes"
	"encoding/json"
	"strings"
)

// ExtractJSONObject locates the first complete JSON object in data, tolerating
// surrounding prose and markdown code fences (```json ... ```) that Codex
// sometimes emits despite instructions. Returns nil if no balanced object is
// found. It is string-aware (skips braces and quotes inside string literals)
// so a '}' inside a path/URL value does not end the object prematurely.
func ExtractJSONObject(data []byte) []byte {
	start := bytes.IndexByte(data, '{')
	if start < 0 {
		return nil
	}
	depth := 0
	inStr := false
	esc := false
	for i := start; i < len(data); i++ {
		c := data[i]
		switch {
		case inStr:
			if esc {
				esc = false
			} else if c == '\\' {
				esc = true
			} else if c == '"' {
				inStr = false
			}
		case c == '"':
			inStr = true
		case c == '{':
			depth++
		case c == '}':
			depth--
			if depth == 0 {
				return data[start : i+1]
			}
		}
	}
	return nil
}

// JSONLineSink returns a per-line callback that emits each valid JSON line
// from Codex's --json stdout stream to sink. Non-JSON lines (banner text,
// blank lines, partial progress) are ignored. Returns nil when sink is nil so
// callers can wire it unconditionally without allocating a closure.
func JSONLineSink(sink func(json.RawMessage)) func(string) {
	if sink == nil {
		return nil
	}
	return func(line string) {
		raw := json.RawMessage(strings.TrimSpace(line))
		if !json.Valid(raw) {
			return
		}
		copyOfRaw := append(json.RawMessage(nil), raw...)
		sink(copyOfRaw)
	}
}
