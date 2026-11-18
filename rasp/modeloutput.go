package rasp

import (
	"context"
	"regexp"
)

// The hook point the SDK's LLM instrumentation calls with what a model
// returned (README "Sources of untrusted input", source "model_output"). No
// patching happens here: the instrumentation already holds the response and
// hands the text over. A no-op unless RASP is on with ModelOutput.
//
// The fragments join the RASP context in ctx: the request's, inside
// Middleware, or the one a worker started with WithScope. Go cannot attach
// state to the rest of a call chain after the fact, so model output seen
// with no RASP context in ctx is not recorded; a worker that acts on a
// model's answer wraps the job: ctx = rasp.WithScope(ctx).

// ModelOutputRecording reports whether model output is recorded at all.
func ModelOutputRecording() bool { return modelOutputOn.Load() }

// RecordModelOutput registers completion text a model returned as untrusted
// input. Never panics.
func RecordModelOutput(ctx context.Context, text, key string) {
	if !modelOutputOn.Load() || text == "" {
		return
	}
	defer func() { _ = recover() }()
	c := FromContext(ctx)
	if c == nil {
		return
	}
	c.add(func(list *[]Input) { addModelOutput(list, text, key) })
}

var toolNameUnsafe = regexp.MustCompile(`[^A-Za-z0-9_-]`)

// RecordToolArguments registers tool-call arguments (a JSON string, JSON
// bytes, or a decoded value) as untrusted input under model.tool.<name>.
// Never panics.
func RecordToolArguments(ctx context.Context, args any, toolName string) {
	if !modelOutputOn.Load() || args == nil {
		return
	}
	if s, ok := args.(string); ok && s == "" {
		return
	}
	defer func() { _ = recover() }()
	c := FromContext(ctx)
	if c == nil {
		return
	}
	path := "model.tool"
	if name := truncChars(toolNameUnsafe.ReplaceAllString(toolName, "_"), 64); name != "" {
		path += "." + name
	}
	c.add(func(list *[]Input) { addToolArguments(list, args, path) })
}
