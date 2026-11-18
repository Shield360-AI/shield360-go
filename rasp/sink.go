package rasp

import (
	"context"
	"strings"
	"sync/atomic"
)

// Shared plumbing of the sink wrappers (sql.go, exec.go, httpclient.go,
// file.go, code.go, response.go). Go has no runtime patching, so every sink
// is opt-in: the app calls rasp.Command instead of exec.Command, opens its
// database through rasp.OpenSQL, and so on. Each wrapper checks before the
// underlying call, returns the block error instead of making it, and fails
// open on anything else.

// testHookDetect, when set, runs at the start of every sink check, inside
// the recovered region (tests: count checks, or panic to prove fail-open).
var testHookDetect atomic.Pointer[func(sink string)]

// checkSink runs a detector at a sink through check, handing it the passive
// IAST slot (nil unless armed). It returns only the block error.
func checkSink(ctx context.Context, sink string, run func(*iastSlot) *Finding) error {
	_, err := checkSinkDecision(ctx, sink, run)
	return err
}

// checkSinkDecision is checkSink that also returns the decision.
func checkSinkDecision(ctx context.Context, sink string, run func(*iastSlot) *Finding) (Decision, error) {
	return check(ctx, sink, func(slot *iastSlot) *Finding {
		if h := testHookDetect.Load(); h != nil {
			(*h)(sink)
		}
		return run(slot)
	})
}

// inputsOf returns the inputs of the RASP context in ctx (nil without one).
func inputsOf(ctx context.Context) []Input {
	return FromContext(ctx).Inputs()
}

// sinkName keeps a caller-supplied sink name within the platform's shape
// (dot-separated words, at most 64 characters); anything else becomes def.
func sinkName(name, def string) string {
	if name == "" || len(name) > 64 || isDigitByte(name[0]) {
		return def
	}
	segLen := 0
	for i := 0; i < len(name); i++ {
		c := name[i]
		switch {
		case c == '.' || c == ':' || c == '/':
			if segLen == 0 {
				return def // empty segment
			}
			segLen = 0
		case isIDCharByte(c) && c != '$':
			segLen++
		default:
			return def
		}
	}
	if segLen == 0 {
		return def
	}
	return name
}

// sinkWord keeps one name segment (a driver or operation name) to
// [A-Za-z0-9_], at most 32 characters, or returns def.
func sinkWord(w, def string) string {
	var b strings.Builder
	for i := 0; i < len(w) && b.Len() < 32; i++ {
		c := w[i]
		switch {
		case isIDCharByte(c) && c != '$':
			b.WriteByte(c)
		case c == '-' || c == '.':
			b.WriteByte('_')
		}
	}
	if b.Len() == 0 {
		return def
	}
	return b.String()
}
