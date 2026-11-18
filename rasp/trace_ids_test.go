package rasp

import (
	"context"
	"testing"

	"go.opentelemetry.io/otel/trace"
)

func spanCtx(t *testing.T) context.Context {
	t.Helper()
	tid, _ := trace.TraceIDFromHex("4bf92f3577b34da6a3ce929d0e0e4736")
	sid, _ := trace.SpanIDFromHex("00f067aa0ba902b7")
	return trace.ContextWithSpanContext(context.Background(), trace.NewSpanContext(trace.SpanContextConfig{TraceID: tid, SpanID: sid, TraceFlags: trace.FlagsSampled}))
}

func TestAddTraceIDsFromTheFirstContextWithASpan(t *testing.T) {
	attrs := map[string]string{}
	addTraceIDs(attrs, context.Background(), nil, spanCtx(t))
	if attrs[traceIDAttr] != "4bf92f3577b34da6a3ce929d0e0e4736" || attrs[spanIDAttr] != "00f067aa0ba902b7" {
		t.Fatalf("ids = %v", attrs)
	}
}

func TestAddTraceIDsLeavesAttrsAloneWithoutASpan(t *testing.T) {
	attrs := map[string]string{"k": "v"}
	addTraceIDs(attrs, context.Background())
	if len(attrs) != 1 {
		t.Fatalf("attrs = %v", attrs)
	}
}

func TestDropTraceIDs(t *testing.T) {
	attrs := map[string]string{traceIDAttr: "x", spanIDAttr: "y", "k": "v"}
	dropTraceIDs(attrs)
	if len(attrs) != 1 || attrs["k"] != "v" {
		t.Fatalf("attrs = %v", attrs)
	}
}
