package rasp

import (
	"context"

	"go.opentelemetry.io/otel/trace"
)

// SHIELD: security event trace ids — an event names the W3C trace and span of
// the request it happened in, so the console's replay opens that trace rather
// than matching one by app, time and route. Ids only, never a value.

const (
	traceIDAttr = "shield360.rasp.trace_id"
	spanIDAttr  = "shield360.rasp.span_id"
)

// addTraceIDs puts the active span's ids on attrs, from ctx or else from the
// fallback (an HTTP request's own context). Nothing when neither has a span.
func addTraceIDs(attrs map[string]string, ctxs ...context.Context) {
	for _, ctx := range ctxs {
		if ctx == nil {
			continue
		}
		sc := trace.SpanContextFromContext(ctx)
		if !sc.IsValid() {
			continue
		}
		attrs[traceIDAttr] = sc.TraceID().String()
		attrs[spanIDAttr] = sc.SpanID().String()
		return
	}
}

// dropTraceIDs removes them: a folded repeat stands for several requests.
func dropTraceIDs(attrs map[string]string) {
	delete(attrs, traceIDAttr)
	delete(attrs, spanIDAttr)
}
