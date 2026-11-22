package rasp

// SHIELD: request correlation — Shield360 Edge's request id and the trace id
// on everything the app records while it serves that request, so Shield360
// joins the app's log records and spans to Edge's record of the request,
// even when the app does not trace. Port of
// sdk/typescript/src/otel/edge-request.ts; passes
// sdk/rasp/testdata/request-correlation.json.
//
// Edge's id is taken from its signed context header when RASP verified one
// (edge_context.go), else from the request's X-Request-Id (Edge always sends
// its own there). It goes on the server span (shield360.edge.request_id: the
// SDK's traced handler and the RASP capture) and on every slog record handed
// the request's context, with the trace id as shield360.edge.trace_id when no
// span is active. Only an id-shaped value is used: letters, digits, ".", "_"
// and "-", 8 to 128 characters.

import (
	"context"
	"regexp"
	"sync"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
)

const (
	// EdgeRequestIDAttr is the attribute Edge's request id goes in.
	EdgeRequestIDAttr = "shield360.edge.request_id"
	// EdgeTraceIDAttr is the attribute the trace id goes in when no span carries it.
	EdgeTraceIDAttr = "shield360.edge.trace_id"
	// RequestIDHeader is Edge's own request id header.
	RequestIDHeader = "X-Request-Id"

	maxTraces = 5000
)

var (
	requestIDRe   = regexp.MustCompile(`^[A-Za-z0-9._-]{8,128}$`)
	traceparentRe = regexp.MustCompile(`^[0-9a-f]{2}-([0-9a-f]{32})-[0-9a-f]{16}-[0-9a-f]{2}$`)

	byTraceMu    sync.Mutex
	byTrace      = map[trace.TraceID]string{}
	byTraceOrder []trace.TraceID
)

// RequestIDOf returns an id-shaped request id, or "".
func RequestIDOf(v string) string {
	if requestIDRe.MatchString(v) {
		return v
	}
	return ""
}

// TraceIDOf returns the trace id in a W3C traceparent, or "".
func TraceIDOf(traceparent string) string {
	m := traceparentRe.FindStringSubmatch(traceparent)
	if m == nil || m[1] == "00000000000000000000000000000000" {
		return ""
	}
	return m[1]
}

// TagServerSpan records the request id on the request's server span and
// remembers it for the span's trace (log records in child spans). Never
// panics.
func TagServerSpan(span trace.Span, requestID string) {
	defer func() { _ = recover() }()
	if span == nil || requestID == "" {
		return
	}
	span.SetAttributes(attribute.String(EdgeRequestIDAttr, requestID))
	sc := span.SpanContext()
	if !sc.IsValid() {
		return
	}
	byTraceMu.Lock()
	defer byTraceMu.Unlock()
	if _, ok := byTrace[sc.TraceID()]; !ok {
		if len(byTraceOrder) >= maxTraces {
			delete(byTrace, byTraceOrder[0])
			byTraceOrder = byTraceOrder[1:]
		}
		byTraceOrder = append(byTraceOrder, sc.TraceID())
	}
	byTrace[sc.TraceID()] = requestID
}

// EdgeIDs returns Edge's request id and the trace id for ctx (either may be
// ""), and whether a span carries the trace.
func EdgeIDs(ctx context.Context) (requestID, traceID string, spanActive bool) {
	defer func() { _ = recover() }()
	if ctx == nil {
		return "", "", false
	}
	sc := trace.SpanContextFromContext(ctx)
	spanActive = sc.IsValid()
	if c := FromContext(ctx); c != nil {
		c.mu.Lock()
		edge, rid, tid := c.edge, c.requestID, c.traceID
		c.mu.Unlock()
		if edge != nil {
			requestID = edge.Rid
			if t := TraceIDOf(edge.Traceparent); t != "" {
				tid = t
			}
		} else {
			requestID = rid
		}
		traceID = tid
	}
	if requestID == "" && spanActive {
		byTraceMu.Lock()
		requestID = byTrace[sc.TraceID()]
		byTraceMu.Unlock()
	}
	if spanActive {
		traceID = sc.TraceID().String()
	}
	return requestID, traceID, spanActive
}

func resetEdgeRequests() {
	byTraceMu.Lock()
	byTrace = map[trace.TraceID]string{}
	byTraceOrder = nil
	byTraceMu.Unlock()
}
