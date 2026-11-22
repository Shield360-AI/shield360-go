package shield360

import (
	"context"
	"log/slog"
	"testing"

	"github.com/ThinkfleetAI/shield360-go/rasp"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
)

// Request correlation: Edge's request id on slog records written in the
// request's spans (rasp/edge_request.go).
func TestAppLogsCarryEdgesRequestID(t *testing.T) {
	exp, p := memoryProvider()
	logger := slog.New(NewLogHandler(LogHandlerOptions{LoggerProvider: p}))
	tp := sdktrace.NewTracerProvider()
	ctx, server := tp.Tracer("test").Start(context.Background(), "GET /a")
	rasp.TagServerSpan(server, rasp.RequestIDOf("3f2a9c0d1e4b5a6978c0d1e2f3a4b5c6"))
	child, span := tp.Tracer("test").Start(ctx, "db")
	logger.InfoContext(child, "query")
	span.End()
	server.End()
	logger.Info("outside")
	records := exp.all()
	if got := attrsOf(records[0])[rasp.EdgeRequestIDAttr].AsString(); got != "3f2a9c0d1e4b5a6978c0d1e2f3a4b5c6" {
		t.Fatalf("request id = %q", got)
	}
	if _, ok := attrsOf(records[0])[rasp.EdgeTraceIDAttr]; ok {
		t.Fatal("a span carries the trace: no trace id attribute")
	}
	if _, ok := attrsOf(records[1])[rasp.EdgeRequestIDAttr]; ok {
		t.Fatal("a record outside the request has no request id")
	}
}
