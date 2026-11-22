package vllm

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"runtime"
	"testing"

	shield360 "github.com/Shield360-AI/shield360-go"
	"go.opentelemetry.io/otel"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
)

// The call site recorded on a real instrumented span is the test's own line:
// the instrumentation, OpenTelemetry and net/http frames are skipped.
func TestCodeLocationThroughInstrumentation(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(ChatCompletionResponse{ID: "x", Model: "m"}) //nolint:errcheck
	}))
	defer srv.Close()

	sr := tracetest.NewSpanRecorder()
	tp := sdktrace.NewTracerProvider(
		sdktrace.WithSpanProcessor(sr),
		sdktrace.WithSpanProcessor(shield360.NewCodeLocationProcessor(shield360.Config{})),
	)
	otel.SetTracerProvider(tp)
	t.Cleanup(func() {
		_ = tp.Shutdown(context.Background())
		otel.SetTracerProvider(sdktrace.NewTracerProvider())
	})

	client := NewClient(srv.URL)
	_, _, line, _ := runtime.Caller(0)
	_, err := client.CreateChatCompletion(context.Background(), ChatCompletionRequest{
		Messages: []ChatMessage{{Role: "user", Content: "hi"}},
	})
	if err != nil {
		t.Fatalf("CreateChatCompletion: %v", err)
	}

	spans := sr.Ended()
	if len(spans) == 0 {
		t.Fatal("no spans recorded")
	}
	span := spans[len(spans)-1]
	// "code_location_test.go" relative to the working directory, or
	// "instrumentation/vllm/code_location_test.go" in a -trimpath build.
	if got := attrString(span, "code.file.path"); got != "code_location_test.go" && got != "instrumentation/vllm/code_location_test.go" {
		t.Errorf("code.file.path = %q", got)
	}
	if got := attrString(span, "code.function.name"); got != "github.com/Shield360-AI/shield360-go/instrumentation/vllm.TestCodeLocationThroughInstrumentation" {
		t.Errorf("code.function.name = %q", got)
	}
	var gotLine int64
	for _, a := range span.Attributes() {
		if a.Key == "code.line.number" {
			gotLine = a.Value.AsInt64()
		}
	}
	if gotLine != int64(line+1) {
		t.Errorf("code.line.number = %d, want %d", gotLine, line+1)
	}
}
