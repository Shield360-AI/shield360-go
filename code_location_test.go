package shield360

import (
	"context"
	"runtime"
	"strings"
	"testing"

	"github.com/ThinkfleetAI/shield360-go/semconv"
	"go.opentelemetry.io/otel/attribute"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
	"go.opentelemetry.io/otel/trace"
)

var genAIStart = trace.WithAttributes(attribute.String(semconv.GenAIOperationName, semconv.GenAIOperationTypeChat))

func newLocationTracer(t *testing.T, cfg Config) (trace.Tracer, *tracetest.SpanRecorder) {
	t.Helper()
	sr := tracetest.NewSpanRecorder()
	opts := []sdktrace.TracerProviderOption{sdktrace.WithSpanProcessor(sr)}
	if p := NewCodeLocationProcessor(cfg); p != nil {
		opts = append(opts, sdktrace.WithSpanProcessor(p))
	}
	tp := sdktrace.NewTracerProvider(opts...)
	t.Cleanup(func() { _ = tp.Shutdown(context.Background()) })
	return tp.Tracer("test"), sr
}

func nextLine() int {
	_, _, line, _ := runtime.Caller(1)
	return line + 1
}

func spanAttrs(s sdktrace.ReadOnlySpan) map[attribute.Key]attribute.Value {
	out := map[attribute.Key]attribute.Value{}
	for _, kv := range s.Attributes() {
		out[kv.Key] = kv.Value
	}
	return out
}

func TestCodeLocationOnGenAISpan(t *testing.T) {
	tr, sr := newLocationTracer(t, Config{})

	wantLine := nextLine()
	_, span := tr.Start(context.Background(), "chat gpt", genAIStart)
	span.End()

	got := spanAttrs(sr.Ended()[0])
	if fn := got[attrCodeFunctionName].AsString(); fn != sdkModulePath+".TestCodeLocationOnGenAISpan" {
		t.Errorf("code.function.name = %q", fn)
	}
	if path := got[attrCodeFilePath].AsString(); path != "code_location_test.go" {
		t.Errorf("code.file.path = %q, want repo-relative test file", path)
	}
	if line := got[attrCodeLineNumber].AsInt64(); line != int64(wantLine) {
		t.Errorf("code.line.number = %d, want %d", line, wantLine)
	}
}

func TestCodeLocationSkipsNonGenAISpans(t *testing.T) {
	tr, sr := newLocationTracer(t, Config{})
	_, span := tr.Start(context.Background(), "http GET")
	span.End()
	for k := range spanAttrs(sr.Ended()[0]) {
		if strings.HasPrefix(string(k), "code.") {
			t.Errorf("non-GenAI span got %s", k)
		}
	}
}

func TestCodeLocationKeepsExistingAttributes(t *testing.T) {
	tr, sr := newLocationTracer(t, Config{})
	_, span := tr.Start(context.Background(), "chat", genAIStart,
		trace.WithAttributes(attribute.String(attrCodeFunctionName, "custom.fn")))
	span.End()
	got := spanAttrs(sr.Ended()[0])
	if got[attrCodeFunctionName].AsString() != "custom.fn" {
		t.Errorf("existing code.function.name overwritten: %q", got[attrCodeFunctionName].AsString())
	}
	if _, ok := got[attrCodeLineNumber]; ok {
		t.Error("code.line.number added alongside a caller-set location")
	}
}

func TestCodeLocationOptOut(t *testing.T) {
	off, on := false, true
	for _, v := range []string{"false", "0", "No", "OFF"} {
		t.Setenv(envCaptureCodeLoc, v)
		if NewCodeLocationProcessor(Config{}) != nil {
			t.Errorf("env %q should disable capture", v)
		}
	}
	if NewCodeLocationProcessor(Config{CaptureCodeLocation: &on}) == nil {
		t.Error("config true should win over env")
	}
	t.Setenv(envCaptureCodeLoc, "")
	if NewCodeLocationProcessor(Config{CaptureCodeLocation: &off}) != nil {
		t.Error("config false should disable capture")
	}
	if NewCodeLocationProcessor(Config{}) == nil {
		t.Error("capture should be on by default")
	}
}

func TestCodeLocationCacheHit(t *testing.T) {
	p := NewCodeLocationProcessor(Config{}).(*codeLocationProcessor)
	sr := tracetest.NewSpanRecorder()
	tp := sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(sr), sdktrace.WithSpanProcessor(p))
	tr := tp.Tracer("test")

	var sizes []int
	for i := 0; i < 2; i++ {
		_, span := tr.Start(context.Background(), "chat", genAIStart)
		span.End()
		p.mu.RLock()
		sizes = append(sizes, len(p.cache))
		p.mu.RUnlock()
	}
	if sizes[0] == 0 || sizes[1] != sizes[0] {
		t.Errorf("cache sizes = %v, want non-empty and unchanged on the second call", sizes)
	}
	a, b := spanAttrs(sr.Ended()[0]), spanAttrs(sr.Ended()[1])
	if a[attrCodeLineNumber] != b[attrCodeLineNumber] || a[attrCodeFilePath].AsString() != "code_location_test.go" {
		t.Errorf("cached location differs: %v vs %v", a, b)
	}
}

func TestCodeLocationSkipFrame(t *testing.T) {
	p := &codeLocationProcessor{modulePath: "github.com/acme/api", ignore: []string{"github.com/acme/wrapper"}}
	cases := []struct {
		fn, file string
		skip     bool
	}{
		{"runtime.goexit", "/go/src/runtime/asm.s", true},
		{"net/http.(*Client).Do", "/go/src/net/http/client.go", true},
		{"go.opentelemetry.io/otel/sdk/trace.(*tracer).Start", "x.go", true},
		{sdkModulePath + "/instrumentation/openai.(*InstrumentedClient).CreateChatCompletion", "/m/instrumentation/openai/instrumentor.go", true},
		{"github.com/sashabaranov/go-openai.(*Client).CreateChatCompletion", "chat.go", true},
		{"github.com/openai/openai-go.(*ChatService).New", "chat.go", true},
		{"github.com/anthropics/anthropic-sdk-go.(*MessageService).New", "m.go", true},
		{"github.com/acme/wrapper/llm.Call", "llm.go", true},
		{"main.main", "/app/main.go", false},
		{"github.com/acme/api/billing.(*Cart).Summarise", "/app/billing/cart.go", false},
		{"github.com/other/svc.Run", "/app/run.go", false},
	}
	for _, c := range cases {
		if got := p.skipFrame(runtime.Frame{Function: c.fn, File: c.file}); got != c.skip {
			t.Errorf("skipFrame(%s) = %v, want %v", c.fn, got, c.skip)
		}
	}
}

func TestCodeLocationNormalisePath(t *testing.T) {
	p := &codeLocationProcessor{
		codeRoot:   "/srv/repo",
		cwd:        "/app",
		home:       "/home/bob",
		modulePath: "github.com/acme/api",
	}
	cases := map[string]string{
		"/srv/repo/billing/cart.go":           "billing/cart.go", // code root
		"github.com/acme/api/billing/cart.go": "billing/cart.go", // -trimpath main module
		"github.com/other/lib@v1.2.0/x.go":    "github.com/other/lib@v1.2.0/x.go",
		"/app/cmd/server/main.go":             "cmd/server/main.go", // working directory
		"/home/bob/proj/x.go":                 "proj/x.go",          // home directory
		"/opt/build/x.go":                     "/opt/build/x.go",
		"/srv/repository-other/x.go":          "/srv/repository-other/x.go",
		"./a.go":                              "a.go",
	}
	for in, want := range cases {
		if got := p.normalisePath(in); got != want {
			t.Errorf("normalisePath(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestCodeLocationBuildHostPathsAreAnonymised(t *testing.T) {
	// A binary built without -trimpath carries the build host's paths, which
	// match nothing at run time.
	p := &codeLocationProcessor{cwd: "/app", home: "/home/app", modulePath: "github.com/acme/api"}
	cases := map[string]string{
		"/home/runner/work/api/api/billing/cart.go":    "billing/cart.go",
		"/github/workspace/billing/cart.go":            "billing/cart.go",
		"/home/vsts/work/1/s/billing/cart.go":          "billing/cart.go",
		"/builds/acme/api/billing/cart.go":             "billing/cart.go",
		"/var/lib/jenkins/workspace/api-main/x.go":     "x.go",
		"/codebuild/output/src123/src/github.com/x.go": "github.com/x.go",
		"/Users/alice/dev/api/x.go":                    "dev/api/x.go",
		"/home/alice/dev/api/x.go":                     "dev/api/x.go",
		"C:/Users/alice/dev/api/x.go":                  "dev/api/x.go",
		"/root/go/src/api/x.go":                        "go/src/api/x.go",
		"/srv/app/x.go":                                "/srv/app/x.go",
	}
	for in, want := range cases {
		got := p.normalisePath(in)
		if got != want {
			t.Errorf("normalisePath(%q) = %q, want %q", in, got, want)
		}
		if strings.Contains(got, "alice") || strings.Contains(got, "runner") {
			t.Errorf("normalisePath(%q) leaks a user: %q", in, got)
		}
	}
}

func TestCodeLocationCodeRootFromEnv(t *testing.T) {
	t.Setenv(envCodeRoot, "/srv/repo/")
	p := NewCodeLocationProcessor(Config{}).(*codeLocationProcessor)
	if got := p.normalisePath("/srv/repo/a/b.go"); got != "a/b.go" {
		t.Errorf("got %q", got)
	}
	p = NewCodeLocationProcessor(Config{CodeRoot: "/srv"}).(*codeLocationProcessor)
	if got := p.normalisePath("/srv/repo/a/b.go"); got != "repo/a/b.go" {
		t.Errorf("config CodeRoot should win over env, got %q", got)
	}
}

// Test binaries report the SDK as the main module; SDK frames must still be skipped.
func TestCodeLocationSkipsSDKWhenItIsMainModule(t *testing.T) {
	p := &codeLocationProcessor{modulePath: sdkModulePath}
	if !p.skipFrame(runtime.Frame{Function: sdkModulePath + "/helpers.Do", File: "/m/helpers/http.go"}) {
		t.Error("SDK frame not skipped")
	}
	if p.skipFrame(runtime.Frame{Function: sdkModulePath + ".TestX", File: "/m/x_test.go"}) {
		t.Error("SDK test frame skipped")
	}
}

// SHIELD: code cost — outbound calls carry their call site, so a costly
// pattern shield360 scan found can be priced by what that call cost.
func TestCodeLocationOnOutboundCalls(t *testing.T) {
	tr, sr := newLocationTracer(t, Config{})
	calls := []struct {
		kind trace.SpanKind
		attr attribute.KeyValue
	}{
		{trace.SpanKindClient, attribute.String("db.system", "postgresql")},
		{trace.SpanKindClient, attribute.String("db.system.name", "mongodb")},
		{trace.SpanKindClient, attribute.String("http.request.method", "GET")},
		{trace.SpanKindClient, attribute.String("rpc.system", "aws-api")},
		{trace.SpanKindProducer, attribute.String("messaging.system", "aws_sqs")},
	}
	for _, c := range calls {
		_, span := tr.Start(context.Background(), "call", trace.WithSpanKind(c.kind), trace.WithAttributes(c.attr))
		span.End()
	}
	for i, s := range sr.Ended() {
		if path := spanAttrs(s)[attrCodeFilePath].AsString(); path != "code_location_test.go" {
			t.Errorf("call %d: code.file.path = %q", i, path)
		}
	}
}

func TestCodeLocationSkipsServerInternalAndPlainClientSpans(t *testing.T) {
	tr, sr := newLocationTracer(t, Config{})
	_, a := tr.Start(context.Background(), "s", trace.WithSpanKind(trace.SpanKindServer), trace.WithAttributes(attribute.String("http.request.method", "GET")))
	a.End()
	_, b := tr.Start(context.Background(), "i", trace.WithSpanKind(trace.SpanKindInternal), trace.WithAttributes(attribute.String("db.system", "postgresql")))
	b.End()
	_, c := tr.Start(context.Background(), "c", trace.WithSpanKind(trace.SpanKindClient), trace.WithAttributes(attribute.String("peer.service", "x")))
	c.End()
	for _, s := range sr.Ended() {
		if _, ok := spanAttrs(s)[attrCodeFilePath]; ok {
			t.Errorf("%s got a call site", s.Name())
		}
	}
}

func TestCodeLocationCallsOptOut(t *testing.T) {
	off := false
	tr, sr := newLocationTracer(t, Config{CaptureCallLocation: &off})
	_, db := tr.Start(context.Background(), "q", trace.WithSpanKind(trace.SpanKindClient), trace.WithAttributes(attribute.String("db.system", "postgresql")))
	db.End()
	_, chat := tr.Start(context.Background(), "chat gpt", genAIStart)
	chat.End()
	ended := sr.Ended()
	if _, ok := spanAttrs(ended[0])[attrCodeFilePath]; ok {
		t.Error("db span stamped with calls off")
	}
	if _, ok := spanAttrs(ended[1])[attrCodeFilePath]; !ok {
		t.Error("GenAI span not stamped with calls off")
	}
	t.Setenv(envCaptureCallLoc, "off")
	if captureCallLocation(Config{}) {
		t.Error("env opt-out ignored")
	}
	on := true
	if !captureCallLocation(Config{CaptureCallLocation: &on}) {
		t.Error("config should win over env")
	}
}
