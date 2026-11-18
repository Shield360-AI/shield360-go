package shield360

// Application logs reach Shield360 only when asked for, through the SDK's own
// LoggerProvider, linked to the span in the logging call's context, masked,
// filtered, rate-limited, and to the same endpoint and headers as traces. The
// Python and TypeScript SDKs carry the same tests.

import (
	"bytes"
	"context"
	"errors"
	"io"
	stdlog "log"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"go.opentelemetry.io/otel/attribute"
	otellog "go.opentelemetry.io/otel/log"
	"go.opentelemetry.io/otel/log/embedded"
	sdklog "go.opentelemetry.io/otel/sdk/log"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
)

type memoryExporter struct {
	mu      sync.Mutex
	records []sdklog.Record
	err     error
}

func (m *memoryExporter) Export(_ context.Context, records []sdklog.Record) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, r := range records {
		m.records = append(m.records, r.Clone())
	}
	return m.err
}
func (m *memoryExporter) Shutdown(context.Context) error   { return nil }
func (m *memoryExporter) ForceFlush(context.Context) error { return nil }

func (m *memoryExporter) all() []sdklog.Record {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]sdklog.Record(nil), m.records...)
}

func (m *memoryExporter) bodies() []string {
	var out []string
	for _, r := range m.all() {
		out = append(out, r.Body().AsString())
	}
	return out
}

func memoryProvider() (*memoryExporter, *sdklog.LoggerProvider) {
	exp := &memoryExporter{}
	return exp, sdklog.NewLoggerProvider(sdklog.WithProcessor(sdklog.NewSimpleProcessor(exp)))
}

func attrsOf(r sdklog.Record) map[string]attribute.Value {
	out := map[string]attribute.Value{}
	r.WalkAttributes(func(kv attribute.KeyValue) bool {
		out[string(kv.Key)] = kv.Value
		return true
	})
	return out
}

func TestAppLogsSendsAtTheLevelAndAbove(t *testing.T) {
	exp, p := memoryProvider()
	logger := slog.New(NewLogHandler(LogHandlerOptions{LoggerProvider: p, Level: "warn"}))
	logger.Debug("d")
	logger.Info("i")
	logger.Warn("w")
	logger.Error("e")
	logger.Log(context.Background(), slog.LevelError+4, "f")
	if got := strings.Join(exp.bodies(), ","); got != "w,e,f" {
		t.Fatalf("bodies = %q", got)
	}
	var texts []string
	var numbers []int
	for _, r := range exp.all() {
		texts = append(texts, r.SeverityText())
		numbers = append(numbers, int(r.Severity()))
	}
	if strings.Join(texts, ",") != "WARN,ERROR,FATAL" || numbers[0] != 13 || numbers[1] != 17 || numbers[2] != 21 {
		t.Fatalf("severities = %v %v", texts, numbers)
	}
}

func TestAppLogsDefaultsToInfo(t *testing.T) {
	exp, p := memoryProvider()
	logger := slog.New(NewLogHandler(LogHandlerOptions{LoggerProvider: p}))
	logger.Debug("d")
	logger.Info("i")
	if got := strings.Join(exp.bodies(), ","); got != "i" {
		t.Fatalf("bodies = %q", got)
	}
}

func TestSlogSeverityMapping(t *testing.T) {
	cases := map[slog.Level]otellog.Severity{
		slog.LevelDebug - 4: 1, slog.LevelDebug: 5, slog.LevelInfo: 9,
		slog.LevelWarn: 13, slog.LevelError: 17, slog.LevelError + 1: 21,
	}
	for level, want := range cases {
		if got := slogSeverity(level); got != want {
			t.Errorf("slogSeverity(%v) = %v, want %v", level, got, want)
		}
	}
}

func TestResolveLogLevel(t *testing.T) {
	cases := map[string]otellog.Severity{
		"": 9, "debug": 5, "WARN": 13, "warning": 13, "fatal": 21, "critical": 21, "trace": 1, "error": 17, "loud": 9,
	}
	for in, want := range cases {
		if got := ResolveLogLevel(in); got != want {
			t.Errorf("ResolveLogLevel(%q) = %v, want %v", in, got, want)
		}
	}
}

func TestAppLogsLinkToTheActiveSpan(t *testing.T) {
	exp, p := memoryProvider()
	logger := slog.New(NewLogHandler(LogHandlerOptions{LoggerProvider: p}))
	tp := sdktrace.NewTracerProvider()
	ctx, span := tp.Tracer("test").Start(context.Background(), "work")
	logger.InfoContext(ctx, "inside")
	span.End()
	logger.Info("outside")
	records := exp.all()
	if len(records) != 2 {
		t.Fatalf("records = %d", len(records))
	}
	sc := span.SpanContext()
	if records[0].TraceID() != sc.TraceID() || records[0].SpanID() != sc.SpanID() {
		t.Fatalf("not linked: %v %v", records[0].TraceID(), records[0].SpanID())
	}
	if records[1].TraceID().IsValid() {
		t.Fatalf("outside record has a trace id")
	}
}

func TestAppLogsMaskCredentialsAndTokens(t *testing.T) {
	exp, p := memoryProvider()
	logger := slog.New(NewLogHandler(LogHandlerOptions{LoggerProvider: p}))
	logger.Info("login password=hunter2&next=1",
		"header", "Authorization: Bearer abcdefghijklmnopqrstuvwxyz0123",
		"note", "t k3j4h5g6f7d8s9a0q1w2e3r4",
		"count", 3)
	r := exp.all()[0]
	if got := r.Body().AsString(); got != "login password=***&next=1" {
		t.Fatalf("body = %q", got)
	}
	a := attrsOf(r)
	if got := a["header"].AsString(); strings.Contains(got, "abcdefghij") {
		t.Fatalf("header not masked: %q", got)
	}
	if got := a["note"].AsString(); got != "t ***" {
		t.Fatalf("note = %q", got)
	}
	if a["count"].AsInt64() != 3 {
		t.Fatalf("count = %v", a["count"])
	}
	// The call site is kept as it is.
	if !strings.HasSuffix(a["code.file.path"].AsString(), "app_logs_test.go") || a["code.line.number"].AsInt64() == 0 ||
		!strings.Contains(a["code.function.name"].AsString(), "TestAppLogsMaskCredentialsAndTokens") {
		t.Fatalf("code attributes = %v", a)
	}
}

func TestMaskLogTextTruncates(t *testing.T) {
	long := strings.Repeat("a ", 20000)
	if got := MaskLogText(long, maxLogBodyChars); len([]rune(got)) != maxLogBodyChars {
		t.Fatalf("len = %d", len([]rune(got)))
	}
	if got := MaskLogText("no secrets here", 100); got != "no secrets here" {
		t.Fatalf("got %q", got)
	}
}

func TestAppLogsGroupsAttributesAndErrors(t *testing.T) {
	exp, p := memoryProvider()
	logger := slog.New(NewLogHandler(LogHandlerOptions{LoggerProvider: p})).With("order_id", "o-1").WithGroup("req")
	logger.Error("failed", "id", 7, slog.Group("user", "plan", "pro"), "err", errors.New("disk full"))
	a := attrsOf(exp.all()[0])
	if a["order_id"].AsString() != "o-1" || a["req.id"].AsInt64() != 7 || a["req.user.plan"].AsString() != "pro" {
		t.Fatalf("attributes = %v", a)
	}
	if a["exception.type"].AsString() != "*errors.errorString" || a["exception.message"].AsString() != "disk full" {
		t.Fatalf("exception = %v", a)
	}
}

func TestAppLogsAreRateLimited(t *testing.T) {
	exp, p := memoryProvider()
	h := NewLogHandler(LogHandlerOptions{LoggerProvider: p, MaxPerSecond: 3}).(*logHandler)
	now := time.Unix(1000, 0)
	h.limiter.now = func() time.Time { return now }
	logger := slog.New(h)
	for i := 0; i < 10; i++ {
		logger.Info("storm")
	}
	if n := len(exp.all()); n != 3 {
		t.Fatalf("sent %d in one second, want 3", n)
	}
	now = now.Add(time.Second)
	logger.Info("next second")
	if n := len(exp.all()); n != 4 {
		t.Fatalf("sent %d, want 4", n)
	}
}

func TestAppLogsNeverExportTheirOwnRecords(t *testing.T) {
	exp, p := memoryProvider()
	for _, name := range []string{"shield360", "shield360.rasp", "opentelemetry.exporter", "go.opentelemetry.io/otel"} {
		slog.New(NewLogHandler(LogHandlerOptions{LoggerProvider: p, Name: name})).Error("sdk")
	}
	app := slog.New(NewLogHandler(LogHandlerOptions{LoggerProvider: p, Name: "shield360_app"}))
	app.Info("Shield360 initialized successfully (Environment: x)")
	app.Info("shield360: application logs unavailable")
	app.Warn("not ours")
	if got := strings.Join(exp.bodies(), ","); got != "not ours" {
		t.Fatalf("bodies = %q", got)
	}
}

// loggingExporter logs with the context it is given, as an exporter's HTTP
// client might; the record must not loop back.
type loggingExporter struct {
	memoryExporter
	logger *slog.Logger
}

func (l *loggingExporter) Export(ctx context.Context, records []sdklog.Record) error {
	l.logger.WarnContext(ctx, "logged by the exporter")
	return l.memoryExporter.Export(ctx, records)
}

func TestAppLogsDoNotLoopThroughTheExporter(t *testing.T) {
	exp := &loggingExporter{}
	p := sdklog.NewLoggerProvider(sdklog.WithProcessor(sdklog.NewSimpleProcessor(exp)))
	exp.logger = slog.New(NewLogHandler(LogHandlerOptions{LoggerProvider: p}))
	exp.logger.Error("once")
	if got := strings.Join(exp.bodies(), ","); got != "once" {
		t.Fatalf("bodies = %q", got)
	}
}

type panickingProvider struct{ embedded.LoggerProvider }

func (panickingProvider) Logger(string, ...otellog.LoggerOption) otellog.Logger { panic("broken") }

func TestAppLogsFailOpen(t *testing.T) {
	// An exporter that fails.
	exp, p := memoryProvider()
	exp.err = errors.New("endpoint down")
	slog.New(NewLogHandler(LogHandlerOptions{LoggerProvider: p})).Info("still fine")
	// A provider that panics.
	h := NewLogHandler(LogHandlerOptions{LoggerProvider: panickingProvider{}})
	if err := h.Handle(context.Background(), slog.NewRecord(time.Now(), slog.LevelError, "x", 0)); err != nil {
		t.Fatalf("Handle returned %v", err)
	}
	slog.New(h).Error("no panic reaches the app")
}

func TestAppLogsAreOffByDefault(t *testing.T) {
	StopCapturingLogs()
	t.Setenv("SHIELD360_CAPTURE_LOGS", "")
	if resolveCaptureLogs(Config{}) {
		t.Fatal("on without being asked")
	}
	h := LogHandler("lib")
	if h.Enabled(context.Background(), slog.LevelError) {
		t.Fatal("enabled while application logs are off")
	}
	if err := h.Handle(context.Background(), slog.NewRecord(time.Now(), slog.LevelError, "x", 0)); err != nil {
		t.Fatal(err)
	}
	if CaptureLogs("info") {
		t.Fatal("CaptureLogs worked without Init")
	}
}

func TestCaptureLogsFromTheEnvironment(t *testing.T) {
	off, on := false, true
	t.Setenv("SHIELD360_CAPTURE_LOGS", "true")
	t.Setenv("SHIELD360_LOG_LEVEL", "ERROR")
	if !resolveCaptureLogs(Config{}) || resolveLogLevel(Config{}) != "ERROR" {
		t.Fatal("environment not read")
	}
	if resolveCaptureLogs(Config{CaptureLogs: &off}) {
		t.Fatal("an explicit false must win over the environment")
	}
	if resolveLogLevel(Config{LogLevel: "debug"}) != "debug" || !resolveCaptureLogs(Config{CaptureLogs: &on}) {
		t.Fatal("explicit options must win")
	}
}

func TestEnableAppLogsForwardsTheDefaultLoggerAndRestoresIt(t *testing.T) {
	exp, p := memoryProvider()
	var printed bytes.Buffer
	prevWriter, prevFlags := stdlog.Writer(), stdlog.Flags()
	stdlog.SetOutput(&printed)
	stdlog.SetFlags(0)
	defer func() {
		stdlog.SetOutput(prevWriter)
		stdlog.SetFlags(prevFlags)
	}()
	before := slog.Default()

	enableAppLogs(p, ResolveLogLevel("info"), true)
	slog.Info("hello", "k", "v")
	stdlog.Printf("from the log package")
	library := slog.New(LogHandler("lib"))
	library.Warn("from a library")
	StopCapturingLogs()
	slog.Info("after stop")

	if got := strings.Join(exp.bodies(), ","); got != "hello,from the log package,from a library" {
		t.Fatalf("bodies = %q", got)
	}
	if out := printed.String(); !strings.Contains(out, "INFO hello k=v") || !strings.Contains(out, "from the log package") || !strings.Contains(out, "after stop") {
		t.Fatalf("console output = %q", out)
	}
	if slog.Default() != before {
		t.Fatal("slog.Default not restored")
	}
	if scope := exp.all()[2].InstrumentationScope().Name; scope != "lib" {
		t.Fatalf("scope = %q", scope)
	}
}

func TestInitSendsLogsToTheIngestRouteWithTheKey(t *testing.T) {
	type request struct {
		path, auth string
		body       []byte
	}
	got := make(chan request, 4)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		got <- request{r.URL.Path, r.Header.Get("Authorization"), b}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	before := slog.Default()
	on := true
	err := Init(Config{
		OtlpEndpoint:    srv.URL + "/api/ingest/otlp",
		OtlpHeaders:     map[string]string{"Authorization": testBearer},
		ApplicationName: "logs-app",
		Environment:     "test",
		DisableTracing:  true,
		DisableMetrics:  true,
		DisableBatch:    true,
		CaptureLogs:     &on,
	})
	if err != nil {
		t.Fatal(err)
	}
	slog.Info("order placed", "order_id", "o-1")
	if err := Shutdown(context.Background()); err != nil {
		t.Fatal(err)
	}
	if slog.Default() != before {
		t.Fatal("Shutdown did not restore slog.Default")
	}
	select {
	case r := <-got:
		if r.path != "/api/ingest/otlp/v1/logs" {
			t.Fatalf("path = %q", r.path)
		}
		if r.auth != testBearer {
			t.Fatalf("authorization header not sent")
		}
		for _, want := range []string{"order placed", "logs-app", "deployment.environment", "o-1"} {
			if !bytes.Contains(r.body, []byte(want)) {
				t.Fatalf("payload lacks %q", want)
			}
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no logs request")
	}
}

// A placeholder header value; never a real key.
const testBearer = "Bearer test-key-1"

// The masking contract (sdk/rasp/README.md, "Masking") through the slog bridge.
func TestAppLogsMaskByNameListsAndQuotedValues(t *testing.T) {
	exp, p := memoryProvider()
	logger := slog.New(NewLogHandler(LogHandlerOptions{LoggerProvider: p}))
	logger.Info(`sent Authorization: Bearer abc and {"password":"pw1"}`,
		"password", "pw1",
		"x-api-key", "short",
		slog.Group("user", "sessionId", "s-1", "name", "ann"),
		"otp", 123456,
		"tags", []string{"token=abc", "ok"},
	)
	r := exp.all()[0]
	if got := r.Body().AsString(); got != `sent Authorization: *** and {"password":"***"}` {
		t.Fatalf("body = %q", got)
	}
	a := attrsOf(r)
	for _, k := range []string{"password", "x-api-key", "user.sessionId", "otp"} {
		if got := a[k].AsString(); got != "***" {
			t.Fatalf("%s = %v", k, a[k])
		}
	}
	if got := a["user.name"].AsString(); got != "ann" {
		t.Fatalf("user.name = %q", got)
	}
	tags := a["tags"].AsSlice()
	if len(tags) != 2 || tags[0].AsString() != "token=***" || tags[1].AsString() != "ok" {
		t.Fatalf("tags = %v", a["tags"])
	}
}

func TestAppLogsKeepReadableIdentifiers(t *testing.T) {
	exp, p := memoryProvider()
	logger := slog.New(NewLogHandler(LogHandlerOptions{LoggerProvider: p}))
	msg := "java.lang.ArrayIndexOutOfBoundsException at /home/runner/work/app/src/orders/service.go:42"
	logger.Error(msg, "stack", "at com.example.orders.OrderService.placeOrder(OrderService.java:42)")
	r := exp.all()[0]
	if got := r.Body().AsString(); got != msg {
		t.Fatalf("body = %q", got)
	}
	if got := attrsOf(r)["stack"].AsString(); got != "at com.example.orders.OrderService.placeOrder(OrderService.java:42)" {
		t.Fatalf("stack = %q", got)
	}
}

func TestMaskLogTextMasksBeforeCutting(t *testing.T) {
	// A hex token crossing the body cut: masked whole, not cut to a short visible prefix.
	prefix := strings.Repeat("a ", (maxLogBodyChars-10)/2)
	got := MaskLogText(prefix+"9f86d081884c7d659a2feaa0c55ad015a3bf4f1b", maxLogBodyChars)
	if got != prefix+"***" {
		t.Fatalf("tail = %q", got[len(got)-20:])
	}
}
