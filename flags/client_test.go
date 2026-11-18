package flags

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
)

var checkoutFlag = map[string]any{
	"key": "new-checkout", "type": "boolean",
	"variations":   []any{map[string]any{"key": "on", "value": true}, map[string]any{"key": "off", "value": false}},
	"offVariation": "off", "on": true,
	"rules": []any{map[string]any{
		"id":         "pro",
		"conditions": []any{map[string]any{"attribute": "plan", "operator": "equals", "values": []any{"pro"}}},
		"serve":      map[string]any{"variation": "on"},
	}},
	"fallthrough": map[string]any{"variation": "off"}, "salt": "s1", "version": 3, "appName": nil,
}

var modelFlag = map[string]any{
	"key": "model-choice", "type": "string",
	"variations":   []any{map[string]any{"key": "a", "value": "openai/gpt-4o-mini"}, map[string]any{"key": "b", "value": "anthropic/claude-haiku"}},
	"offVariation": "a", "on": true, "rules": []any{},
	"fallthrough": map[string]any{"variation": "b"}, "salt": "s2", "appName": "checkout-api",
}

var segmentFlag = map[string]any{
	"key": "beta-banner", "type": "string",
	"variations":   []any{map[string]any{"key": "plain", "value": "plain"}, map[string]any{"key": "beta", "value": "beta"}},
	"offVariation": "plain", "on": true,
	"rules": []any{map[string]any{
		"id":         "beta",
		"conditions": []any{map[string]any{"attribute": "segment", "operator": "in_segment", "values": []any{"beta-users"}}},
		"serve":      map[string]any{"variation": "beta"},
	}},
	"fallthrough": map[string]any{"variation": "plain"}, "salt": "s3",
}

var betaSegment = map[string]any{
	"key":        "beta-users",
	"conditions": []any{map[string]any{"attribute": "groups", "operator": "in", "values": []any{"beta"}}},
}

func onOff(key string, on bool) map[string]any {
	return map[string]any{
		"key": key, "type": "boolean",
		"variations":   []any{map[string]any{"key": "on", "value": true}, map[string]any{"key": "off", "value": false}},
		"offVariation": "off", "on": on, "rules": []any{},
		"fallthrough": map[string]any{"variation": "on"}, "salt": "s4",
	}
}

func stringFlag(key string, value any) map[string]any {
	t := "string"
	if _, ok := value.(map[string]any); ok {
		t = "json"
	}
	return map[string]any{
		"key": key, "type": t,
		"variations":   []any{map[string]any{"key": "a", "value": value}, map[string]any{"key": "b", "value": value}},
		"offVariation": "a", "on": true, "rules": []any{},
		"fallthrough": map[string]any{"variation": "b"}, "salt": "s5",
	}
}

type reply struct {
	status int
	body   string
	etag   string
}

// fakeServer answers the rules feed with scripted replies (the last one
// repeats) and records each request.
type fakeServer struct {
	*httptest.Server
	mu       sync.Mutex
	replies  []reply
	requests []*http.Request
	posts    []*http.Request
	prompts  []map[string]any
	prompt   func(w http.ResponseWriter, body map[string]any)
}

func newServer(t *testing.T, replies ...reply) *fakeServer {
	t.Helper()
	s := &fakeServer{replies: replies}
	s.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		defer s.mu.Unlock()
		if r.URL.Path != PromptPath {
			s.requests = append(s.requests, r.Clone(context.Background()))
		}
		if r.URL.Path == PromptPath {
			data, _ := io.ReadAll(r.Body)
			var body map[string]any
			_ = json.Unmarshal(data, &body)
			s.prompts = append(s.prompts, body)
			s.posts = append(s.posts, r.Clone(context.Background()))
			if s.prompt != nil {
				s.prompt(w, body)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"name": body["name"], "version": body["version"], "prompt": "hi"}})
			return
		}
		if r.URL.Path != RulesPath {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		rep := s.replies[0]
		if len(s.replies) > 1 {
			s.replies = s.replies[1:]
		}
		if rep.etag != "" {
			w.Header().Set("ETag", rep.etag)
		}
		w.WriteHeader(rep.status)
		_, _ = io.WriteString(w, rep.body)
	}))
	t.Cleanup(s.Close)
	return s
}

func (s *fakeServer) request(i int) *http.Request {
	s.mu.Lock()
	defer s.mu.Unlock()
	if i < 0 {
		i += len(s.requests)
	}
	return s.requests[i]
}

func (s *fakeServer) promptBody(i int) (*http.Request, map[string]any) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.posts[i], s.prompts[i]
}

func feed(t *testing.T, flags []any, segments ...any) string {
	t.Helper()
	body := map[string]any{"version": "v1", "flags": flags}
	if segments != nil {
		body["segments"] = segments
	}
	data, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

// newClient makes a client against the fake server that does not poll:
// tests drive fetches with Refresh.
func newClient(t *testing.T, s *fakeServer, app string) *Client {
	t.Helper()
	c := New(Options{URL: s.URL + "/", APIKey: "k1", ApplicationName: app, PollInterval: time.Hour})
	c.manual = true
	return c
}

func TestDefaultsUntilRulesArriveThenLocalEvaluation(t *testing.T) {
	s := newServer(t, reply{status: 500})
	c := newClient(t, s, "checkout-api")
	ctx := context.Background()
	if d := c.GetFlagDetail(ctx, "new-checkout", nil, false); d.Reason.Kind != ReasonNotReady || d.Value != false || d.Variation != "" {
		t.Fatalf("before rules: %+v", d)
	}
	if c.Refresh() {
		t.Fatal("a 500 is not current rules")
	}
	if c.IsEnabled(ctx, "new-checkout", map[string]any{"plan": "pro"}) {
		t.Fatal("served before rules arrived")
	}

	s.mu.Lock()
	s.replies = []reply{{status: 200, body: feed(t, []any{checkoutFlag, modelFlag}), etag: `"v1"`}}
	s.mu.Unlock()
	if !c.Refresh() {
		t.Fatal("Refresh failed")
	}
	req := s.request(-1)
	if req.URL.Path != RulesPath || req.Header.Get("Authorization") != "Bearer k1" || req.Header.Get("Accept") != "application/json" {
		t.Fatalf("request: %s %v", req.URL.Path, req.Header)
	}
	if !c.IsEnabled(ctx, "new-checkout", map[string]any{"key": "u1", "plan": "pro"}) {
		t.Error("pro should be on")
	}
	if c.IsEnabled(ctx, "new-checkout", map[string]any{"key": "u1", "plan": "free"}) {
		t.Error("free should be off")
	}
	if got := c.GetString(ctx, "model-choice", map[string]any{"key": "u1"}, "x"); got != "anthropic/claude-haiku" {
		t.Errorf("model-choice = %q", got)
	}
	if d := c.GetFlagDetail(ctx, "missing", nil, "fallback"); d.Value != "fallback" || d.Reason.Kind != ReasonFlagNotFound {
		t.Errorf("missing: %+v", d)
	}
	if c.Version() != "v1" {
		t.Errorf("Version = %q", c.Version())
	}
}

func TestSendsTheETagAndKeepsRulesOn304(t *testing.T) {
	s := newServer(t, reply{status: 200, body: feed(t, []any{checkoutFlag}), etag: `"v1"`}, reply{status: 304})
	c := newClient(t, s, "")
	c.Refresh()
	if !c.Refresh() {
		t.Fatal("a 304 is current rules")
	}
	if got := s.request(1).Header.Get("If-None-Match"); got != `"v1"` {
		t.Errorf("If-None-Match = %q", got)
	}
	if s.request(0).Header.Get("If-None-Match") != "" {
		t.Error("first request must not send If-None-Match")
	}
	if !c.IsEnabled(context.Background(), "new-checkout", map[string]any{"plan": "pro"}) {
		t.Error("rules lost on 304")
	}
}

func TestKeepsLastGoodRulesAndNeverPanicsOnGarbage(t *testing.T) {
	s := newServer(t,
		reply{status: 200, body: feed(t, []any{checkoutFlag})},
		reply{status: 500},
		reply{status: 200, body: "garbage"},
		reply{status: 200, body: `"a string"`},
		reply{status: 200, body: `{"flags": "nope"}`},
		reply{status: 200, body: `{"flags": [null, 1, "x", {"key": 5}], "segments": [null, {"key": 1}]}`},
	)
	c := newClient(t, s, "")
	ctx := context.Background()
	c.Refresh()
	for i := 0; i < 4; i++ {
		if c.Refresh() {
			t.Fatalf("garbage reply %d accepted", i)
		}
		if !c.IsEnabled(ctx, "new-checkout", map[string]any{"plan": "pro"}) {
			t.Fatalf("lost rules after garbage reply %d", i)
		}
	}
	if !c.Refresh() {
		t.Fatal("a valid body with only invalid flags is still current")
	}
	if d := c.GetFlagDetail(ctx, "new-checkout", map[string]any{"plan": "pro"}, true); d.Reason.Kind != ReasonFlagNotFound {
		t.Errorf("invalid flags must be dropped: %+v", d)
	}
	// Odd contexts and defaults never panic.
	_ = c.GetFlag(nil, "new-checkout", map[string]any{"plan": make(chan int), "x": func() {}}, struct{}{}) //nolint:staticcheck // nil ctx on purpose
}

func TestLeavesOutInvalidFlagsAndOtherApps(t *testing.T) {
	broken := map[string]any{}
	for k, v := range checkoutFlag {
		broken[k] = v
	}
	broken["key"], broken["offVariation"] = "broken", "nope"
	s := newServer(t, reply{status: 200, body: feed(t, []any{broken, modelFlag})})
	c := newClient(t, s, "billing")
	c.Refresh()
	ctx := context.Background()
	if d := c.GetFlagDetail(ctx, "broken", nil, true); d.Value != true || d.Variation != "" || d.Reason.Kind != ReasonFlagNotFound {
		t.Errorf("broken: %+v", d)
	}
	if d := c.GetFlagDetail(ctx, "model-choice", nil, "x"); d.Reason.Kind != ReasonFlagNotFound {
		t.Errorf("other app's flag served: %+v", d)
	}
	right := newClient(t, s, "checkout-api")
	right.Refresh()
	if got := right.GetString(ctx, "model-choice", nil, "x"); got != "anthropic/claude-haiku" {
		t.Errorf("own app's flag = %q", got)
	}
}

func TestWrongTypeReturnsTheDefault(t *testing.T) {
	s := newServer(t, reply{status: 200, body: feed(t, []any{modelFlag, checkoutFlag})})
	c := newClient(t, s, "checkout-api")
	c.Refresh()
	ctx := context.Background()
	if d := c.GetFlagDetail(ctx, "model-choice", nil, 7); d.Value != 7 || d.Variation != "" || d.Reason.Kind != ReasonWrongType {
		t.Errorf("number default for a string flag: %+v", d)
	}
	if got := c.GetNumber(ctx, "model-choice", nil, 1.5); got != 1.5 {
		t.Errorf("GetNumber = %v", got)
	}
	if got := c.GetBool(ctx, "model-choice", nil, true); got != true {
		t.Errorf("GetBool = %v", got)
	}
	if got := c.GetJSON(ctx, "model-choice", nil, map[string]any{"d": 1}); got.(map[string]any)["d"] != 1 {
		t.Errorf("GetJSON = %v", got)
	}
	if got := c.GetFlag(ctx, "model-choice", nil, nil); got != "anthropic/claude-haiku" {
		t.Errorf("nil default accepts any kind: %v", got)
	}
}

func TestStampsTheVariationOnTheRecordingSpan(t *testing.T) {
	s := newServer(t, reply{status: 200, body: feed(t, []any{checkoutFlag})})
	c := newClient(t, s, "")
	c.Refresh()
	recorder := tracetest.NewSpanRecorder()
	tp := sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(recorder))
	defer func() { _ = tp.Shutdown(context.Background()) }()
	ctx, span := tp.Tracer("test").Start(context.Background(), "work")
	c.IsEnabled(ctx, "new-checkout", map[string]any{"plan": "pro"})
	c.GetFlag(ctx, "missing", nil, false)
	span.End()
	ended := recorder.Ended()
	if len(ended) != 1 {
		t.Fatalf("%d spans", len(ended))
	}
	attrs := map[string]string{}
	for _, a := range ended[0].Attributes() {
		attrs[string(a.Key)] = a.Value.Emit()
	}
	if attrs["shield360.flag.new-checkout"] != "on" || len(attrs) != 1 {
		t.Errorf("attributes = %v", attrs)
	}

	quiet := New(Options{URL: s.URL, APIKey: "k1", PollInterval: time.Hour, DisableSpanAttributes: true})
	quiet.manual = true
	quiet.Refresh()
	ctx, span = tp.Tracer("test").Start(context.Background(), "quiet")
	quiet.IsEnabled(ctx, "new-checkout", map[string]any{"plan": "pro"})
	span.End()
	if got := recorder.Ended()[1].Attributes(); len(got) != 0 {
		t.Errorf("DisableSpanAttributes still stamped %v", got)
	}
}

func TestSegmentsInTheFeed(t *testing.T) {
	invalid := map[string]any{"key": "beta-users", "conditions": []any{}}
	s := newServer(t,
		reply{status: 200, body: feed(t, []any{segmentFlag}, betaSegment)},
		reply{status: 200, body: feed(t, []any{segmentFlag}, invalid)},
		reply{status: 200, body: feed(t, []any{segmentFlag})},
	)
	c := newClient(t, s, "")
	ctx := context.Background()
	beta := map[string]any{"key": "u1", "groups": []string{"staff", "beta"}}
	c.Refresh()
	if d := c.GetFlagDetail(ctx, "beta-banner", beta, "x"); d.Value != "beta" || d.Reason.Kind != ReasonRuleMatch || d.Reason.RuleID != "beta" {
		t.Errorf("in segment: %+v", d)
	}
	if got := c.GetString(ctx, "beta-banner", map[string]any{"groups": []string{"staff"}}, "x"); got != "plain" {
		t.Errorf("outside segment: %q", got)
	}
	c.Refresh() // the segment no longer validates: it is dropped, and unknown segments never match
	if got := c.GetString(ctx, "beta-banner", beta, "x"); got != "plain" {
		t.Errorf("invalid segment: %q", got)
	}
	c.Refresh() // no segments at all
	if got := c.GetString(ctx, "beta-banner", beta, "x"); got != "plain" {
		t.Errorf("absent segments: %q", got)
	}
}

func TestModelAndKillSwitch(t *testing.T) {
	ctx := context.Background()
	notReady := New(Options{URL: "http://127.0.0.1:1", APIKey: "k1", PollInterval: time.Hour})
	defer notReady.Close()
	if notReady.KillSwitch(ctx, "ai-off", nil) {
		t.Error("kill switch engaged before rules arrived")
	}
	if got := notReady.Model(ctx, "model-choice", nil, "openai/gpt-4o-mini"); got != "openai/gpt-4o-mini" {
		t.Errorf("Model default = %q", got)
	}

	s := newServer(t, reply{status: 200, body: feed(t, []any{modelFlag, onOff("ai-off", false), onOff("ai-on", true), stringFlag("blank-model", " ")})})
	c := newClient(t, s, "checkout-api")
	c.Refresh()
	if got := c.Model(ctx, "model-choice", nil, "openai/gpt-4o-mini"); got != "anthropic/claude-haiku" {
		t.Errorf("Model = %q", got)
	}
	if got := c.Model(ctx, "blank-model", nil, "openai/gpt-4o-mini"); got != "openai/gpt-4o-mini" {
		t.Errorf("blank Model = %q", got)
	}
	if !c.KillSwitch(ctx, "ai-off", nil) {
		t.Error("a flag serving false engages the switch")
	}
	if c.KillSwitch(ctx, "ai-on", nil) {
		t.Error("a flag serving true leaves the switch off")
	}
	if c.KillSwitch(ctx, "unknown", nil) {
		t.Error("an unknown switch is not engaged")
	}
}

func TestPromptHelper(t *testing.T) {
	ctx := context.Background()
	s := newServer(t, reply{status: 200, body: feed(t, []any{
		stringFlag("prompt-at", "support-reply@3"),
		stringFlag("prompt-name", "support-reply"),
		stringFlag("prompt-object", map[string]any{"name": "triage", "version": "1.2.0"}),
		stringFlag("prompt-bad", map[string]any{"version": "1"}),
	})})
	c := newClient(t, s, "")
	c.Refresh()
	def := PromptRef{Name: "fallback", Version: "2"}

	got := c.Prompt(ctx, "prompt-at", map[string]any{"key": "u1"}, def, PromptOptions{Compile: true, Variables: map[string]any{"user": "Ana"}})
	if got.Name != "support-reply" || got.Version != "3" || got.Variation != "b" || got.Err != "" || got.Prompt == nil {
		t.Fatalf("name@version: %+v", got)
	}
	req, body := s.promptBody(0)
	if req.Method != http.MethodPost || req.Header.Get("Authorization") != "Bearer k1" || req.Header.Get("Content-Type") != "application/json" {
		t.Errorf("prompt request %s %v", req.Method, req.Header)
	}
	if body["name"] != "support-reply" || body["version"] != "3" || body["shouldCompile"] != true || body["source"] != "go-sdk" ||
		body["variables"].(map[string]any)["user"] != "Ana" {
		t.Errorf("prompt body = %v", body)
	}

	if got := c.Prompt(ctx, "prompt-name", nil, def, PromptOptions{}); got.Name != "support-reply" || got.Version != "" || got.Err != "" {
		t.Errorf("name only: %+v", got)
	}
	if _, second := s.promptBody(1); second["shouldCompile"] != false || second["version"] != nil {
		t.Errorf("name-only body = %v", second)
	}
	if got := c.Prompt(ctx, "prompt-object", nil, def, PromptOptions{}); got.Name != "triage" || got.Version != "1.2.0" || got.Variation != "b" {
		t.Errorf("object: %+v", got)
	}
	if got := c.Prompt(ctx, "prompt-bad", nil, def, PromptOptions{}); got.Name != "fallback" || got.Version != "2" || got.Variation != "" || got.Err != "" {
		t.Errorf("unusable value falls back to def: %+v", got)
	}
	if got := c.Prompt(ctx, "unknown", nil, PromptRef{}, PromptOptions{}); got.Err == "" || got.Prompt != nil {
		t.Errorf("no name anywhere: %+v", got)
	}

	s.mu.Lock()
	s.prompt = func(w http.ResponseWriter, _ map[string]any) { w.WriteHeader(http.StatusBadGateway) }
	s.mu.Unlock()
	if got := c.Prompt(ctx, "prompt-name", nil, def, PromptOptions{}); got.Err == "" || got.Prompt != nil || got.Name != "support-reply" {
		t.Errorf("HTTP failure: %+v", got)
	}
	s.mu.Lock()
	s.prompt = func(w http.ResponseWriter, _ map[string]any) { _, _ = io.WriteString(w, `{"err": "Prompt not found"}`) }
	s.mu.Unlock()
	if got := c.Prompt(ctx, "prompt-name", nil, def, PromptOptions{}); got.Err != "Prompt not found" || got.Prompt != nil {
		t.Errorf("server error: %+v", got)
	}
	s.mu.Lock()
	s.prompt = func(w http.ResponseWriter, _ map[string]any) { _, _ = io.WriteString(w, `garbage`) }
	s.mu.Unlock()
	if got := c.Prompt(ctx, "prompt-name", nil, def, PromptOptions{Variables: map[string]any{"bad": make(chan int)}}); got.Err == "" {
		t.Errorf("unmarshalable variables: %+v", got)
	}
	if got := c.Prompt(nil, "prompt-name", nil, def, PromptOptions{}); got.Err == "" || got.Prompt != nil { //nolint:staticcheck // nil ctx on purpose
		t.Errorf("garbage response: %+v", got)
	}
}

func TestPollingStartsOnFirstUseAndWaitUntilReady(t *testing.T) {
	s := newServer(t, reply{status: 200, body: feed(t, []any{checkoutFlag}), etag: `"v1"`})
	c := New(Options{URL: s.URL, APIKey: "k1", PollInterval: time.Hour})
	defer c.Close()
	if !c.WaitUntilReady(5 * time.Second) {
		t.Fatal("never became ready")
	}
	if !c.IsEnabled(context.Background(), "new-checkout", map[string]any{"plan": "pro"}) {
		t.Error("not served after WaitUntilReady")
	}
	c.Close()
	c.Close() // twice is fine

	unreachable := New(Options{URL: "http://127.0.0.1:1", APIKey: "k1", PollInterval: time.Hour, Timeout: time.Second})
	defer unreachable.Close()
	if unreachable.WaitUntilReady(50 * time.Millisecond) {
		t.Error("ready without rules")
	}
}

func TestDestinationResolution(t *testing.T) {
	s := newServer(t, reply{status: 200, body: feed(t, []any{checkoutFlag})})
	t.Setenv("SHIELD360_URL", "")
	t.Setenv("SHIELD360_API_KEY", "")
	defer SetDefaults(Defaults{})

	none := New(Options{})
	if none.Refresh() {
		t.Error("fetched without a destination")
	}

	t.Setenv("SHIELD360_URL", s.URL+"/")
	t.Setenv("SHIELD360_API_KEY", "env-key")
	fromEnv := New(Options{})
	if !fromEnv.Refresh() || s.request(0).Header.Get("Authorization") != "Bearer env-key" {
		t.Error("env destination not used")
	}

	SetDefaults(Defaults{URL: s.URL, APIKey: "init-key", ApplicationName: "checkout-api"})
	fromInit := New(Options{})
	if !fromInit.Refresh() || s.request(1).Header.Get("Authorization") != "Bearer init-key" {
		t.Error("Init destination must win over env")
	}
	if fromInit.applicationName() != "checkout-api" {
		t.Error("Init application name not used")
	}

	explicit := New(Options{URL: s.URL, APIKey: "opt-key", ApplicationName: "billing"})
	if !explicit.Refresh() || s.request(2).Header.Get("Authorization") != "Bearer opt-key" || explicit.applicationName() != "billing" {
		t.Error("Options must win")
	}
	if Default() == nil || Default() != Default() {
		t.Error("Default client")
	}
}

func TestConcurrentUseIsSafe(t *testing.T) {
	s := newServer(t, reply{status: 200, body: feed(t, []any{checkoutFlag, segmentFlag}, betaSegment), etag: `"v1"`}, reply{status: 304})
	c := newClient(t, s, "")
	c.Refresh()
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 200; j++ {
				if j%50 == 0 {
					c.Refresh()
				}
				c.IsEnabled(context.Background(), "new-checkout", map[string]any{"plan": "pro"})
				c.GetString(context.Background(), "beta-banner", map[string]any{"groups": []any{"beta"}}, "x")
			}
		}()
	}
	wg.Wait()
}

func TestPollIntervalAndTimeoutDefaults(t *testing.T) {
	cases := map[time.Duration]time.Duration{0: DefaultPollInterval, -1: DefaultPollInterval, time.Second: MinPollInterval, time.Minute: time.Minute}
	for in, want := range cases {
		if got := New(Options{PollInterval: in}).pollInterval(); got != want {
			t.Errorf("pollInterval(%v) = %v, want %v", in, got, want)
		}
	}
	if got := New(Options{}).timeout(); got != DefaultTimeout {
		t.Errorf("timeout = %v", got)
	}
}
