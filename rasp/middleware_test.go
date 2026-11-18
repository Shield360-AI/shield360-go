package rasp

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// Middleware: inputs recorded in the request's context (query, route
// parameters, body, cookies, the input headers), virtual patches run before
// the handler, the block error mapped to the contract's 403.

func exampleRule() VirtualPatchRule {
	for _, r := range BuiltInRules {
		if r.Example {
			return r
		}
	}
	panic("no example rule")
}

// bodyRule is a body-reading rule that applies in Go: the built-in body
// rules are Node-only, so the test pins its own rule through the signed
// config path, built from the shape of the built-in vp.react2shell.
func bodyRule() VirtualPatchRule {
	for _, r := range BuiltInRules {
		if r.ID == "vp.react2shell" {
			r.ID = "vp.go-body-test"
			r.Runtimes = nil
			return r
		}
	}
	panic("no vp.react2shell")
}

func setMode(t *testing.T, vp Mode) *eventLog {
	return setupEngine(t, engineSettings{attacks: map[AttackType]Mode{VirtualPatch: vp}, modelOutput: true})
}

func keysOf(r *http.Request) map[string]string {
	c := FromContext(r.Context())
	if c == nil {
		return nil
	}
	out := map[string]string{}
	for _, i := range c.Inputs() {
		if _, ok := out[i.Key]; !ok {
			out[i.Key] = i.Value
		}
	}
	return out
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func do(t *testing.T, h http.Handler, method, target string, body string, headers map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	var rd io.Reader
	if body != "" {
		rd = strings.NewReader(body)
	}
	r := httptest.NewRequest(method, target, rd)
	for k, v := range headers {
		r.Header.Set(k, v)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

func decode(t *testing.T, w *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &m); err != nil {
		t.Fatalf("body %q: %v", w.Body.String(), err)
	}
	return m
}

func TestMiddleware(t *testing.T) {
	ex := exampleRule()
	exHeaders := requestFor(ex).Headers

	t.Run("records query, cookies and the input headers in the request context only", func(t *testing.T) {
		setMode(t, ModeMonitor)
		var outside *Context
		h := Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { writeJSON(w, 200, keysOf(r)) }))
		w := do(t, h, "GET", "/items/42?q="+url.QueryEscape("hello world")+"&tag=a&tag=b", "", map[string]string{
			"Cookie": "sid=abc123; theme=dark", "User-Agent": "test-agent/1", "X-Other": "skip",
		})
		got := decode(t, w)
		if got["query.q"] != "hello world" || got["cookie.sid"] != "abc123" || got["header.user-agent"] != "test-agent/1" || got["query.tag"] != "a" {
			t.Errorf("keys %v", got)
		}
		if _, ok := got["header.x-other"]; ok {
			t.Error("x-other recorded")
		}
		if outside = FromContext(context.Background()); outside != nil {
			t.Error("context leaked")
		}
	})

	t.Run("a virtual patch in block mode answers 403 with the contract body; monitor lets it through", func(t *testing.T) {
		log := setMode(t, ModeBlock)
		ran := false
		h := Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ran = true
			writeJSON(w, 200, map[string]bool{"ok": true})
		}))
		w := do(t, h, "GET", "/", "", exHeaders)
		if w.Code != 403 || w.Header().Get("Content-Type") != "application/json" || ran {
			t.Fatalf("status %d type %q ran %v", w.Code, w.Header().Get("Content-Type"), ran)
		}
		ev := log.all()
		want := map[string]any{"error": BlockMessage, "attack": "virtual_patch", "rule": ex.ID, "event": ev[0].Attrs["shield360.rasp.event_id"]}
		if got := decode(t, w); !mapsEqual(got, want) {
			t.Errorf("body %v, want %v", got, want)
		}
		if a := ev[0].Attrs; a["shield360.rasp.decision"] != "blocked" || a["shield360.rasp.framework"] != "net/http" || a["shield360.rasp.sink"] != "server.request" {
			t.Errorf("attrs %v", a)
		}
		log = setMode(t, ModeMonitor)
		if w := do(t, h, "GET", "/", "", exHeaders); w.Code != 200 {
			t.Errorf("monitor: %d", w.Code)
		}
		if log.all()[0].Attrs["shield360.rasp.decision"] != "monitored" {
			t.Error("not monitored")
		}
	})

	t.Run("buffers the body: JSON leaves and form fields recorded, body rules judged before the handler, the handler reads it all", func(t *testing.T) {
		setMode(t, ModeBlock)
		br := bodyRule()
		setRemoteConfig(remote(func(r *RemoteConfig) {
			r.Attacks = map[AttackType]Mode{VirtualPatch: ModeBlock}
			r.Rules = []VirtualPatchRule{br}
		}))
		var read string
		h := Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			b, _ := io.ReadAll(r.Body)
			read = string(b)
			writeJSON(w, 200, keysOf(r))
		}))
		body := `{"user":{"name":"O'Brien"},"tags":["a1","b2"]}`
		w := do(t, h, "POST", "/orders?sort=name", body, map[string]string{"Content-Type": "application/json"})
		got := decode(t, w)
		if got["query.sort"] != "name" || got["body.user.name"] != "O'Brien" || got["body.tags.0"] != "a1" || read != body {
			t.Errorf("keys %v read %q", got, read)
		}
		w = do(t, h, "POST", "/form", "name=Ana&city=Lisbon", map[string]string{"Content-Type": "application/x-www-form-urlencoded"})
		if decode(t, w)["body.city"] != "Lisbon" {
			t.Error("form field")
		}
		shape := requestFor(br)
		hdr := map[string]string{}
		for k, v := range shape.Headers {
			hdr[k] = v
		}
		w = do(t, h, shape.Method, "/action", shape.Body, hdr)
		if w.Code != 403 || decode(t, w)["rule"] != br.ID {
			t.Errorf("body rule: %d %s", w.Code, w.Body.String())
		}
	})

	t.Run("ServeMux patterns give the route template and path parameters", func(t *testing.T) {
		log := setMode(t, ModeMonitor)
		mux := http.NewServeMux()
		mux.HandleFunc("GET /users/{id}/posts/{rest...}", func(w http.ResponseWriter, r *http.Request) {
			_, _ = Check(r.Context(), "test.sink", func() *Finding {
				return &Finding{Attack: SQLInjection, Rule: "sqli.userinput"}
			})
			writeJSON(w, 200, keysOf(r))
		})
		got := decode(t, do(t, Middleware(mux), "GET", "/users/7/posts/a/b", "", nil))
		if got["params.id"] != "7" || got["params.rest"] != "a/b" {
			t.Errorf("keys %v", got)
		}
		if route := log.all()[0].Attrs["shield360.rasp.route"]; route != "/users/{id}/posts/{rest...}" {
			t.Errorf("route %q", route)
		}
	})

	t.Run("RecordRoute serves routers whose templates the middleware cannot see", func(t *testing.T) {
		setMode(t, ModeMonitor)
		h := Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			RecordRoute(r.Context(), "/users/:id", map[string]string{"id": "7"})
			writeJSON(w, 200, map[string]any{"keys": keysOf(r), "route": FromContext(r.Context()).Route()})
		}))
		got := decode(t, do(t, h, "GET", "/users/7", "", nil))
		if got["route"] != "/users/:id" || got["keys"].(map[string]any)["params.id"] != "7" {
			t.Errorf("got %v", got)
		}
	})

	t.Run("WriteBlocked maps a block error a sink returned; a panic with it gets the 403; other panics propagate", func(t *testing.T) {
		setMode(t, ModeMonitor)
		blockErr := &BlockedError{Attack: SQLInjection, Rule: "sqli.userinput", EventID: strings.Repeat("e", 32)}
		h := Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if WriteBlocked(w, errors.Join(errors.New("query failed"), blockErr)) {
				return
			}
			w.WriteHeader(500)
		}))
		w := do(t, h, "GET", "/x", "", nil)
		want := map[string]any{"error": BlockMessage, "attack": "sql_injection", "rule": "sqli.userinput", "event": strings.Repeat("e", 32)}
		if w.Code != 403 || !mapsEqual(decode(t, w), want) {
			t.Errorf("%d %s", w.Code, w.Body.String())
		}
		if WriteBlocked(httptest.NewRecorder(), errors.New("other")) {
			t.Error("mapped a plain error")
		}
		p := Middleware(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { panic(blockErr) }))
		if w := do(t, p, "GET", "/x", "", nil); w.Code != 403 {
			t.Errorf("panic: %d", w.Code)
		}
		defer func() {
			if v := recover(); v != "app bug" {
				t.Errorf("recovered %v", v)
			}
		}()
		do(t, Middleware(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { panic("app bug") })), "GET", "/x", "", nil)
	})

	t.Run("RecordRequestBody adds a body the app read itself, once", func(t *testing.T) {
		setMode(t, ModeMonitor)
		h := Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_ = RecordRequestBody(r.Context(), map[string]any{"note": "later"}, "")
			_ = RecordRequestBody(r.Context(), map[string]any{"note": "twice"}, "")
			writeJSON(w, 200, keysOf(r))
		}))
		// A GET body Middleware does not read stays unknown until recorded.
		if got := decode(t, do(t, h, "GET", "/late", "x", nil)); got["body.note"] != "later" {
			t.Errorf("keys %v", got)
		}
	})

	t.Run("inactive: the handler runs with no context", func(t *testing.T) {
		configureEngine(engineSettings{applicationName: "a", getenv: noEnv})
		h := Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			writeJSON(w, 200, map[string]any{"ctx": FromContext(r.Context()) != nil})
		}))
		if got := decode(t, do(t, h, "GET", "/?q=x", "", exHeaders)); got["ctx"] != false {
			t.Errorf("got %v", got)
		}
	})
}

func mapsEqual(a, b map[string]any) bool {
	ja, _ := json.Marshal(a)
	jb, _ := json.Marshal(b)
	return string(ja) == string(jb)
}

func TestModelOutputAsInput(t *testing.T) {
	inRequest := func() context.Context {
		r := httptest.NewRequest("POST", "/chat", nil)
		return withContext(context.Background(), captureRequest(r, Framework))
	}

	t.Run("records completion fragments and tool-call argument leaves", func(t *testing.T) {
		setMode(t, ModeMonitor)
		ctx := inRequest()
		RecordModelOutput(ctx, "first line\nsecond line", "")
		RecordToolArguments(ctx, `{"sql":"select 1"}`, "run_query")
		RecordToolArguments(ctx, map[string]any{"url": "https://example.com"}, "fetch page")
		var got [][2]string
		for _, i := range FromContext(ctx).Inputs() {
			if i.Source == SourceModelOutput {
				got = append(got, [2]string{i.Key, i.Value})
			}
		}
		want := [][2]string{{"model.completion", "first line"}, {"model.completion", "second line"}, {"model.tool.run_query.sql", "select 1"}, {"model.tool.fetch_page.url", "https://example.com"}}
		if len(got) != len(want) {
			t.Fatalf("got %v", got)
		}
		for i := range want {
			if got[i] != want[i] {
				t.Errorf("%d: %v, want %v", i, got[i], want[i])
			}
		}
	})

	t.Run("outside a request: recorded only in a scope the worker started", func(t *testing.T) {
		setMode(t, ModeMonitor)
		RecordModelOutput(context.Background(), "x y z", "") // no scope: dropped, no panic
		ctx := WithScope(context.Background())
		RecordModelOutput(ctx, "rm -rf build && make", "")
		c := FromContext(ctx)
		if c.InRequest() || len(c.Inputs()) != 1 {
			t.Errorf("inputs %v", c.Inputs())
		}
		if f := DetectCommand("rm -rf build && make", c.Inputs()); ruleOf(f) != "cmdi.model_output" {
			t.Errorf("finding %v", f)
		}
	})

	t.Run("records nothing when RASP is off or model output is disabled", func(t *testing.T) {
		setupEngine(t, engineSettings{modelOutput: false})
		ctx := inRequest()
		RecordModelOutput(ctx, "x", "")
		if len(FromContext(ctx).Inputs()) != 0 {
			t.Error("recorded with model output disabled")
		}
		configureEngine(engineSettings{applicationName: "a", modelOutput: true, getenv: noEnv})
		RecordModelOutput(ctx, "x", "")
		if len(FromContext(ctx).Inputs()) != 0 {
			t.Error("recorded while off")
		}
	})
}

// shortBody yields some bytes, fails once as a body that ends early does,
// then reports io.EOF, as net/http's own body reader does after
// io.ErrUnexpectedEOF.
type shortBody struct{ step int }

func (b *shortBody) Read(p []byte) (int, error) {
	b.step++
	switch b.step {
	case 1:
		return copy(p, "partial"), nil
	case 2:
		return 0, io.ErrUnexpectedEOF
	}
	return 0, io.EOF
}

// The handler sees the read error of a truncated body, after the bytes that
// arrived, never a short body that looks complete.
func TestMiddlewareKeepsBodyReadErrors(t *testing.T) {
	setMode(t, ModeMonitor)
	var data string
	var readErr error
	h := Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, err := io.ReadAll(r.Body)
		data, readErr = string(b), err
	}))
	r := httptest.NewRequest("POST", "/upload", &shortBody{})
	h.ServeHTTP(httptest.NewRecorder(), r)
	if data != "partial" || !errors.Is(readErr, io.ErrUnexpectedEOF) {
		t.Errorf("handler read %q, err %v", data, readErr)
	}
}
