package rasp

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
)

// The protection triangle (sdk/rasp/testdata/triangle.json) and request
// correlation (sdk/rasp/testdata/request-correlation.json).

const edgeTestKey = "0123456789abcdef0123456789abcdef"

func loadShared(t *testing.T, rel string, v any) {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(raspDir, rel))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(b, v); err != nil {
		t.Fatal(err)
	}
}

type triangleCorpus struct {
	EdgeContext json.RawMessage `json:"edgeContext"`
	ParseKeys   []struct {
		Name   string          `json:"name"`
		Config json.RawMessage `json:"config"`
		Kids   []string        `json:"kids"`
	} `json:"parseKeys"`
	Context []struct {
		Name        string          `json:"name"`
		Header      string          `json:"header"`
		Method      string          `json:"method"`
		Path        string          `json:"path"`
		RequestID   *string         `json:"requestId"`
		Now         int64           `json:"now"`
		ReplayGroup json.RawMessage `json:"replayGroup"`
		Expect      *struct {
			Rid  string   `json:"rid"`
			Iat  int64    `json:"iat"`
			Exp  int64    `json:"exp"`
			M    string   `json:"m"`
			Ph   string   `json:"ph"`
			Ct   string   `json:"ct"`
			Risk int      `json:"risk"`
			Trap int      `json:"trap"`
			Fl   bool     `json:"fl"`
			Waf  []string `json:"waf"`
			Tp   string   `json:"tp"`
			Rt   string   `json:"rt"`
		} `json:"expect"`
	} `json:"context"`
	Verdict []struct {
		Name   string  `json:"name"`
		Rid    string  `json:"rid"`
		Act    string  `json:"act"`
		Cat    string  `json:"cat"`
		Src    string  `json:"src"`
		TTL    int64   `json:"ttl"`
		Iat    int64   `json:"iat"`
		Expect *string `json:"expect"`
	} `json:"verdict"`
	Suspect []struct {
		Context struct {
			Ct   string `json:"ct"`
			Risk int    `json:"risk"`
			Trap int    `json:"trap"`
			Fl   bool   `json:"fl"`
		} `json:"context"`
		Expect bool `json:"expect"`
	} `json:"suspect"`
	PathHash []struct {
		Path string `json:"path"`
		Hex  string `json:"hex"`
	} `json:"pathHash"`
}

func TestTriangleCorpus(t *testing.T) {
	var c triangleCorpus
	loadShared(t, "testdata/triangle.json", &c)
	for _, k := range c.ParseKeys {
		kids := []string{}
		for _, key := range ParseEdgeKeys(k.Config) {
			kids = append(kids, key.Kid)
		}
		if !reflect.DeepEqual(kids, k.Kids) {
			t.Errorf("parseKeys %q: got %v, want %v", k.Name, kids, k.Kids)
		}
	}
	keys := ParseEdgeKeys(c.EdgeContext)
	caches := map[string]*EdgeReplayCache{}
	for _, x := range c.Context {
		var cache *EdgeReplayCache
		if g := string(x.ReplayGroup); g != "" && g != "null" {
			if caches[g] == nil {
				caches[g] = NewEdgeReplayCache(0)
			}
			cache = caches[g]
		}
		rid := ""
		if x.RequestID != nil {
			rid = *x.RequestID
		}
		got := verifyEdgeContext(keys, x.Header, x.Method, x.Path, rid, x.Now, cache)
		if x.Expect == nil {
			if got != nil {
				t.Errorf("context %q: got %+v, want nil", x.Name, got)
			}
			continue
		}
		e := x.Expect
		want := &EdgeRequestContext{Rid: e.Rid, Iat: e.Iat, Exp: e.Exp, Method: e.M, PathHash: e.Ph, ClientType: e.Ct, Risk: e.Risk, Trap: e.Trap, Flagged: e.Fl, Waf: e.Waf, Traceparent: e.Tp, RedTeam: e.Rt}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("context %q: got %+v, want %+v", x.Name, got, want)
		}
	}
	if len(c.Context) < 40 {
		t.Fatalf("corpus has %d context cases", len(c.Context))
	}
	for _, v := range c.Verdict {
		got := SignEdgeVerdict(keys, v.Rid, v.Act, v.Cat, v.Src, v.TTL, v.Iat)
		want := ""
		if v.Expect != nil {
			want = *v.Expect
		}
		if got != want {
			t.Errorf("verdict %q: got %q, want %q", v.Name, got, want)
		}
	}
	for _, s := range c.Suspect {
		ctx := &EdgeRequestContext{ClientType: s.Context.Ct, Risk: s.Context.Risk, Trap: s.Context.Trap, Flagged: s.Context.Fl}
		if EdgeSaysSuspect(ctx) != s.Expect {
			t.Errorf("suspect %+v: want %v", s.Context, s.Expect)
		}
	}
	for _, p := range c.PathHash {
		if got := EdgePathHash(p.Path); got != p.Hex {
			t.Errorf("pathHash %q: got %s, want %s", p.Path, got, p.Hex)
		}
	}
}

type correlationCorpus struct {
	RequestID []struct {
		Name   string  `json:"name"`
		Value  *string `json:"value"`
		Expect *string `json:"expect"`
	} `json:"requestId"`
	Traceparent []struct {
		Name   string  `json:"name"`
		Value  *string `json:"value"`
		Expect *string `json:"expect"`
	} `json:"traceparent"`
	Resolve []struct {
		Name        string            `json:"name"`
		XRequestID  *string           `json:"xRequestId"`
		Traceparent *string           `json:"traceparent"`
		EdgeRid     *string           `json:"edgeRid"`
		SpanActive  bool              `json:"spanActive"`
		Expect      map[string]string `json:"expect"`
	} `json:"resolve"`
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

func TestRequestCorrelationIDs(t *testing.T) {
	var c correlationCorpus
	loadShared(t, "testdata/request-correlation.json", &c)
	for _, x := range c.RequestID {
		if got := RequestIDOf(deref(x.Value)); got != deref(x.Expect) {
			t.Errorf("requestId %q: got %q, want %q", x.Name, got, deref(x.Expect))
		}
	}
	for _, x := range c.Traceparent {
		if got := TraceIDOf(deref(x.Value)); got != deref(x.Expect) {
			t.Errorf("traceparent %q: got %q, want %q", x.Name, got, deref(x.Expect))
		}
	}
}

func edgeCtxHeader(path string, over map[string]any) string {
	now := time.Now().Unix()
	p := map[string]any{"rid": fmt.Sprintf("req_%d", time.Now().UnixNano()), "iat": now, "exp": now + 30, "m": "GET", "ph": EdgePathHash(path), "ct": "unknown", "risk": 0, "trap": 0, "fl": false}
	for k, v := range over {
		p[k] = v
	}
	b, _ := json.Marshal(p)
	payload := base64.RawURLEncoding.EncodeToString(b)
	m := hmac.New(sha256.New, []byte(edgeTestKey))
	m.Write([]byte("s360-ctx|v1|" + payload))
	return "v1.0a1b2c3d." + payload + "." + base64.RawURLEncoding.EncodeToString(m.Sum(nil))
}

func setEdgeKeys(t *testing.T) {
	t.Helper()
	raw := fmt.Sprintf(`{"keys":[{"kid":"0a1b2c3d","key":"%s"}]}`, base64.RawURLEncoding.EncodeToString([]byte(edgeTestKey)))
	setRemoteConfig(&RemoteConfig{Version: "cfg-1", Exp: float64(time.Now().Unix() + 3600), EdgeKeys: ParseEdgeKeys(json.RawMessage(raw))})
	t.Cleanup(func() { setRemoteConfig(nil) })
}

func edgeRequest(t *testing.T, headers map[string]string, sent map[string]string) context.Context {
	t.Helper()
	r := httptest.NewRequest(http.MethodGet, "/api/x?id=1", nil)
	for k, v := range headers {
		r.Header.Set(k, v)
	}
	// Edge sends its own X-Request-Id with every context (the signed rid);
	// a test that sets none gets that one.
	if v, ok := headers[EdgeContextHeader]; ok {
		if _, has := headers[RequestIDHeader]; !has {
			if parts := strings.Split(v, "."); len(parts) == 4 {
				b, _ := base64.RawURLEncoding.DecodeString(parts[2])
				var p struct {
					Rid string `json:"rid"`
				}
				if json.Unmarshal(b, &p) == nil && p.Rid != "" {
					r.Header.Set(RequestIDHeader, p.Rid)
				}
			}
		}
	}
	c := captureRequest(r, "test")
	c.SetHeaderFunc(func(k, v string) { sent[k] = v })
	return withContext(context.Background(), c)
}

func sqliFinding() *Finding {
	return &Finding{Attack: "sql_injection", Rule: "sqli.userinput", Input: &Input{Value: "1 or 1=1", Key: "query.id", Source: SourceRequest}}
}

func verdictPayload(t *testing.T, v string) string {
	t.Helper()
	parts := strings.Split(v, ".")
	if len(parts) != 4 {
		t.Fatalf("verdict %q", v)
	}
	b, _ := base64.RawURLEncoding.DecodeString(parts[2])
	return string(b)
}

func TestAFlaggedClientIsBlockedForInjectionTheAppOnlyMonitors(t *testing.T) {
	log := setupEngine(t, engineSettings{mode: ModeMonitor})
	setEdgeKeys(t)
	sent := map[string]string{}
	ctx := edgeRequest(t, map[string]string{EdgeContextHeader: edgeCtxHeader("/api/x", map[string]any{"ct": "suspected_agent", "fl": true, "rid": "req_flagged_0001"})}, sent)
	if FromContext(ctx).Edge() == nil {
		t.Fatal("context not verified")
	}
	d, err := HandleFinding(ctx, sqliFinding(), "db", FindingExtra{})
	if d != DecisionBlocked || err == nil {
		t.Fatalf("got %v %v, want blocked", d, err)
	}
	a := log.all()[len(log.all())-1].Attrs
	if a["shield360.rasp.tightened_by_edge"] != "true" || a["shield360.edge.request_id"] != "req_flagged_0001" {
		t.Fatalf("attrs %v", a)
	}
	p := verdictPayload(t, sent[EdgeVerdictHeader])
	if !strings.Contains(p, `"act":"block"`) || !strings.Contains(p, `"cat":"sql_injection"`) {
		t.Fatalf("verdict %s", p)
	}
}

func TestAnUnmarkedClientIsMonitoredAndFlaggedOnce(t *testing.T) {
	log := setupEngine(t, engineSettings{mode: ModeMonitor})
	setEdgeKeys(t)
	sent := map[string]string{}
	ctx := edgeRequest(t, map[string]string{EdgeContextHeader: edgeCtxHeader("/api/x", nil)}, sent)
	if d, _ := HandleFinding(ctx, sqliFinding(), "db", FindingExtra{}); d != DecisionMonitored {
		t.Fatalf("got %v", d)
	}
	if !strings.Contains(verdictPayload(t, sent[EdgeVerdictHeader]), `"act":"flag"`) {
		t.Fatal("no flag verdict")
	}
	delete(sent, EdgeVerdictHeader)
	_, _ = HandleFinding(ctx, sqliFinding(), "db", FindingExtra{})
	if len(sent) != 0 {
		t.Fatal("one verdict per request")
	}
	if _, ok := log.all()[0].Attrs["shield360.rasp.tightened_by_edge"]; ok {
		t.Fatal("not tightened")
	}
}

func TestVerifiedCrawlersForgedContextsAndMismatchedIDsChangeNothing(t *testing.T) {
	setupEngine(t, engineSettings{mode: ModeMonitor})
	setEdgeKeys(t)
	forged := edgeCtxHeader("/api/x", map[string]any{"fl": true})
	forged = forged[:len(forged)-2] + "xx"
	for _, h := range []map[string]string{
		{EdgeContextHeader: edgeCtxHeader("/api/x", map[string]any{"ct": "verified_crawler", "fl": true})},
		{EdgeContextHeader: forged},
		{EdgeContextHeader: edgeCtxHeader("/api/x", map[string]any{"fl": true, "rid": "req_aaaaaaaaaa"}), RequestIDHeader: "req_bbbbbbbbbb"},
	} {
		ctx := edgeRequest(t, h, map[string]string{})
		if d, err := HandleFinding(ctx, sqliFinding(), "db", FindingExtra{}); d != DecisionMonitored || err != nil {
			t.Fatalf("%v: got %v %v", h, d, err)
		}
	}
}

func TestAContextWithoutEdgesRequestIDIsNotTrusted(t *testing.T) {
	setupEngine(t, engineSettings{mode: ModeMonitor})
	setEdgeKeys(t)
	r := httptest.NewRequest(http.MethodGet, "/api/x", nil)
	r.Header.Set(EdgeContextHeader, edgeCtxHeader("/api/x", map[string]any{"fl": true, "rid": "req_lifted_0001"}))
	if captureRequest(r, "test").Edge() != nil {
		t.Fatal("a context without X-Request-Id verified")
	}
}

func TestEdgeIDsLikeTheCorpus(t *testing.T) {
	setupEngine(t, engineSettings{mode: ModeMonitor})
	var c correlationCorpus
	loadShared(t, "testdata/request-correlation.json", &c)
	tp := sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(sdktrace.NewSimpleSpanProcessor(tracetest.NewInMemoryExporter())))
	defer func() { _ = tp.Shutdown(context.Background()) }()
	for _, x := range c.Resolve {
		edgeReplay = NewEdgeReplayCache(0)
		setEdgeKeys(t)
		r := httptest.NewRequest(http.MethodGet, "/a", nil)
		if x.XRequestID != nil {
			r.Header.Set(RequestIDHeader, *x.XRequestID)
		}
		if x.Traceparent != nil {
			r.Header.Set("Traceparent", *x.Traceparent)
		}
		if x.EdgeRid != nil {
			r.Header.Set(EdgeContextHeader, edgeCtxHeader("/a", map[string]any{"rid": *x.EdgeRid}))
			// A context verifies only with Edge's own X-Request-Id (the same id).
			if x.XRequestID == nil {
				r.Header.Set(RequestIDHeader, *x.EdgeRid)
			}
		}
		base := context.Background()
		if x.SpanActive {
			ctx, s := tp.Tracer("t").Start(base, "GET /a")
			defer s.End()
			base = ctx
		}
		ctx := withContext(base, captureRequest(r.WithContext(base), "test"))
		rid, tid, active := EdgeIDs(ctx)
		got := map[string]string{}
		if rid != "" {
			got[EdgeRequestIDAttr] = rid
		}
		if tid != "" && !active {
			got[EdgeTraceIDAttr] = tid
		}
		if !reflect.DeepEqual(got, x.Expect) && !(len(got) == 0 && len(x.Expect) == 0) {
			t.Errorf("resolve %q: got %v, want %v", x.Name, got, x.Expect)
		}
	}
}

func TestTagsTheServerSpanAndCarriesTheIDToChildSpans(t *testing.T) {
	defer resetEdgeRequests()
	exp := tracetest.NewInMemoryExporter()
	tp := sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(sdktrace.NewSimpleSpanProcessor(exp)))
	defer func() { _ = tp.Shutdown(context.Background()) }()
	ctx, server := tp.Tracer("t").Start(context.Background(), "GET /a")
	TagServerSpan(server, RequestIDOf("3f2a9c0d1e4b5a6978c0d1e2f3a4b5c6"))
	child, span := tp.Tracer("t").Start(ctx, "db")
	if rid, _, _ := EdgeIDs(child); rid != "3f2a9c0d1e4b5a6978c0d1e2f3a4b5c6" {
		t.Fatalf("child span: %q", rid)
	}
	span.End()
	server.End()
	found := false
	for _, s := range exp.GetSpans() {
		for _, a := range s.Attributes {
			if s.Name == "GET /a" && string(a.Key) == EdgeRequestIDAttr && a.Value.AsString() == "3f2a9c0d1e4b5a6978c0d1e2f3a4b5c6" {
				found = true
			}
		}
	}
	if !found {
		t.Fatal("server span not tagged")
	}
}
