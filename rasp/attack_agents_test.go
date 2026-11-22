package rasp

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/ThinkfleetAI/shield360-go/clienttype"
)

// AI attack agents (sdk/rasp/README.md "AI attack agents"): the shared
// conformance vectors (testdata/ai-attack-agents.json), the tracker's
// bounds, and the middleware: deter answer, verdict for Edge, events,
// tripwire page.

type agentVectors struct {
	DefaultHeaders map[string]string `json:"defaultHeaders"`
	Config         []struct {
		Name   string            `json:"name"`
		Value  json.RawMessage   `json:"value"`
		Expect AttackAgentConfig `json:"expect"`
	} `json:"config"`
	ClientKey []struct {
		IP  string  `json:"ip"`
		Key *string `json:"key"`
	} `json:"clientKey"`
	UserKey []struct {
		User string  `json:"user"`
		Key  *string `json:"key"`
	} `json:"userKey"`
	Fingerprint []struct {
		Name    string            `json:"name"`
		Headers map[string]string `json:"headers"`
		Expect  *struct {
			Kind string `json:"kind"`
			ID   string `json:"id"`
		} `json:"expect"`
	} `json:"fingerprint"`
	OAST []struct {
		Value  string  `json:"value"`
		Expect *string `json:"expect"`
	} `json:"oast"`
	Sequences []struct {
		Name   string          `json:"name"`
		Kind   string          `json:"kind"`
		Config json.RawMessage `json:"config"`
		Steps  []struct {
			At       int64              `json:"at"`
			IP       string             `json:"ip"`
			User     string             `json:"user"`
			Path     string             `json:"path"`
			Route    string             `json:"route"`
			Status   int                `json:"status"`
			Headers  *map[string]string `json:"headers"`
			Inputs   []string           `json:"inputs"`
			Finding  bool               `json:"finding"`
			Decoy    bool               `json:"decoy"`
			Verified bool               `json:"verified"`
			RedTeam  bool               `json:"redTeam"`
			Expect   struct {
				Deter bool        `json:"deter"`
				Mark  *AttackMark `json:"mark"`
			} `json:"expect"`
		} `json:"steps"`
	} `json:"sequences"`
}

func loadAgentVectors(t *testing.T) agentVectors {
	var v agentVectors
	loadShared(t, "testdata/ai-attack-agents.json", &v)
	return v
}

func derefStr(p *string) string {
	if p == nil {
		return ""
	}
	return *p
}

func TestAttackAgentConformance(t *testing.T) {
	v := loadAgentVectors(t)
	for _, c := range v.Config {
		if got := ParseAttackAgents(c.Value); got != c.Expect {
			t.Errorf("config %s: %+v, want %+v", c.Name, got, c.Expect)
		}
	}
	for _, c := range v.ClientKey {
		if got := ClientKey(c.IP); got != derefStr(c.Key) {
			t.Errorf("client key %q: %q, want %q", c.IP, got, derefStr(c.Key))
		}
	}
	for _, c := range v.UserKey {
		if got := UserKey(c.User); got != derefStr(c.Key) {
			t.Errorf("user key %q: %q, want %q", c.User, got, derefStr(c.Key))
		}
	}
	for _, c := range v.Fingerprint {
		kind, id := AttackFingerprint(c.Headers)
		wantKind, wantID := "", ""
		if c.Expect != nil {
			wantKind, wantID = c.Expect.Kind, c.Expect.ID
		}
		if kind != wantKind || id != wantID {
			t.Errorf("fingerprint %s: %q %q, want %q %q", c.Name, kind, id, wantKind, wantID)
		}
	}
	for _, c := range v.OAST {
		if got := FindCallbackDomain(c.Value); got != derefStr(c.Expect) {
			t.Errorf("oast %q: %q, want %q", c.Value, got, derefStr(c.Expect))
		}
	}
	kinds := map[string]bool{}
	for _, sq := range v.Sequences {
		kinds[sq.Kind] = true
		cfgRaw := map[string]any{}
		def, _ := json.Marshal(DefaultAttackAgents)
		_ = json.Unmarshal(def, &cfgRaw)
		if len(sq.Config) > 0 {
			_ = json.Unmarshal(sq.Config, &cfgRaw)
		}
		merged, _ := json.Marshal(cfgRaw)
		cfg := ParseAttackAgents(merged)
		tr := NewAttackAgentTracker(0, 0)
		marked := false
		for i, st := range sq.Steps {
			now := time.Unix(st.At, 0)
			headers := v.DefaultHeaders
			if st.Headers != nil {
				headers = *st.Headers
			}
			r := AgentRequest{IP: st.IP, User: st.User, Path: st.Path, Headers: headers, Inputs: st.Inputs, Verified: st.Verified || st.RedTeam}
			deter := false
			var mark *AttackMark
			if st.Decoy {
				mark = tr.After(r, AgentResponse{Status: st.Status, Decoy: true}, cfg, now)
			} else {
				made, m, trip := tr.Before(r, cfg, now)
				deter, mark = m != nil, made
				if !deter && !trip {
					if a := tr.After(r, AgentResponse{Status: st.Status, Route: st.Route, Finding: st.Finding}, cfg, now); a != nil {
						mark = a
					}
				}
			}
			if mark != nil {
				marked = true
			}
			if deter != st.Expect.Deter || !reflect.DeepEqual(mark, st.Expect.Mark) {
				t.Errorf("%s step %d: deter %v mark %+v, want deter %v mark %+v", sq.Name, i, deter, mark, st.Expect.Deter, st.Expect.Mark)
			}
		}
		if marked != (sq.Kind == "attack") {
			t.Errorf("%s (%s): marked %v", sq.Name, sq.Kind, marked)
		}
	}
	if !kinds["attack"] || !kinds["benign"] {
		t.Errorf("kinds %v", kinds)
	}
}

func TestAttackAgentTrackerBounds(t *testing.T) {
	cfg := DefaultAttackAgents
	tr := NewAttackAgentTracker(50, 20)
	now := time.Unix(1_000_000, 0)
	for i := 0; i < 500; i++ {
		tr.After(AgentRequest{IP: fmt.Sprintf("10.0.%d.%d", i>>8, i&255), Path: fmt.Sprintf("/x%d", i), Headers: map[string]string{}}, AgentResponse{Status: 404}, cfg, now)
		tr.Before(AgentRequest{IP: fmt.Sprintf("10.1.%d.%d", i>>8, i&255), Path: "/", Headers: map[string]string{"user-agent": "sqlmap/1"}}, cfg, now)
	}
	if k, m := tr.Sizes(); k > 50 || m > 20 {
		t.Fatalf("sizes %d %d", k, m)
	}
	tr = NewAttackAgentTracker(0, 0)
	r := AgentRequest{IP: "192.0.2.1", Path: "/", Headers: map[string]string{"user-agent": "nikto/2.5"}}
	if _, m, _ := tr.Before(r, cfg, time.Unix(0, 0)); m == nil || m.Kind != KindScanner {
		t.Fatal("not marked")
	}
	r.Headers = map[string]string{"user-agent": "Mozilla/5.0"}
	if _, m, _ := tr.Before(r, cfg, time.Unix(1799, 0)); m == nil {
		t.Fatal("expired early")
	}
	if _, m, _ := tr.Before(r, cfg, time.Unix(1800, 0)); m != nil {
		t.Fatal("did not expire")
	}
}

func BenchmarkAttackAgentRequest(b *testing.B) {
	cfg := DefaultAttackAgents
	tr := NewAttackAgentTracker(0, 0)
	h := map[string]string{"user-agent": "Mozilla/5.0 Chrome/131", "accept": "*/*"}
	inputs := []string{"hello world", "a@b.example"}
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		r := AgentRequest{IP: fmt.Sprintf("10.%d.%d.%d", (i>>16)&255, (i>>8)&255, i&255), Path: "/api/items/1", Headers: h, Inputs: inputs}
		now := time.Unix(int64(i), 0)
		tr.Before(r, cfg, now)
		tr.After(r, AgentResponse{Status: 200, Route: "/api/items/{id}"}, cfg, now)
	}
}

func TestAttackAgentPageHidden(t *testing.T) {
	p := TripwirePage("/_debug/console/abc")
	if !strings.Contains(p, `<div hidden aria-hidden="true">`) || !strings.Contains(p, "<!-- ") || strings.Count(p, "/_debug/console/abc") != 2 {
		t.Fatal(p)
	}
}

func TestClientTypeAttackKinds(t *testing.T) {
	c := clienttype.Classify(map[string]string{"user-agent": "", "x-artex-replay-nonce": "1"}, clienttype.Signals{})
	if c.ClientType != clienttype.AIAttackAgent || c.Reasons[0] != "attack_agent_header:artex-replay" {
		t.Fatalf("%+v", c)
	}
	c = clienttype.Classify(map[string]string{"user-agent": "sqlmap/1.8"}, clienttype.Signals{})
	if c.ClientType != clienttype.Scanner || c.Reasons[0] != "ua_attack_tool:sqlmap" {
		t.Fatalf("%+v", c)
	}
	if clienttype.Classify(map[string]string{"user-agent": "sqlmap/1.8"}, clienttype.Signals{VerifiedAgent: true}).ClientType != clienttype.VerifiedAgent {
		t.Fatal("verified first")
	}
	if clienttype.Classify(map[string]string{"user-agent": "Mozilla/5.0"}, clienttype.Signals{AttackMark: clienttype.AIAttackAgent}).ClientType != clienttype.AIAttackAgent {
		t.Fatal("mark")
	}
	if clienttype.Classify(map[string]string{"user-agent": "python-httpx/0.27"}, clienttype.Signals{}).ClientType != clienttype.UnverifiedAutomation {
		t.Fatal("httpx")
	}
}

// ---- middleware ------------------------------------------------------------------

func agentSetup(t *testing.T, mode Mode, block string, over func(*RemoteConfig)) *eventLog {
	t.Helper()
	log := setupEngine(t, engineSettings{attacks: map[AttackType]Mode{AIAttackAgent: ModeMonitor}})
	key := base64.RawURLEncoding.EncodeToString([]byte(edgeTestKey))
	r := remote(func(r *RemoteConfig) {
		r.Attacks[AIAttackAgent] = mode
		a := ParseAttackAgents(json.RawMessage(block))
		r.AttackAgents = &a
		r.EdgeKeys = ParseEdgeKeys(json.RawMessage(`{"keys":[{"kid":"0a1b2c3d","key":"` + key + `"}]}`))
		if over != nil {
			over(r)
		}
	})
	setRemoteConfig(r)
	setAgentTracker(nil)
	setSuspiciousTable(NewSuspiciousTable(0, nil))
	t.Cleanup(func() {
		setRemoteConfig(nil)
		setAgentTracker(nil)
	})
	return log
}

func agentRules(log *eventLog) []string {
	var out []string
	for _, e := range log.all() {
		if e.Attrs["shield360.rasp.attack"] == string(AIAttackAgent) {
			out = append(out, e.Attrs["shield360.rasp.rule"])
		}
	}
	return out
}

func agentApp() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/items", func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("ok")) })
	mux.HandleFunc("GET /admin", func(w http.ResponseWriter, r *http.Request) {
		IdentifyUser(r.Context(), "mallory")
		w.WriteHeader(http.StatusForbidden)
	})
	mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("home")) })
	return Middleware(mux)
}

func agentGet(h http.Handler, target, ip string, headers map[string]string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, target, nil)
	req.RemoteAddr = ip + ":1234"
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

var browserUA = map[string]string{"User-Agent": "Mozilla/5.0"}

func edgeContextFor(method, path, rid, ct string) string {
	return edgeContextWith(method, path, rid, ct, nil)
}

func edgeContextWith(method, path, rid, ct string, extra map[string]any) string {
	now := time.Now().Unix()
	body := map[string]any{"rid": rid, "iat": now, "exp": now + 30, "m": method, "ph": edgePathHashForTest(path), "ct": ct, "risk": 0, "trap": 0, "fl": false}
	for k, v := range extra {
		body[k] = v
	}
	payload, _ := json.Marshal(body)
	p := base64.RawURLEncoding.EncodeToString(payload)
	m := hmac.New(sha256.New, []byte(edgeTestKey))
	m.Write([]byte("s360-ctx|v1|" + p))
	return "v1.0a1b2c3d." + p + "." + base64.RawURLEncoding.EncodeToString(m.Sum(nil))
}

func edgePathHashForTest(path string) string {
	s := sha256.Sum256([]byte(path))
	return fmt.Sprintf("%x", s[:8])
}

func TestAttackAgentMiddleware(t *testing.T) {
	t.Run("deters a tool with 429 and Retry-After in block mode", func(t *testing.T) {
		log := agentSetup(t, ModeBlock, `{"retryAfterSeconds":120}`, nil)
		h := agentApp()
		rec := agentGet(h, "/api/items?id=1", "198.51.100.7", map[string]string{"User-Agent": "sqlmap/1.8.2#stable"})
		if rec.Code != 429 || rec.Header().Get("Retry-After") != "120" || strings.TrimSpace(rec.Body.String()) != `{"error":"Too Many Requests"}` {
			t.Fatalf("%d %v %s", rec.Code, rec.Header(), rec.Body)
		}
		e := log.all()[0].Attrs
		if e["shield360.rasp.rule"] != "attack_agent.fingerprint" || e["shield360.rasp.client_kind"] != KindScanner || e["shield360.rasp.reason"] != ReasonFingerprint || e["shield360.rasp.decision"] != "blocked" || e["shield360.rasp.sink"] != AttackAgentHTTPSink {
			t.Fatalf("%v", e)
		}
		if rec := agentGet(h, "/", "198.51.100.7", browserUA); rec.Code != 429 {
			t.Fatalf("still marked: %d", rec.Code)
		}
		if got := agentRules(log); got[1] != "attack_agent.marked" {
			t.Fatalf("%v", got)
		}
	})

	t.Run("only reports in monitor mode", func(t *testing.T) {
		log := agentSetup(t, ModeMonitor, `{}`, nil)
		rec := agentGet(agentApp(), "/api/items?u=http%3A%2F%2Fabc.oast.fun%2F", "198.51.100.8", browserUA)
		if rec.Code != 200 || agentRules(log)[0] != "attack_agent.oast" || log.all()[0].Attrs["shield360.rasp.decision"] != "monitored" {
			t.Fatalf("%d %v", rec.Code, agentRules(log))
		}
	})

	t.Run("marks on behavior after the app answers, then deters", func(t *testing.T) {
		log := agentSetup(t, ModeBlock, `{"threshold":5}`, nil)
		h := agentApp()
		for i := 0; i < 5; i++ {
			if rec := agentGet(h, fmt.Sprintf("/missing/%d", i), "198.51.100.9", browserUA); rec.Code != 404 {
				t.Fatalf("step %d: %d", i, rec.Code)
			}
		}
		if got := agentRules(log); !reflect.DeepEqual(got, []string{"attack_agent.behavior"}) {
			t.Fatalf("%v", got)
		}
		if rec := agentGet(h, "/", "198.51.100.9", browserUA); rec.Code != 429 {
			t.Fatalf("%d", rec.Code)
		}
	})

	t.Run("a matched route answering 200 is never scored", func(t *testing.T) {
		log := agentSetup(t, ModeBlock, `{"threshold":5}`, nil)
		h := agentApp()
		for i := 0; i < 20; i++ {
			agentGet(h, "/api/items", "198.51.100.10", browserUA)
		}
		if len(agentRules(log)) != 0 {
			t.Fatalf("%v", agentRules(log))
		}
	})

	t.Run("sends a signed block verdict to Edge on the deter answer", func(t *testing.T) {
		agentSetup(t, ModeBlock, `{}`, nil)
		rid := "req_attackagent01"
		rec := agentGet(agentApp(), "/api/items", "198.51.100.11", map[string]string{"User-Agent": "nuclei/3.3", "X-Request-Id": rid, EdgeContextHeader: edgeContextFor("GET", "/api/items", rid, "human")})
		if rec.Code != 429 {
			t.Fatalf("%d", rec.Code)
		}
		v := rec.Header().Get(EdgeVerdictHeader)
		parts := strings.Split(v, ".")
		if len(parts) != 4 {
			t.Fatalf("verdict %q", v)
		}
		raw, _ := base64.RawURLEncoding.DecodeString(parts[2])
		var got map[string]any
		_ = json.Unmarshal(raw, &got)
		if got["act"] != "block" || got["cat"] != KindScanner || got["ttl"] != float64(1800) || got["rid"] != rid {
			t.Fatalf("%v", got)
		}
	})

	t.Run("never marks a client Edge verified", func(t *testing.T) {
		log := agentSetup(t, ModeBlock, `{}`, nil)
		rid := "req_verifiedcrawl1"
		rec := agentGet(agentApp(), "/api/items", "198.51.100.12", map[string]string{"User-Agent": "nuclei/3.3", "X-Request-Id": rid, EdgeContextHeader: edgeContextFor("GET", "/api/items", rid, "verified_crawler")})
		if rec.Code != 200 || len(agentRules(log)) != 0 {
			t.Fatalf("%d %v", rec.Code, agentRules(log))
		}
	})

	t.Run("never marks or deters the red team Edge named in its context, even from a marked address", func(t *testing.T) {
		log := agentSetup(t, ModeBlock, `{"tripwire":true}`, nil)
		h := agentApp()
		const ip = "198.51.100.40"
		if rec := agentGet(h, "/", ip, map[string]string{"User-Agent": "nuclei/3.3"}); rec.Code != 429 {
			t.Fatalf("not marked: %d", rec.Code)
		}
		before := len(agentRules(log))
		for _, path := range []string{"/api/items", "/_debug/console/abc"} {
			rid := fmt.Sprintf("req_redteam_%02d", len(path))
			rec := agentGet(h, path, ip, map[string]string{"User-Agent": "nuclei/3.3", "X-Request-Id": rid, EdgeContextHeader: edgeContextWith("GET", path, rid, "automation", map[string]any{"rt": "crun12345678"})})
			if rec.Code == 429 || rec.Header().Get(EdgeVerdictHeader) != "" {
				t.Fatalf("%s: red team deterred: %d %v", path, rec.Code, rec.Header())
			}
		}
		if got := agentRules(log); len(got) != before {
			t.Fatalf("red team reported: %v", got)
		}
		rid := "req_notredteam1"
		if rec := agentGet(h, "/api/items", ip, map[string]string{"User-Agent": "Mozilla/5.0", "X-Request-Id": rid, EdgeContextHeader: edgeContextFor("GET", "/api/items", rid, "automation")}); rec.Code != 429 {
			t.Fatalf("without rt: %d", rec.Code)
		}
	})

	t.Run("does nothing with the attack type off", func(t *testing.T) {
		log := agentSetup(t, ModeOff, `{}`, nil)
		if rec := agentGet(agentApp(), "/api/items", "198.51.100.13", map[string]string{"User-Agent": "sqlmap/1"}); rec.Code != 200 || len(agentRules(log)) != 0 {
			t.Fatalf("%d", rec.Code)
		}
	})

	t.Run("tripwire page on a decoy, and a client that follows it is marked", func(t *testing.T) {
		log := agentSetup(t, ModeMonitor, `{"tripwire":true}`, func(r *RemoteConfig) {
			r.Deception = ParseDeception(json.RawMessage(`{"paths":["/wp-admin"],"action":"monitor","ttlSeconds":60}`))
		})
		h := agentApp()
		rec := agentGet(h, "/wp-admin", "198.51.100.14", browserUA)
		url := regexp.MustCompile(`/_debug/console/[A-Za-z0-9_-]{16}`).FindString(rec.Body.String())
		if rec.Code != 404 || url == "" {
			t.Fatalf("%d %s", rec.Code, rec.Body)
		}
		if rec := agentGet(h, url, "198.51.100.14", browserUA); rec.Code != 404 {
			t.Fatalf("%d", rec.Code)
		}
		found := false
		for _, e := range log.all() {
			if e.Attrs["shield360.rasp.rule"] == "attack_agent.tripwire" && e.Attrs["shield360.rasp.client_kind"] == KindAIAttackAgent {
				found = true
			}
		}
		if !found {
			t.Fatalf("%v", agentRules(log))
		}
	})

	t.Run("plain 404 on a decoy while the tripwire is off", func(t *testing.T) {
		agentSetup(t, ModeMonitor, `{}`, func(r *RemoteConfig) {
			r.Deception = ParseDeception(json.RawMessage(`{"paths":["/wp-admin"],"action":"monitor","ttlSeconds":60}`))
		})
		if rec := agentGet(agentApp(), "/wp-admin", "198.51.100.15", browserUA); strings.Contains(rec.Body.String(), "_debug") {
			t.Fatal(rec.Body.String())
		}
	})

	t.Run("follows a signed-in user across addresses", func(t *testing.T) {
		agentSetup(t, ModeBlock, `{"threshold":6}`, nil)
		h := agentApp()
		for i := 0; i < 3; i++ {
			agentGet(h, "/admin", fmt.Sprintf("192.0.2.%d", i+1), browserUA)
		}
		if m := agentTracker().MarkOf([]string{"u:mallory"}, time.Now()); m == nil || m.Reason != ReasonBehavior {
			t.Fatalf("%+v", m)
		}
	})
}
