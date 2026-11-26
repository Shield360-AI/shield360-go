package defend

// SHIELD: decoy and trap verdicts (agent-guides/edge-deception-spec.md, "What
// each layer does"): a honeypot trap hit behind Edge carries a signed verdict
// (cat trap, src defend), so Edge blocks the client fleet-wide.

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Shield360-AI/shield360-go/rasp"
)

func trapCtx(path, rid string, over map[string]any) string {
	p := map[string]any{"rid": rid, "iat": nowS, "exp": nowS + 30, "m": "GET", "ph": rasp.EdgePathHash(path), "ct": "unknown", "risk": 0, "trap": 0, "fl": false}
	for k, v := range over {
		p[k] = v
	}
	body, _ := json.Marshal(p)
	payload := b64.EncodeToString(body)
	m := hmac.New(sha256.New, edgeSecret)
	m.Write([]byte("s360-ctx|v1|" + payload))
	return "v1.0a1b2c3d." + payload + "." + b64.EncodeToString(m.Sum(nil))
}

func trapVerdictPayload(t *testing.T, v string) string {
	t.Helper()
	parts := strings.Split(v, ".")
	if len(parts) != 4 {
		t.Fatalf("verdict %q", v)
	}
	b, _ := b64.DecodeString(parts[2])
	return string(b)
}

func trapPolicy(mode string) string {
	return sign(JWSType, claims(`{"honeypots":{"enabled":true,"secret":"`+b64.EncodeToString(edgeSecret)+`","mode":"`+mode+`"},"traps":{"action":"block","ttlSeconds":1800},"edgeContext":{"keys":[{"kid":"0a1b2c3d","key":"`+b64.EncodeToString(edgeSecret)+`"}]}}`))
}

func TestTrapHitBehindEdgeSendsABlockVerdict(t *testing.T) {
	s := newSetup(t, trapPolicy("block"), nil)
	hit := func(ip, rid string, over map[string]any) Result {
		path := s.d.Crumbs(req(ip, "GET", "/", browser...), Call{}).Path
		h := browser
		if over != nil {
			h = with("x-shield360-edge-context", trapCtx(path, rid, over), "x-request-id", rid)
		}
		return s.d.Defend(req(ip, "GET", path, h...), Call{})
	}
	r := hit("198.51.100.30", "req_trap_000001", map[string]any{})
	if r.Decoy == nil {
		t.Fatal("a crumb path answers with fake data")
	}
	p := trapVerdictPayload(t, r.Verdict)
	for _, want := range []string{`"rid":"req_trap_000001"`, `"act":"block"`, `"cat":"trap"`, `"src":"defend"`, `"ttl":1800`} {
		if !strings.Contains(p, want) {
			t.Fatalf("verdict %s lacks %s", p, want)
		}
	}
	resp := ResponseFor(r)
	found := false
	for _, h := range resp.Headers {
		found = found || (h[0] == rasp.EdgeVerdictHeader && h[1] == r.Verdict)
	}
	if !found {
		t.Fatal("the decoy answer carries the verdict", resp.Headers)
	}
	// Exempt or unverified: no verdict, the hit still counts.
	if r := hit("198.51.100.31", "req_trap_000002", nil); r.Verdict != "" || !contains(r.Reasons, "trap:honeypot") {
		t.Fatal("no Edge: no verdict", r)
	}
	if r := hit("198.51.100.32", "req_trap_000003", map[string]any{"ct": "verified_crawler"}); r.Verdict != "" {
		t.Fatal("verified crawler", r)
	}
	if r := hit("198.51.100.33", "req_trap_000004", map[string]any{"rt": "crun12345678"}); r.Verdict != "" {
		t.Fatal("red team", r)
	}
	if r := hit(rasp.SimulatedClient, "req_trap_000005", map[string]any{}); r.Verdict != "" {
		t.Fatal("simulated client", r)
	}
}

func TestTrapHitInMonitorStillBlocksAtEdgeThroughTheMiddleware(t *testing.T) {
	for _, c := range []struct {
		name   string
		policy string
		opt    func(*Options)
	}{
		{"monitor mode", trapPolicy("block"), func(o *Options) { o.Mode = Monitor }},
		{"honeypots in monitor", trapPolicy("monitor"), nil},
	} {
		t.Run(c.name, func(t *testing.T) {
			s := newSetup(t, c.policy, c.opt)
			ip := "198.51.100.40"
			path := s.d.Crumbs(req(ip, "GET", "/", browser...), Call{}).Path
			r := httptest.NewRequest(http.MethodGet, path, nil)
			r.RemoteAddr = ip + ":1234"
			for i := 0; i+1 < len(browser); i += 2 {
				r.Header.Set(browser[i], browser[i+1])
			}
			r.Header.Set("X-Shield360-Edge-Context", trapCtx(path, "req_trap_000010", map[string]any{}))
			r.Header.Set("X-Request-Id", "req_trap_000010")
			rec := httptest.NewRecorder()
			s.d.Middleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("app")) })).ServeHTTP(rec, r)
			if rec.Code == http.StatusForbidden {
				t.Fatalf("monitor denied the request locally: %d", rec.Code)
			}
			if p := trapVerdictPayload(t, rec.Header().Get(rasp.EdgeVerdictHeader)); !strings.Contains(p, `"act":"block"`) || !strings.Contains(p, `"cat":"trap"`) || !strings.Contains(p, `"src":"defend"`) {
				t.Fatalf("verdict %s", p)
			}
		})
	}
}
