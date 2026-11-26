package rasp

// SHIELD: decoy and trap verdicts (README "Deception", "Protection triangle"):
// a decoy hit behind Edge carries a signed verdict on its 404, so Edge blocks
// the client fleet-wide; never without a verified context, for a verified
// crawler, a red team run or the simulated client.

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func decoyRequest(path, ip string, over map[string]any) (*http.Request, string) {
	r := httptest.NewRequest(http.MethodGet, path, nil)
	r.RemoteAddr = ip + ":4000"
	if over == nil {
		return r, ""
	}
	h := edgeCtxHeader(path, over)
	var p struct {
		Rid string `json:"rid"`
	}
	b, _ := base64.RawURLEncoding.DecodeString(strings.Split(h, ".")[2])
	_ = json.Unmarshal(b, &p)
	r.Header.Set(EdgeContextHeader, h)
	r.Header.Set(RequestIDHeader, p.Rid)
	return r, p.Rid
}

func TestDecoyHitSendsAVerdict(t *testing.T) {
	keys := func(r *RemoteConfig) {
		raw := fmt.Sprintf(`{"keys":[{"kid":"0a1b2c3d","key":"%s"}]}`, base64.RawURLEncoding.EncodeToString([]byte(edgeTestKey)))
		r.EdgeKeys = ParseEdgeKeys(json.RawMessage(raw))
	}
	serve := func(r *http.Request) *httptest.ResponseRecorder {
		probe := &handlerProbe{}
		rec := httptest.NewRecorder()
		Middleware(probe.handler()).ServeHTTP(rec, r)
		if probe.called != 0 || rec.Code != http.StatusNotFound {
			t.Fatalf("decoy: %d, handler %d", rec.Code, probe.called)
		}
		return rec
	}

	t.Run("blocked hit: block, cat deception, src rasp, the deception TTL", func(t *testing.T) {
		deceptionSetup(t, engineSettings{}, `{"paths":["/wp-admin"],"action":"block","ttlSeconds":1200}`, keys)
		r, rid := decoyRequest("/wp-admin/setup.php", "203.0.113.5", map[string]any{})
		p := verdictPayload(t, serve(r).Header().Get(EdgeVerdictHeader))
		for _, want := range []string{`"rid":"` + rid + `"`, `"act":"block"`, `"cat":"deception"`, `"src":"rasp"`, `"ttl":1200`} {
			if !strings.Contains(p, want) {
				t.Fatalf("verdict %s lacks %s", p, want)
			}
		}
	})

	t.Run("monitored hit still blocks at Edge; the app still answers its 404", func(t *testing.T) {
		deceptionSetup(t, engineSettings{}, `{"paths":["/wp-admin"],"action":"monitor","ttlSeconds":900}`, keys)
		r, _ := decoyRequest("/wp-admin", "203.0.113.6", map[string]any{})
		rec := serve(r)
		if rec.Code != http.StatusNotFound {
			t.Fatalf("status %d", rec.Code)
		}
		if p := verdictPayload(t, rec.Header().Get(EdgeVerdictHeader)); !strings.Contains(p, `"act":"block"`) || !strings.Contains(p, `"cat":"deception"`) || !strings.Contains(p, `"ttl":900`) {
			t.Fatalf("verdict %s", p)
		}
	})

	t.Run("no verdict when exempt, unverified or unkeyed; the event is reported", func(t *testing.T) {
		log, _ := deceptionSetup(t, engineSettings{}, blockBlock, keys)
		cases := []struct {
			ip   string
			over map[string]any
		}{
			{"203.0.113.7", nil},
			{"203.0.113.8", map[string]any{"ct": "verified_crawler"}},
			{"203.0.113.9", map[string]any{"rt": "crun12345678"}},
			{SimulatedClient, map[string]any{}},
		}
		for _, c := range cases {
			r, _ := decoyRequest("/wp-admin", c.ip, c.over)
			if v := serve(r).Header().Get(EdgeVerdictHeader); v != "" {
				t.Fatalf("%s %v: verdict %s", c.ip, c.over, v)
			}
		}
		r, _ := decoyRequest("/wp-admin", "203.0.113.10", map[string]any{})
		r.Header.Set(EdgeContextHeader, r.Header.Get(EdgeContextHeader)[:len(r.Header.Get(EdgeContextHeader))-2]+"xx")
		if v := serve(r).Header().Get(EdgeVerdictHeader); v != "" {
			t.Fatal("a forged context got a verdict")
		}
		if n := len(deceptionEvents(log)); n != 5 {
			t.Fatalf("events %d", n)
		}
		deceptionSetup(t, engineSettings{}, blockBlock, nil)
		r, _ = decoyRequest("/wp-admin", "203.0.113.11", map[string]any{})
		if v := serve(r).Header().Get(EdgeVerdictHeader); v != "" {
			t.Fatal("no keys: no verdict")
		}
	})
}
