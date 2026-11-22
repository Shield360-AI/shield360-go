package rasp

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"sync"
	"testing"
	"time"
)

// Deception: decoy paths from the signed config (README "Deception"), the
// shared conformance cases (testdata/deception.json), the suspicious table
// and the middleware.

func TestDeceptionConformance(t *testing.T) {
	corpus := loadJSON(t, "testdata/deception.json")
	for _, raw := range corpus["config"].([]any) {
		c := raw.(map[string]any)
		var in json.RawMessage
		if v, ok := c["deception"]; ok {
			in, _ = json.Marshal(v)
		}
		got := ParseDeception(in)
		// Through the claims parser too: a key that is missing stays absent.
		claims := map[string]any{"v": 1, "app": "a", "exp": 1, "version": "x"}
		if v, ok := c["deception"]; ok {
			claims["deception"] = v
		}
		payload, _ := json.Marshal(claims)
		parsed, reason := parseClaims(payload)
		if reason != "" || !reflect.DeepEqual(parsed.Deception, got) {
			t.Errorf("%s: claims gave %+v (%s), ParseDeception %+v", c["name"], parsed.Deception, reason, got)
		}
		want := c["expect"]
		if want == nil {
			if got != nil {
				t.Errorf("%s: got %+v, want off", c["name"], got)
			}
			continue
		}
		w := want.(map[string]any)
		var paths []string
		for _, p := range w["paths"].([]any) {
			paths = append(paths, p.(string))
		}
		exp := &DeceptionConfig{Paths: paths, Action: w["action"].(string), TTLSeconds: int(w["ttlSeconds"].(float64))}
		if !reflect.DeepEqual(got, exp) {
			t.Errorf("%s: got %+v, want %+v", c["name"], got, exp)
		}
	}
	defaults := corpus["decoys"].([]any)
	for _, raw := range corpus["match"].([]any) {
		c := raw.(map[string]any)
		decoys := defaults
		if d, ok := c["decoys"]; ok {
			decoys = d.([]any)
		}
		block, _ := json.Marshal(map[string]any{"paths": decoys})
		cfg := ParseDeception(block)
		want, _ := c["expect"].(string)
		target := c["target"].(string)
		if got := MatchDecoy(cfg.Paths, target); got != want {
			t.Errorf("MatchDecoy(%q, %q) = %q, want %q", decoys, target, got, want)
		}
		// The middleware matches net/http's decoded URL.Path; a target
		// net/http refuses never reaches it.
		got := ""
		if req, err := http.NewRequest("GET", "http://example.test"+target, nil); err == nil {
			got = matchDecoded(cfg.Paths, req.URL.Path)
		}
		if got != want {
			t.Errorf("URL.Path of %q with %q = %q, want %q", target, decoys, got, want)
		}
	}
}

type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *fakeClock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *fakeClock) add(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

func newClock() *fakeClock { return &fakeClock{t: time.Unix(1_800_000_000, 0)} }

func TestSuspiciousTable(t *testing.T) {
	t.Run("marks expire and lookups do not extend them", func(t *testing.T) {
		clk := newClock()
		tb := NewSuspiciousTable(10, clk.now)
		tb.Mark("10.0.0.1", time.Minute)
		tb.Mark("", time.Minute)
		if !tb.Suspicious("10.0.0.1") || tb.Suspicious("10.0.0.2") || tb.Suspicious("") || tb.Len() != 1 {
			t.Fatal("mark")
		}
		clk.add(59 * time.Second)
		if !tb.Suspicious("10.0.0.1") {
			t.Fatal("expired early")
		}
		clk.add(time.Second)
		if tb.Suspicious("10.0.0.1") || tb.Len() != 0 {
			t.Fatal("not expired at mark + ttl")
		}
	})
	t.Run("the cap holds: oldest evicted, re-marking refreshes the order", func(t *testing.T) {
		clk := newClock()
		tb := NewSuspiciousTable(3, clk.now)
		for i := 1; i <= 3; i++ {
			tb.Mark(fmt.Sprintf("10.0.0.%d", i), time.Hour)
		}
		tb.Mark("10.0.0.1", time.Hour) // now the newest
		for i := 4; i <= 103; i++ {
			tb.Mark(fmt.Sprintf("10.0.1.%d", i), time.Hour)
			if tb.Len() > 3 {
				t.Fatalf("size %d over the cap", tb.Len())
			}
		}
		if tb.Len() != 3 || tb.Suspicious("10.0.0.1") || !tb.Suspicious("10.0.1.103") {
			t.Fatal("eviction order")
		}
		tb2 := NewSuspiciousTable(3, clk.now)
		tb2.Mark("a", time.Hour)
		tb2.Mark("b", time.Hour)
		tb2.Mark("c", time.Hour)
		tb2.Mark("a", time.Hour)
		tb2.Mark("d", time.Hour) // b is the oldest now
		if tb2.Suspicious("b") || !tb2.Suspicious("a") || !tb2.Suspicious("c") || !tb2.Suspicious("d") {
			t.Fatal("re-marking did not refresh the order")
		}
	})
	t.Run("expired marks go before live ones", func(t *testing.T) {
		clk := newClock()
		tb := NewSuspiciousTable(3, clk.now)
		tb.Mark("short1", time.Second)
		tb.Mark("short2", time.Second)
		tb.Mark("long", time.Hour)
		clk.add(2 * time.Second)
		tb.Mark("new", time.Hour)
		if tb.Len() != 2 || !tb.Suspicious("long") || !tb.Suspicious("new") {
			t.Fatal("expired marks not dropped first")
		}
	})
	t.Run("after a lower TTL, expired marks behind live ones go first", func(t *testing.T) {
		clk := newClock()
		tb := NewSuspiciousTable(3, clk.now)
		tb.Mark("a", time.Hour)
		tb.Mark("b", time.Hour)
		tb.Mark("c", time.Second)
		clk.add(2 * time.Second)
		tb.Mark("d", time.Hour)
		if tb.Len() != 3 || !tb.Suspicious("a") || !tb.Suspicious("b") || !tb.Suspicious("d") || tb.Suspicious("c") {
			t.Fatal("a live mark was evicted while an expired one stayed")
		}
	})
	t.Run("a full table evicts the mark closest to expiring", func(t *testing.T) {
		clk := newClock()
		tb := NewSuspiciousTable(2, clk.now)
		tb.Mark("a", time.Hour)
		tb.Mark("b", 10*time.Second)
		tb.Mark("c", time.Hour)
		if tb.Suspicious("b") || !tb.Suspicious("a") || !tb.Suspicious("c") {
			t.Fatal("not the soonest-to-expire mark evicted")
		}
	})
	t.Run("default cap", func(t *testing.T) {
		tb := NewSuspiciousTable(0, nil)
		for i := 0; i < DefaultSuspiciousCap+50; i++ {
			tb.Mark(fmt.Sprintf("ip-%d", i), time.Hour)
		}
		if tb.Len() != DefaultSuspiciousCap {
			t.Fatalf("size %d", tb.Len())
		}
	})
}

// deceptionSetup configures the engine with a signed deception block and a
// fresh table on a fake clock.
func deceptionSetup(t *testing.T, s engineSettings, block string, over func(*RemoteConfig)) (*eventLog, *fakeClock) {
	t.Helper()
	log := setupEngine(t, s)
	r := remote(func(r *RemoteConfig) {
		r.Deception = ParseDeception(json.RawMessage(block))
		// SHIELD: AI attack agents — off here (decoy hits add to its score); attack_agents_test.go covers the two together.
		r.Attacks[AIAttackAgent] = ModeOff
		if over != nil {
			over(r)
		}
	})
	setRemoteConfig(r)
	clk := newClock()
	setSuspiciousTable(NewSuspiciousTable(100, clk.now))
	t.Cleanup(func() {
		setRemoteConfig(nil)
		setSuspiciousTable(NewSuspiciousTable(0, nil))
	})
	return log, clk
}

type handlerProbe struct{ called int }

func (h *handlerProbe) handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h.called++
		if r.URL.Path == "/orders/1" {
			_, _ = w.Write([]byte("ok"))
			return
		}
		http.NotFound(w, r)
	})
}

func serveAt(h http.Handler, method, target, remoteAddr string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, target, nil)
	req.RemoteAddr = remoteAddr
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func deceptionEvents(log *eventLog) []Event {
	var out []Event
	for _, e := range log.all() {
		if e.Attrs["shield360.rasp.attack"] == "deception" {
			out = append(out, e)
		}
	}
	return out
}

const (
	monitorBlock = `{"paths":["/wp-admin","/.git/config"],"action":"monitor","ttlSeconds":60}`
	blockBlock   = `{"paths":["/wp-admin","/.git/config"],"action":"block","ttlSeconds":60}`
)

func TestDeceptionMiddleware(t *testing.T) {
	t.Run("a decoy never reaches the handler and answers like an unknown path", func(t *testing.T) {
		log, _ := deceptionSetup(t, engineSettings{}, monitorBlock, nil)
		probe := &handlerProbe{}
		h := Middleware(probe.handler())
		hit := serveAt(h, "GET", "/wp-admin/install.php?x=1", "203.0.113.5:4000")
		if probe.called != 0 {
			t.Fatal("decoy reached the handler")
		}
		unknown := serveAt((&handlerProbe{}).handler(), "GET", "/nothing-here", "198.51.100.1:1")
		if hit.Code != http.StatusNotFound || hit.Body.String() != unknown.Body.String() || !reflect.DeepEqual(hit.Header(), unknown.Header()) {
			t.Fatalf("decoy answered %d %q %v, unknown path %d %q %v", hit.Code, hit.Body.String(), hit.Header(), unknown.Code, unknown.Body.String(), unknown.Header())
		}
		ev := deceptionEvents(log)
		if len(ev) != 1 {
			t.Fatalf("events %v", ev)
		}
		a := ev[0].Attrs
		want := map[string]string{"shield360.rasp.rule": "deception.hit", "shield360.rasp.decision": "monitored", "shield360.rasp.mode": "monitor", "shield360.rasp.sink": "http.deception", "shield360.rasp.route": "/wp-admin", "shield360.rasp.framework": "net/http", "shield360.rasp.method": "GET", "shield360.rasp.config_version": "v1"}
		for k, v := range want {
			if a[k] != v {
				t.Errorf("%s = %q, want %q", k, a[k], v)
			}
		}
		if _, ok := a["shield360.rasp.input_key"]; ok {
			t.Error("deception events carry no input")
		}
		// An encoded decoy is a decoy too.
		if rec := serveAt(h, "GET", "/.git%2Fconfig", "203.0.113.6:1"); rec.Code != 404 || probe.called != 0 {
			t.Fatalf("encoded decoy: %d, handler %d", rec.Code, probe.called)
		}
	})

	t.Run("monitor: a marked client is reported and goes on", func(t *testing.T) {
		log, clk := deceptionSetup(t, engineSettings{}, monitorBlock, nil)
		probe := &handlerProbe{}
		h := Middleware(probe.handler())
		serveAt(h, "GET", "/wp-admin", "203.0.113.5:4000")
		rec := serveAt(h, "GET", "/orders/1", "203.0.113.5:4001")
		if rec.Code != 200 || probe.called != 1 {
			t.Fatalf("monitored request: %d, handler %d", rec.Code, probe.called)
		}
		serveAt(h, "GET", "/orders/1", "198.51.100.9:1") // another client
		ev := deceptionEvents(log)
		if len(ev) != 2 || ev[1].Attrs["shield360.rasp.rule"] != "deception.suspicious" || ev[1].Attrs["shield360.rasp.decision"] != "monitored" || ev[1].Attrs["shield360.rasp.route"] != "/orders/:id" {
			t.Fatalf("events %v", ev)
		}
		clk.add(60 * time.Second)
		serveAt(h, "GET", "/orders/1", "203.0.113.5:4002")
		if len(deceptionEvents(log)) != 2 {
			t.Fatal("the mark did not expire")
		}
	})

	t.Run("block: a marked client gets the block response", func(t *testing.T) {
		log, _ := deceptionSetup(t, engineSettings{}, blockBlock, nil)
		probe := &handlerProbe{}
		h := Middleware(probe.handler())
		if serveAt(h, "GET", "/wp-admin", "[2001:db8::1]:443").Code != 404 {
			t.Fatal("decoy")
		}
		rec := serveAt(h, "POST", "/orders/1", "[2001:db8::1]:444")
		if rec.Code != 403 || probe.called != 0 {
			t.Fatalf("blocked request: %d, handler %d", rec.Code, probe.called)
		}
		var body map[string]string
		_ = json.Unmarshal(rec.Body.Bytes(), &body)
		ev := deceptionEvents(log)
		if body["attack"] != "deception" || body["rule"] != "deception.suspicious" || body["event"] != ev[1].Attrs["shield360.rasp.event_id"] {
			t.Fatalf("block body %v", body)
		}
		if ev[0].Attrs["shield360.rasp.decision"] != "blocked" || ev[1].Attrs["shield360.rasp.mode"] != "block" {
			t.Fatalf("events %v", ev)
		}
	})

	t.Run("attacks.deception caps the action; the default mode does not apply", func(t *testing.T) {
		cases := []struct {
			name   string
			block  string
			signed Mode
			mode   Mode
			want   int // status of the marked client's request; 0 = off (decoy reaches the app)
		}{
			{"unset, action block", blockBlock, "", ModeMonitor, 403},
			{"signed block, action block", blockBlock, ModeBlock, "", 403},
			{"signed monitor caps", blockBlock, ModeMonitor, ModeBlock, 200},
			{"signed block does not raise monitor", monitorBlock, ModeBlock, "", 200},
			{"default mode block does not raise monitor", monitorBlock, "", ModeBlock, 200},
			{"signed off", blockBlock, ModeOff, "", 0},
		}
		for _, c := range cases {
			t.Run(c.name, func(t *testing.T) {
				deceptionSetup(t, engineSettings{}, c.block, func(r *RemoteConfig) {
					r.Mode = c.mode
					if c.signed != "" {
						r.Attacks[Deception] = c.signed
					}
				})
				probe := &handlerProbe{}
				h := Middleware(probe.handler())
				first := serveAt(h, "GET", "/wp-admin", "203.0.113.7:1")
				if c.want == 0 {
					if probe.called != 1 || first.Code != 404 {
						t.Fatal("off: the decoy should reach the app")
					}
					return
				}
				if got := serveAt(h, "GET", "/orders/1", "203.0.113.7:2").Code; got != c.want {
					t.Fatalf("got %d, want %d", got, c.want)
				}
			})
		}
	})

	t.Run("local off, monitor-only and the kill switch", func(t *testing.T) {
		for name, s := range map[string]engineSettings{
			"local off": {attacks: map[AttackType]Mode{Deception: ModeOff}},
		} {
			deceptionSetup(t, s, blockBlock, nil)
			probe := &handlerProbe{}
			serveAt(Middleware(probe.handler()), "GET", "/wp-admin", "203.0.113.8:1")
			if probe.called != 1 {
				t.Fatalf("%s: decoy intercepted", name)
			}
		}
		log, _ := deceptionSetup(t, engineSettings{monitorOnly: true}, blockBlock, nil)
		probe := &handlerProbe{}
		h := Middleware(probe.handler())
		serveAt(h, "GET", "/wp-admin", "203.0.113.9:1")
		if serveAt(h, "GET", "/orders/1", "203.0.113.9:2").Code != 200 || deceptionEvents(log)[1].Attrs["shield360.rasp.decision"] != "monitored" {
			t.Fatal("monitor-only did not cap block")
		}
		deceptionSetup(t, engineSettings{}, blockBlock, func(r *RemoteConfig) { r.KillSwitch = true })
		probe = &handlerProbe{}
		serveAt(Middleware(probe.handler()), "GET", "/wp-admin", "203.0.113.10:1")
		if probe.called != 1 {
			t.Fatal("kill switch: decoy intercepted")
		}
	})

	t.Run("dropping the config turns deception off; a new config keeps marks", func(t *testing.T) {
		deceptionSetup(t, engineSettings{}, blockBlock, nil)
		probe := &handlerProbe{}
		h := Middleware(probe.handler())
		serveAt(h, "GET", "/wp-admin", "203.0.113.11:1")
		setRemoteConfig(remote(func(r *RemoteConfig) {
			r.Deception = ParseDeception(json.RawMessage(`{"paths":["/phpmyadmin"],"action":"block"}`))
		}))
		if serveAt(h, "GET", "/orders/1", "203.0.113.11:2").Code != 403 {
			t.Fatal("mark lost on a config change")
		}
		setRemoteConfig(nil)
		if serveAt(h, "GET", "/wp-admin", "203.0.113.11:3").Code != 404 || probe.called != 1 {
			t.Fatal("deception still on without a config")
		}
	})

	t.Run("no client address: still a 404, nothing marked", func(t *testing.T) {
		deceptionSetup(t, engineSettings{}, blockBlock, nil)
		probe := &handlerProbe{}
		h := Middleware(probe.handler())
		if serveAt(h, "GET", "/wp-admin", "").Code != 404 || probe.called != 0 || suspiciousTable().Len() != 0 {
			t.Fatal("no address")
		}
		if serveAt(h, "GET", "/orders/1", "").Code != 200 {
			t.Fatal("an unknown client is not suspicious")
		}
	})

	t.Run("fails open", func(t *testing.T) {
		deceptionSetup(t, engineSettings{}, blockBlock, nil)
		setSuspiciousTable(NewSuspiciousTable(10, func() time.Time { panic("clock") }))
		probe := &handlerProbe{}
		rec := serveAt(Middleware(probe.handler()), "GET", "/wp-admin", "203.0.113.12:1")
		if probe.called != 1 || rec.Code != 404 {
			t.Fatal("a panic in deception did not fail open")
		}
		rec = serveAt(Middleware(probe.handler()), "GET", "/orders/1", "203.0.113.12:1")
		if probe.called != 2 || rec.Code != 200 {
			t.Fatal("normal request broken")
		}
	})

	t.Run("a sink that panics does not change the answer", func(t *testing.T) {
		deceptionSetup(t, engineSettings{}, blockBlock, nil)
		setEventSink(panicSink{})
		probe := &handlerProbe{}
		if serveAt(Middleware(probe.handler()), "GET", "/wp-admin", "203.0.113.13:1").Code != 404 || probe.called != 0 {
			t.Fatal("reporting broke the decoy")
		}
	})
}

type panicSink struct{}

func (panicSink) add(Event, string) bool { panic("sink") }
