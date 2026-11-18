package rasp

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"
)

// Custom rules in the SDK (README "Custom rules"): rules arrive inside the
// signed config, invalid ones are skipped with one warning and never break
// the config, request rules run with the request's capture, finding rules
// when a built-in check fires, the custom_rule mode caps every action, and
// evaluation fails open.

func rule(over map[string]any) json.RawMessage {
	r := map[string]any{"id": "r1", "name": "Rule one", "expression": `request.path.startsWith("/admin")`, "action": "monitor", "enabled": true}
	for k, v := range over {
		r[k] = v
	}
	b, _ := json.Marshal(r)
	return b
}

func rawRules(items ...any) []json.RawMessage {
	var out []json.RawMessage
	for _, it := range items {
		if r, ok := it.(json.RawMessage); ok {
			out = append(out, r)
			continue
		}
		b, _ := json.Marshal(it)
		out = append(out, b)
	}
	return out
}

func ruleIDs(rules []*CustomRule) []string {
	out := []string{}
	for _, r := range rules {
		out = append(out, r.ID)
	}
	return out
}

// customRemote applies a signed config carrying the custom rules.
func customRemote(t *testing.T, attacks map[AttackType]Mode, rules ...json.RawMessage) {
	t.Helper()
	setRemoteConfig(remote(func(r *RemoteConfig) {
		r.Mode = ModeMonitor
		for k, v := range attacks {
			r.Attacks[k] = v
		}
		r.CustomRules = rules
	}))
	t.Cleanup(func() { setRemoteConfig(nil) })
}

func ruleEvents(log *eventLog) []string {
	out := []string{}
	for _, e := range log.all() {
		out = append(out, e.Attrs["shield360.rasp.rule"])
	}
	return out
}

// serve runs one request through Middleware and returns the recorder and
// whether the handler ran.
func serve(r *http.Request, h http.HandlerFunc) (*httptest.ResponseRecorder, bool) {
	ran := false
	w := httptest.NewRecorder()
	Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ran = true
		if h != nil {
			h(w, r)
		}
	})).ServeHTTP(w, r)
	return w, ran
}

func adminRequest() *http.Request {
	r := httptest.NewRequest(http.MethodGet, "/admin/users", nil)
	r.Header.Set("User-Agent", "curl/8.4")
	r.RemoteAddr = "10.1.2.3:5555"
	return r
}

func TestParseCustomRules(t *testing.T) {
	t.Cleanup(resetCustomRuleWarnings)

	t.Run("keeps valid, enabled rules for this app, in order", func(t *testing.T) {
		resetCustomRuleWarnings()
		var warned []SkippedRule
		got := ParseCustomRules(rawRules(rule(nil), rule(map[string]any{"id": "r2", "apps": []string{"orders-api", "billing"}}),
			rule(map[string]any{"id": "r3", "apps": []string{"billing"}}), rule(map[string]any{"id": "r4", "enabled": false}),
			rule(map[string]any{"id": "r5", "apps": nil}), rule(map[string]any{"id": "r6", "apps": []string{}})),
			"orders-api", func(s SkippedRule) { warned = append(warned, s) })
		if !reflect.DeepEqual(ruleIDs(got), []string{"r1", "r2", "r5", "r6"}) || len(warned) != 0 {
			t.Errorf("%v %v", ruleIDs(got), warned)
		}
		if got[0].Name != "Rule one" || got[0].Action != "monitor" || got[0].Expr.Phase != PhaseRequest {
			t.Errorf("%+v", got[0])
		}
	})

	t.Run("skips each invalid rule with one warning, and never warns twice for it", func(t *testing.T) {
		resetCustomRuleWarnings()
		raw := rawRules(
			rule(map[string]any{"id": "Bad Id"}),
			rule(map[string]any{"id": "ok-1"}),
			rule(map[string]any{"id": "ok-1"}),
			rule(map[string]any{"id": "x2", "action": "allow"}),
			rule(map[string]any{"id": "x3", "enabled": "yes"}),
			rule(map[string]any{"id": "x4", "expression": `request.method = "GET"`}),
			rule(map[string]any{"id": "x5", "apps": "orders-api"}),
			rule(map[string]any{"id": "x6", "name": 7}),
			nil,
			"rule",
		)
		var warned []SkippedRule
		warn := func(s SkippedRule) { warned = append(warned, s) }
		if got := ruleIDs(ParseCustomRules(raw, "orders-api", warn)); !reflect.DeepEqual(got, []string{"ok-1"}) {
			t.Fatal(got)
		}
		if len(warned) != 9 {
			t.Fatalf("%d warnings: %v", len(warned), warned)
		}
		reasons := []string{}
		for _, w := range warned {
			reasons = append(reasons, w.Reason)
		}
		want := []string{"invalid id", "duplicate id", "invalid action", "invalid enabled flag", "expression: syntax", "invalid apps", "invalid name", "not an object", "not an object"}
		if !reflect.DeepEqual(reasons, want) {
			t.Errorf("%v", reasons)
		}
		ParseCustomRules(raw, "orders-api", warn)
		if len(warned) != 9 {
			t.Errorf("warned again: %d", len(warned))
		}
	})

	t.Run("the default warning names the rule and the reason", func(t *testing.T) {
		resetCustomRuleWarnings()
		logs := captureLogs(t)
		ParseCustomRules(rawRules(rule(map[string]any{"id": "broken", "expression": `request.path.matches("(a+)+")`})), "a", nil)
		if l := logs(); len(l) != 1 || !strings.Contains(l[0], `"broken"`) || !strings.Contains(l[0], "expression: regex") {
			t.Errorf("%v", l)
		}
	})

	t.Run("keeps at most 64", func(t *testing.T) {
		resetCustomRuleWarnings()
		var raw []json.RawMessage
		for i := 0; i < 70; i++ {
			raw = append(raw, rule(map[string]any{"id": "r" + string(rune('a'+i/26)) + string(rune('a'+i%26))}))
		}
		if got := ParseCustomRules(raw, "a", func(SkippedRule) {}); len(got) != 64 {
			t.Error(len(got))
		}
	})

	t.Run("more than 32 apps is invalid", func(t *testing.T) {
		apps := make([]string, 33)
		for i := range apps {
			apps[i] = "a"
		}
		if got := ParseCustomRules(rawRules(rule(map[string]any{"apps": apps})), "a", func(SkippedRule) {}); len(got) != 0 {
			t.Error(ruleIDs(got))
		}
	})
}

func TestRequestSubject(t *testing.T) {
	setupEngine(t, engineSettings{})
	r := httptest.NewRequest("POST", "/api/orders/42?id=42&id=43&q=%252e%252e", nil)
	r.Header.Set("User-Agent", "curl/8.4")
	r.Header.Add("X-Multi", "a")
	r.Header.Add("X-Multi", "b")
	r.RemoteAddr = "[::ffff:10.1.2.3]:443"
	c := captureRequest(r, Framework)
	c.captureBody([]byte(`{"user":{"role":"admin"}}`), "application/json")
	s := requestSubject(c, "orders-api")
	q := s.Request
	if *q.Method != "POST" || *q.Path != "/api/orders/42" || *q.Route != "/api/orders/:id" || *q.IP != "::ffff:10.1.2.3" {
		t.Errorf("%s %s %s %s", *q.Method, *q.Path, *q.Route, *q.IP)
	}
	if q.Query["id"] != "42" || q.Query["q"] != "%2e%2e" || q.Body["user.role"] != "admin" {
		t.Errorf("%v %v", q.Query, q.Body)
	}
	if q.Headers["user-agent"] != "curl/8.4" || q.Headers["x-multi"] != "a, b" {
		t.Errorf("%v", q.Headers)
	}
	decoded := false
	for _, in := range s.Inputs {
		decoded = decoded || (in.Key == "query.q" && in.Value == "..")
	}
	if !decoded {
		t.Errorf("%v", s.Inputs)
	}
	if s := requestSubject(nil, "a"); s.Request != nil || *s.App != "a" {
		t.Error("no context")
	}
	if s := requestSubject(&Context{inputs: []Input{{Value: "v", Key: "model.x", Source: SourceModelOutput}}}, "a"); s.Request != nil || len(s.Inputs) != 1 {
		t.Error("outside a request")
	}
}

func TestCustomRequestRules(t *testing.T) {
	t.Run("report a match as a custom_rule event and let the request through in monitor", func(t *testing.T) {
		log := setupEngine(t, engineSettings{})
		customRemote(t, nil, rule(map[string]any{"action": "alert"}))
		if _, ran := serve(adminRequest(), nil); !ran {
			t.Fatal("blocked")
		}
		ev := log.all()
		if len(ev) != 1 {
			t.Fatalf("%v", ev)
		}
		for k, v := range map[string]string{
			"shield360.rasp.attack": "custom_rule", "shield360.rasp.rule": "custom.r1", "shield360.rasp.decision": "monitored",
			"shield360.rasp.sink": "server.request", "shield360.rasp.route": "/admin/users", "shield360.rasp.config_version": "v1",
		} {
			if ev[0].Attrs[k] != v {
				t.Errorf("%s = %q", k, ev[0].Attrs[k])
			}
		}
	})

	t.Run("block only when the rule says block and the custom_rule mode is block", func(t *testing.T) {
		log := setupEngine(t, engineSettings{})
		customRemote(t, nil, rule(map[string]any{"action": "block"}))
		if _, ran := serve(adminRequest(), nil); !ran || log.all()[0].Attrs["shield360.rasp.decision"] != "monitored" {
			t.Error("block action in monitor mode")
		}
		customRemote(t, map[AttackType]Mode{CustomRuleAttack: ModeBlock}, rule(map[string]any{"action": "monitor"}))
		if _, ran := serve(adminRequest(), nil); !ran {
			t.Error("monitor action in block mode")
		}
		customRemote(t, map[AttackType]Mode{CustomRuleAttack: ModeBlock}, rule(map[string]any{"action": "block"}))
		w, ran := serve(adminRequest(), nil)
		var body BlockBody
		_ = json.Unmarshal(w.Body.Bytes(), &body)
		if ran || w.Code != 403 || body.Attack != CustomRuleAttack || body.Rule != "custom.r1" {
			t.Errorf("%v %d %+v", ran, w.Code, body)
		}
		customRemote(t, map[AttackType]Mode{CustomRuleAttack: ModeOff}, rule(map[string]any{"action": "block"}))
		before := len(log.all())
		if _, ran := serve(adminRequest(), nil); !ran || len(log.all()) != before {
			t.Error("mode off")
		}
	})

	t.Run("match each rule once per request; input rules run again when the body arrives", func(t *testing.T) {
		log := setupEngine(t, engineSettings{})
		customRemote(t, nil,
			rule(map[string]any{"id": "path", "expression": `request.path == "/upload"`}),
			rule(map[string]any{"id": "traversal", "expression": `input.value.contains("../")`}),
			rule(map[string]any{"id": "role", "expression": `request.body["role"] == "admin"`}),
			rule(map[string]any{"id": "ip", "expression": `request.ip.inCidr("10.0.0.0/8") && request.headers["user-agent"].startsWith("curl/")`}),
		)
		// A body Middleware does not read (GET) stays unknown until the app
		// records it; a request without one has a known, empty body.
		r := httptest.NewRequest(http.MethodGet, "/upload", strings.NewReader("{}"))
		r.Header.Set("User-Agent", "curl/8.4")
		r.RemoteAddr = "10.1.2.3:5555"
		serve(r, func(w http.ResponseWriter, r *http.Request) {
			if !reflect.DeepEqual(ruleEvents(log), []string{"custom.path", "custom.ip"}) {
				t.Errorf("head: %v", ruleEvents(log))
			}
			if err := RecordRequestBody(r.Context(), map[string]any{"role": "admin", "file": "../../etc/passwd"}, "application/json"); err != nil {
				t.Error(err)
			}
		})
		if got := ruleEvents(log); !reflect.DeepEqual(got, []string{"custom.path", "custom.ip", "custom.traversal", "custom.role"}) {
			t.Errorf("body: %v", got)
		}
		if k := log.all()[2].Attrs["shield360.rasp.input_key"]; k != "body.file" {
			t.Errorf("input key %q", k)
		}
	})

	t.Run("stop at the first rule that blocks", func(t *testing.T) {
		log := setupEngine(t, engineSettings{})
		customRemote(t, map[AttackType]Mode{CustomRuleAttack: ModeBlock}, rule(map[string]any{"id": "a", "action": "block"}), rule(map[string]any{"id": "b"}))
		if _, ran := serve(adminRequest(), nil); ran {
			t.Error("not blocked")
		}
		if got := ruleEvents(log); !reflect.DeepEqual(got, []string{"custom.a"}) {
			t.Error(got)
		}
	})

	t.Run("a virtual patch that blocks first means no custom rule runs", func(t *testing.T) {
		log := setupEngine(t, engineSettings{})
		vp := exampleRule()
		setRemoteConfig(remote(func(r *RemoteConfig) {
			r.Attacks[VirtualPatch] = ModeBlock
			r.Rules = []VirtualPatchRule{vp}
			r.CustomRules = []json.RawMessage{rule(map[string]any{"expression": "true"})}
		}))
		t.Cleanup(func() { setRemoteConfig(nil) })
		c := &Context{inRequest: true, method: "GET", path: "/", vp: &vpState{req: *requestFor(vp)}}
		if err := runVirtualPatches(c); AsBlocked(err) == nil {
			t.Fatalf("not blocked: %v", err)
		}
		if got := ruleEvents(log); len(got) != 1 || got[0] != vp.ID {
			t.Error(got)
		}
	})

	t.Run("fail open when the work budget runs out", func(t *testing.T) {
		log := setupEngine(t, engineSettings{})
		customRemote(t, map[AttackType]Mode{CustomRuleAttack: ModeBlock}, rule(map[string]any{"expression": `input.value.matches("a{100}x")`, "action": "block"}))
		var q []string
		for i := 0; i < 200; i++ {
			q = append(q, "k"+strings.Repeat("x", i%7)+string(rune('a'+i%26))+"="+strings.Repeat("a", 4096))
		}
		if _, ran := serve(httptest.NewRequest(http.MethodGet, "/x?"+strings.Join(q, "&"), nil), nil); !ran {
			t.Error("blocked")
		}
		if len(log.all()) != 0 {
			t.Error(ruleEvents(log))
		}
	})

	t.Run("do nothing while RASP is off", func(t *testing.T) {
		log := setupEngine(t, engineSettings{})
		customRemote(t, map[AttackType]Mode{CustomRuleAttack: ModeBlock}, rule(map[string]any{"action": "block"}))
		Disable()
		defer Enable()
		if _, ran := serve(adminRequest(), nil); !ran || len(log.all()) != 0 {
			t.Error("ran while off")
		}
	})

	t.Run("a local off for custom_rule wins over the signed mode", func(t *testing.T) {
		log := setupEngine(t, engineSettings{attacks: map[AttackType]Mode{CustomRuleAttack: ModeOff}})
		customRemote(t, map[AttackType]Mode{CustomRuleAttack: ModeBlock}, rule(map[string]any{"action": "block"}))
		if _, ran := serve(adminRequest(), nil); !ran || len(log.all()) != 0 {
			t.Error("local off ignored")
		}
	})
}

func TestCustomFindingRules(t *testing.T) {
	sqli := func() *Finding {
		return &Finding{Attack: SQLInjection, Rule: "sqli.userinput", Input: &Input{Value: "1 OR 1=1", Key: "query.q", Source: SourceRequest}}
	}
	reqCtx := func(target string) context.Context {
		return withContext(context.Background(), captureRequest(httptest.NewRequest(http.MethodGet, target, nil), Framework))
	}

	t.Run("see the built-in finding, its sink and the request", func(t *testing.T) {
		log := setupEngine(t, engineSettings{})
		customRemote(t, nil, rule(map[string]any{"id": "admin-sqli", "action": "alert",
			"expression": `attack.type == "sql_injection" && sink.name == "pg.query" && request.path.startsWith("/admin")`}))
		if _, err := HandleFinding(reqCtx("/admin/search?q=1%20OR%201%3D1"), sqli(), "pg.query", FindingExtra{}); err != nil {
			t.Fatal(err)
		}
		ev := log.all()
		if len(ev) != 2 || ev[0].Attrs["shield360.rasp.rule"] != "sqli.userinput" || ev[1].Attrs["shield360.rasp.rule"] != "custom.admin-sqli" ||
			ev[1].Attrs["shield360.rasp.attack"] != "custom_rule" || ev[1].Attrs["shield360.rasp.sink"] != "pg.query" || ev[1].Attrs["shield360.rasp.input_key"] != "query.q" {
			t.Errorf("%v", ev)
		}
	})

	t.Run("never run in the request phase, and request rules never run on findings", func(t *testing.T) {
		log := setupEngine(t, engineSettings{})
		customRemote(t, nil, rule(map[string]any{"id": "f", "expression": `attack.type != null`}), rule(map[string]any{"id": "q", "expression": `request.path == "/a"`}))
		ctx := reqCtx("/a")
		if err := runVirtualPatches(FromContext(ctx)); err != nil {
			t.Fatal(err)
		}
		if got := ruleEvents(log); !reflect.DeepEqual(got, []string{"custom.q"}) {
			t.Error(got)
		}
		_, _ = HandleFinding(ctx, sqli(), "pg.query", FindingExtra{})
		if got := ruleEvents(log); !reflect.DeepEqual(got, []string{"custom.q", "sqli.userinput", "custom.f"}) {
			t.Error(got)
		}
	})

	t.Run("can block a finding the attack type only monitors; the built-in block wins when both block", func(t *testing.T) {
		setupEngine(t, engineSettings{})
		stop := rule(map[string]any{"id": "stop", "expression": `attack.type == "sql_injection"`, "action": "block"})
		customRemote(t, map[AttackType]Mode{CustomRuleAttack: ModeBlock}, stop)
		d, err := HandleFinding(reqCtx("/a"), sqli(), "pg.query", FindingExtra{})
		if b := AsBlocked(err); b == nil || b.Attack != CustomRuleAttack || d != DecisionBlocked {
			t.Errorf("%v %v", d, err)
		}
		customRemote(t, map[AttackType]Mode{CustomRuleAttack: ModeBlock, SQLInjection: ModeBlock}, stop)
		_, err = HandleFinding(reqCtx("/a"), sqli(), "pg.query", FindingExtra{})
		if b := AsBlocked(err); b == nil || b.Attack != SQLInjection {
			t.Errorf("%v", err)
		}
	})

	t.Run("block a real sink through the finding rule", func(t *testing.T) {
		setupEngine(t, engineSettings{})
		customRemote(t, map[AttackType]Mode{CustomRuleAttack: ModeBlock}, rule(map[string]any{"id": "no-sqli-admin", "action": "block",
			"expression": `attack.type == "sql_injection" && request.path.startsWith("/admin")`}))
		ctx := reqCtx("/admin?q=" + "x%27%20OR%20%271%27%3D%271")
		err := checkSink(ctx, "db.postgres.query", func(slot *iastSlot) *Finding {
			return detectSQLWith("SELECT * FROM t WHERE a = 'x' OR '1'='1'", FromContext(ctx).Inputs(), DialectPostgres, slot)
		})
		if b := AsBlocked(err); b == nil || b.Rule != "custom.no-sqli-admin" {
			t.Errorf("%v", err)
		}
	})

	t.Run("skip attack types that are off", func(t *testing.T) {
		log := setupEngine(t, engineSettings{})
		customRemote(t, map[AttackType]Mode{SQLInjection: ModeOff}, rule(map[string]any{"expression": `attack.type == "sql_injection"`}))
		_, _ = HandleFinding(reqCtx("/a"), sqli(), "pg.query", FindingExtra{})
		if len(log.all()) != 0 {
			t.Error(ruleEvents(log))
		}
	})

	t.Run("run outside a request with the request fields null", func(t *testing.T) {
		log := setupEngine(t, engineSettings{})
		customRemote(t, nil, rule(map[string]any{"expression": `request.path == null && app.name == "orders-api" && attack.type == "sql_injection"`}))
		_, _ = HandleFinding(context.Background(), sqli(), "pg.query", FindingExtra{})
		if got := ruleEvents(log); !reflect.DeepEqual(got, []string{"sqli.userinput", "custom.r1"}) {
			t.Error(got)
		}
	})

	t.Run("goroutines sharing a request share the budget safely", func(t *testing.T) {
		setupEngine(t, engineSettings{})
		customRemote(t, nil, rule(map[string]any{"expression": `attack.type == "sql_injection" && input.value.matches("OR")`}))
		ctx := reqCtx("/a?q=1%20OR%201")
		var wg sync.WaitGroup
		for i := 0; i < 16; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				_, _ = HandleFinding(ctx, sqli(), "pg.query", FindingExtra{})
			}()
		}
		wg.Wait()
	})
}

func TestSignedCustomRulesRoundTrip(t *testing.T) {
	k1 := keyPair(t, "k1")
	logs := captureLogs(t)
	resetCustomRuleWarnings()
	t.Cleanup(func() { setRemoteConfig(nil); resetCustomRuleWarnings() })
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/api/rasp/config") {
			c := claims(map[string]any{
				"exp": time.Now().Unix() + 600, "version": "cfg-1",
				"attacks":     map[string]any{"ssrf": "block", "custom_rule": "block"},
				"customRules": []any{json.RawMessage(rule(map[string]any{"action": "block"})), json.RawMessage(rule(map[string]any{"id": "broken", "expression": `request.path.matches("(a+)+")`}))},
			})
			_ = json.NewEncoder(w).Encode(map[string]any{"config": jws(k1, c, nil)})
			return
		}
		_, _ = w.Write([]byte("{}"))
	}))
	defer srv.Close()
	Init(&Options{DisableComponents: true, CacheDir: t.TempDir(), ConfigPublicKey: jsonText(jwk(k1))},
		InitContext{ApplicationName: "orders-api", URL: srv.URL, APIKey: "k", Getenv: noEnv})
	deadline := time.Now().Add(5 * time.Second)
	for len(CustomRules()) == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if got := ruleIDs(CustomRules()); !reflect.DeepEqual(got, []string{"r1"}) {
		t.Fatal(got)
	}
	if ModeFor(SSRF) != ModeBlock || ModeFor(CustomRuleAttack) != ModeBlock {
		t.Error("the rest of the config")
	}
	var custom []string
	for _, l := range logs() {
		if strings.Contains(l, "custom rule") {
			custom = append(custom, l)
		}
	}
	if len(custom) != 1 || !strings.Contains(custom[0], `"broken"`) {
		t.Errorf("%v", custom)
	}
	w, ran := serve(adminRequest(), nil)
	if ran || w.Code != 403 {
		t.Errorf("not blocked: %d", w.Code)
	}
}

// Mode off skips custom rules: no expression is evaluated, so no budget is
// spent and no request-state lock is taken.
func TestCustomRulesOffAreNotEvaluated(t *testing.T) {
	for _, local := range []bool{false, true} {
		var attacks map[AttackType]Mode
		if local {
			attacks = map[AttackType]Mode{CustomRuleAttack: ModeOff}
		}
		log := setupEngine(t, engineSettings{attacks: attacks})
		signed := map[AttackType]Mode{CustomRuleAttack: ModeOff}
		if local {
			signed = map[AttackType]Mode{CustomRuleAttack: ModeBlock}
		}
		customRemote(t, signed,
			rule(map[string]any{"id": "req", "expression": `input.value.matches("a+b")`, "action": "block"}),
			rule(map[string]any{"id": "fnd", "expression": `attack.type != null && input.value.matches("a+b")`, "action": "block"}))
		c := captureRequest(httptest.NewRequest(http.MethodGet, "/x?q="+strings.Repeat("a", 4000), nil), Framework)
		if err := runVirtualPatches(c); err != nil {
			t.Fatal(err)
		}
		_, _ = HandleFinding(withContext(context.Background(), c), &Finding{Attack: SQLInjection, Rule: "sqli.userinput"}, "pg.query", FindingExtra{})
		if c.ruleSt != nil {
			t.Errorf("local=%v: rules evaluated (%d steps left)", local, c.ruleSt.budget.Steps)
		}
		for _, r := range ruleEvents(log) {
			if strings.HasPrefix(r, CustomRulePrefix) {
				t.Errorf("local=%v: %s reported", local, r)
			}
		}
	}
}
