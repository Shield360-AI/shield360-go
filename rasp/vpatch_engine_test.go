package rasp

import (
	"context"
	"encoding/json"
	"errors"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"
)

// Virtual patches: each built-in rule matches a request built from the shape
// its own rule file documents (no new payloads), and stops matching when one
// clause is missing. Then the engine: modes, caps, kill switches, events.

type jsonRaw = json.RawMessage

func versionIn(rule VirtualPatchRule, rt string) string {
	if r := rule.RuntimeVersions[rt]; len(r) > 0 {
		return r[0][0]
	}
	return "24.22.0"
}

// runtimeFor is a runtime the rule applies in.
func runtimeFor(rule VirtualPatchRule) string {
	if len(rule.Runtimes) > 0 {
		return rule.Runtimes[0]
	}
	return Runtime
}

func TestVirtualPatches(t *testing.T) {
	for _, rule := range BuiltInRules {
		rt := runtimeFor(rule)
		v := versionIn(rule, rt)
		t.Run(rule.ID+" matches its documented request shape", func(t *testing.T) {
			f := MatchVirtualPatches(requestFor(rule), []VirtualPatchRule{rule}, PhaseAll, rt, v)
			if f == nil || f.Attack != VirtualPatch || f.Rule != rule.ID {
				t.Fatalf("got %+v", f)
			}
			want := rule.Action
			if want == "" {
				want = ModeBlock
			}
			if f.Action != want {
				t.Errorf("action = %s, want %s", f.Action, want)
			}
			if len(rule.CVEs) > 0 && f.CVE != rule.CVEs[0] {
				t.Errorf("cve = %s", f.CVE)
			}
		})
		t.Run(rule.ID+" needs every clause", func(t *testing.T) {
			for i, c := range rule.Match {
				cut := rule
				cut.Match = append(append([]MatchClause{}, rule.Match[:i]...), rule.Match[i+1:]...)
				r := requestFor(cut)
				// A clause on a target the remaining clauses also fill can still be met.
				if ClauseMatches(r, c) {
					continue
				}
				if f := MatchVirtualPatches(r, []VirtualPatchRule{rule}, PhaseAll, rt, v); f != nil {
					t.Errorf("matched without clause %d", i)
				}
			}
		})
	}

	t.Run("built-in node rules never apply in Go; the example rule applies everywhere", func(t *testing.T) {
		for _, rule := range BuiltInRules {
			applies := RuleApplies(rule, Runtime, RuntimeVersion())
			if rule.Example != applies {
				t.Errorf("%s applies in go = %v", rule.ID, applies)
			}
		}
	})

	t.Run("runtimeVersions: [from, to) ranges; other runtimes skip node rules", func(t *testing.T) {
		var rule VirtualPatchRule
		for _, r := range BuiltInRules {
			if len(r.RuntimeVersions["node"]) > 0 {
				rule = r
			}
		}
		from, to := rule.RuntimeVersions["node"][0][0], rule.RuntimeVersions["node"][0][1]
		if !RuleApplies(rule, "node", from) || RuleApplies(rule, "node", to) || RuleApplies(rule, "python", from) {
			t.Error("range check failed")
		}
	})

	t.Run("runtimeVersions for go", func(t *testing.T) {
		rule := VirtualPatchRule{ID: "vp.go-test", Runtimes: []string{"go"}, RuntimeVersions: map[string][][2]string{"go": {{"1.22.0", "1.22.5"}}},
			Match: []MatchClause{{Target: "method", Op: "equals", Values: []string{"GET"}}}}
		r := &VpRequest{Method: "GET", Headers: map[string]string{}}
		if MatchVirtualPatches(r, []VirtualPatchRule{rule}, PhaseAll, "go", "1.22.4") == nil {
			t.Error("1.22.4 is in [1.22.0, 1.22.5)")
		}
		if MatchVirtualPatches(r, []VirtualPatchRule{rule}, PhaseAll, "go", "1.22.5") != nil {
			t.Error("1.22.5 is outside")
		}
		if MatchVirtualPatches(r, []VirtualPatchRule{rule}, PhaseAll, "node", "1.22.4") != nil {
			t.Error("a go rule never applies in node")
		}
		if !regexp.MustCompile(`^\d+\.\d+`).MatchString(RuntimeVersion()) {
			t.Errorf("RuntimeVersion = %q", RuntimeVersion())
		}
	})

	t.Run("phases: head rules never read the body; body rules wait for it", func(t *testing.T) {
		var bodyRule VirtualPatchRule
		for _, r := range BuiltInRules {
			if NeedsBody(r) {
				bodyRule = r
				break
			}
		}
		r := requestFor(bodyRule)
		rt := runtimeFor(bodyRule)
		if MatchVirtualPatches(r, []VirtualPatchRule{bodyRule}, PhaseHead, rt, versionIn(bodyRule, rt)) != nil {
			t.Error("head phase judged a body rule")
		}
		if f := MatchVirtualPatches(r, []VirtualPatchRule{bodyRule}, PhaseBody, rt, versionIn(bodyRule, rt)); ruleOf(f) != bodyRule.ID {
			t.Errorf("body phase: %v", f)
		}
	})

	t.Run("refuses patterns with backreferences or lookaround", func(t *testing.T) {
		r := &VpRequest{Method: "GET", Path: "/aa", Headers: map[string]string{}}
		if !ClauseMatches(r, MatchClause{Target: "path", Op: "regex", Value: "^/a+$"}) {
			t.Error("plain pattern")
		}
		if ClauseMatches(r, MatchClause{Target: "path", Op: "regex", Value: `(a)\1`}) || ClauseMatches(r, MatchClause{Target: "path", Op: "regex", Value: "a(?=a)"}) {
			t.Error("refused patterns matched")
		}
	})

	t.Run("lenient parsing: invalid rules are dropped one by one", func(t *testing.T) {
		rules := parseRules([]jsonRaw{
			jsonRaw(`{"id":"vp.ok","match":[{"target":"method","op":"equals","values":["GET",3]}]}`),
			jsonRaw(`{"id":5,"match":[]}`),
			jsonRaw(`{"id":"vp.nomatch"}`),
			jsonRaw(`"text"`),
		})
		if len(rules) != 1 || rules[0].ID != "vp.ok" || len(rules[0].Match[0].Values) != 1 {
			t.Errorf("rules = %+v", rules)
		}
	})
}

type eventLog struct {
	mu     sync.Mutex
	events []Event
}

func (l *eventLog) add(e Event, _ string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.events = append(l.events, e)
	return true
}

func (l *eventLog) all() []Event {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]Event(nil), l.events...)
}

func noEnv(string) string { return "" }

func envOf(kv ...string) func(string) string {
	m := map[string]string{}
	for i := 0; i+1 < len(kv); i += 2 {
		m[kv[i]] = kv[i+1]
	}
	return func(k string) string { return m[k] }
}

// setupEngine configures the engine for a test and restores the off state
// afterwards.
func setupEngine(t *testing.T, s engineSettings) *eventLog {
	t.Helper()
	if s.applicationName == "" {
		s.applicationName = "orders-api"
	}
	if s.getenv == nil {
		s.getenv = noEnv
	}
	s.enabled = true
	// SHIELD: AI attack agents — off unless the test sets it: findings and 404s from the
	// shared test address would otherwise add up across tests and mark it.
	if _, ok := s.attacks[AIAttackAgent]; !ok {
		attacks := map[AttackType]Mode{AIAttackAgent: ModeOff}
		for k, v := range s.attacks {
			attacks[k] = v
		}
		s.attacks = attacks
	}
	setAgentTracker(nil)
	configureEngine(s)
	log := &eventLog{}
	setEventSink(log)
	t.Cleanup(func() {
		setEventSink(nil)
		configureEngine(engineSettings{applicationName: "default", getenv: noEnv})
	})
	return log
}

func remote(over func(*RemoteConfig)) *RemoteConfig {
	r := &RemoteConfig{Version: "v1", Attacks: map[AttackType]Mode{}}
	if over != nil {
		over(r)
	}
	return r
}

var finding = Finding{Attack: SQLInjection, Rule: "sqli.userinput", Input: &Input{Value: "v", Key: "query.id", Source: SourceRequest}}

func TestEngine(t *testing.T) {
	ctx := context.Background()

	t.Run("monitor by default: reports, never blocks", func(t *testing.T) {
		log := setupEngine(t, engineSettings{})
		f := finding
		d, err := HandleFinding(ctx, &f, "pg.query", FindingExtra{})
		if d != DecisionMonitored || err != nil {
			t.Fatalf("d=%s err=%v", d, err)
		}
		ev := log.all()
		if len(ev) != 1 {
			t.Fatalf("events = %d", len(ev))
		}
		a := ev[0].Attrs
		if !regexp.MustCompile(`^[a-f0-9]{32}$`).MatchString(a["shield360.rasp.event_id"]) {
			t.Errorf("event id %q", a["shield360.rasp.event_id"])
		}
		if a["shield360.rasp.input_key"] != "query.id" || a["shield360.rasp.config_version"] != "local" || a["shield360.rasp.language"] != "go" {
			t.Errorf("attrs %v", a)
		}
		for k, v := range a {
			if v == "v" {
				t.Errorf("the input value leaked into %s", k)
			}
		}
	})

	t.Run("block mode returns the typed error with the event id", func(t *testing.T) {
		log := setupEngine(t, engineSettings{attacks: map[AttackType]Mode{SQLInjection: ModeBlock}})
		f := finding
		d, err := HandleFinding(ctx, &f, "pg.query", FindingExtra{})
		if d != DecisionBlocked || !errors.Is(err, ErrBlocked) {
			t.Fatalf("d=%s err=%v", d, err)
		}
		b := AsBlocked(err)
		if b.EventID != log.all()[0].Attrs["shield360.rasp.event_id"] || b.StatusCode() != 403 {
			t.Errorf("block error %+v", b)
		}
	})

	t.Run("xss never blocks", func(t *testing.T) {
		setupEngine(t, engineSettings{mode: ModeBlock})
		if ModeFor(XSS) != ModeMonitor {
			t.Error("xss mode")
		}
		if d, err := HandleFinding(ctx, &Finding{Attack: XSS, Rule: "xss.reflected"}, "http.response", FindingExtra{}); d != DecisionMonitored || err != nil {
			t.Errorf("d=%s err=%v", d, err)
		}
	})

	t.Run("a virtual patch is capped by its own action and by the virtual_patch mode", func(t *testing.T) {
		setupEngine(t, engineSettings{attacks: map[AttackType]Mode{VirtualPatch: ModeBlock}})
		if d, _ := HandleFinding(ctx, &Finding{Attack: VirtualPatch, Rule: "vp.x", Action: ModeMonitor}, VpSink, FindingExtra{}); d != DecisionMonitored {
			t.Errorf("own action: %s", d)
		}
		setupEngine(t, engineSettings{})
		if d, _ := HandleFinding(ctx, &Finding{Attack: VirtualPatch, Rule: "vp.x", Action: ModeBlock}, VpSink, FindingExtra{}); d != DecisionMonitored {
			t.Errorf("mode cap: %s", d)
		}
	})

	t.Run("the signed config overrides local modes, except a local off", func(t *testing.T) {
		setupEngine(t, engineSettings{attacks: map[AttackType]Mode{SQLInjection: ModeMonitor, SSRF: ModeOff}})
		setRemoteConfig(remote(func(r *RemoteConfig) { r.Attacks = map[AttackType]Mode{SQLInjection: ModeBlock, SSRF: ModeBlock} }))
		if ModeFor(SQLInjection) != ModeBlock || ModeFor(SSRF) != ModeOff || ModeFor(XXE) != ModeMonitor {
			t.Errorf("modes %s %s %s", ModeFor(SQLInjection), ModeFor(SSRF), ModeFor(XXE))
		}
	})

	t.Run("monitor-only (no pinned key) caps block", func(t *testing.T) {
		setupEngine(t, engineSettings{mode: ModeBlock, monitorOnly: true})
		if ModeFor(SQLInjection) != ModeMonitor {
			t.Error("not capped")
		}
	})

	t.Run("kill switch order: env off, signed killSwitch, runtime call", func(t *testing.T) {
		setupEngine(t, engineSettings{getenv: envOf("SHIELD360_RASP", "off")})
		if Active() {
			t.Error("env off")
		}
		setupEngine(t, engineSettings{})
		setRemoteConfig(remote(func(r *RemoteConfig) { r.KillSwitch = true }))
		if Active() || ModeFor(SQLInjection) != ModeOff {
			t.Error("signed kill switch")
		}
		setRemoteConfig(remote(nil))
		Disable()
		if Active() {
			t.Error("runtime disable")
		}
		Enable()
		if !Active() {
			t.Error("enable")
		}
		if d, _ := Check(ctx, "pg.query", func() *Finding { f := finding; return &f }); d != DecisionMonitored {
			t.Error("check after enable")
		}
	})

	t.Run("SHIELD360_RASP=block sets the default mode", func(t *testing.T) {
		setupEngine(t, engineSettings{getenv: envOf("SHIELD360_RASP", "block")})
		if ModeFor(CommandInjection) != ModeBlock {
			t.Error("default mode")
		}
	})

	t.Run("the signed config rules replace the built-in list; nil keeps it", func(t *testing.T) {
		setupEngine(t, engineSettings{})
		setRemoteConfig(remote(func(r *RemoteConfig) {
			r.Rules = []VirtualPatchRule{{ID: "vp.only", Match: []MatchClause{{Target: "method", Op: "equals", Values: []string{"GET"}}}}}
		}))
		if got := VirtualPatches(); len(got) != 1 || got[0].ID != "vp.only" {
			t.Errorf("rules %v", got)
		}
		setRemoteConfig(remote(nil))
		if len(VirtualPatches()) != len(BuiltInRules) {
			t.Error("built-in list")
		}
	})

	t.Run("allow-lists: the signed config's lists win list by list", func(t *testing.T) {
		setupEngine(t, engineSettings{allow: Allow{Commands: []string{"convert"}, FileRoots: []string{"/srv"}}})
		setRemoteConfig(remote(func(r *RemoteConfig) { r.Allow = &RemoteAllow{Commands: []string{"git"}} }))
		a := AllowLists()
		if len(a.Commands) != 1 || a.Commands[0] != "git" || len(a.FileRoots) != 1 {
			t.Errorf("allow %+v", a)
		}
	})

	t.Run("snippets only with the signed snippets flag, masked and at most 64 characters", func(t *testing.T) {
		log := setupEngine(t, engineSettings{})
		secret := "token=" + strings.Repeat("s", 30)
		f := Finding{Attack: SQLInjection, Rule: "sqli.userinput", Input: &Input{Value: secret, Key: "body.t", Source: SourceRequest}}
		_, _ = HandleFinding(ctx, &f, "pg.query", FindingExtra{})
		if _, ok := log.all()[0].Attrs["shield360.rasp.snippet"]; ok {
			t.Error("snippet without the flag")
		}
		setRemoteConfig(remote(func(r *RemoteConfig) { r.Snippets = true }))
		f.Rule = "sqli.stacked"
		_, _ = HandleFinding(ctx, &f, "pg.query", FindingExtra{})
		if got := log.all()[1].Attrs["shield360.rasp.snippet"]; got != "token=***" {
			t.Errorf("snippet %q", got)
		}
		if n := len(MaskSnippet(strings.Repeat("a ", 200))); n > 64 {
			t.Errorf("snippet length %d", n)
		}
	})

	t.Run("events carry the route template or the path with ids replaced, and shaped keys", func(t *testing.T) {
		if got := RouteOf("/api/orders/12345/items/3f2a9c1e-0b1d-4e6f-8a7b-9c0d1e2f3a4b"); got != "/api/orders/:id/items/:id" {
			t.Errorf("RouteOf = %s", got)
		}
		if got := RouteOf("/a/deadbeef/cafebabe1/abcdefgh"); got != "/a/deadbeef/:id/abcdefgh" {
			t.Errorf("RouteOf hex = %s", got)
		}
		log := setupEngine(t, engineSettings{})
		rc := &Context{inRequest: true, method: "get", path: "/api/orders/42", framework: Framework}
		f := Finding{Attack: SQLInjection, Rule: "sqli.userinput", Input: &Input{Value: "v", Key: "query.a b", Source: SourceRequest}}
		_, _ = HandleFinding(withContext(ctx, rc), &f, "pg.query", FindingExtra{})
		a := log.all()[0].Attrs
		if a["shield360.rasp.route"] != "/api/orders/:id" || a["shield360.rasp.method"] != "GET" || a["shield360.rasp.framework"] != "net/http" || a["shield360.rasp.input_key"] != "query.a_b" {
			t.Errorf("attrs %v", a)
		}
	})

	t.Run("Check fails open on detector panics and returns only the block error", func(t *testing.T) {
		setupEngine(t, engineSettings{})
		if d, err := Check(ctx, "pg.query", func() *Finding { panic("detector bug") }); d != DecisionNone || err != nil {
			t.Errorf("d=%s err=%v", d, err)
		}
		setupEngine(t, engineSettings{mode: ModeBlock})
		if _, err := Check(ctx, "pg.query", func() *Finding { f := finding; return &f }); !errors.Is(err, ErrBlocked) {
			t.Errorf("err=%v", err)
		}
	})

	t.Run("inactive: findings are dropped", func(t *testing.T) {
		configureEngine(engineSettings{applicationName: "a", getenv: noEnv})
		f := finding
		if d, err := HandleFinding(ctx, &f, "pg.query", FindingExtra{}); d != DecisionNone || err != nil {
			t.Errorf("d=%s err=%v", d, err)
		}
		ran := false
		_, _ = Check(ctx, "pg.query", func() *Finding { ran = true; return nil })
		if ran {
			t.Error("a check ran while RASP is off")
		}
	})
}

// A refresh must publish the state it computed under the same lock: an
// Enable racing a signed killSwitch must not leave RASP active.
func TestRefreshCannotPublishStaleState(t *testing.T) {
	setupEngine(t, engineSettings{})
	Disable()
	done := make(chan struct{})
	testHookRefresh = func() {
		testHookRefresh = nil
		go func() {
			setRemoteConfig(remote(func(r *RemoteConfig) { r.KillSwitch = true }))
			close(done)
		}()
		select {
		case <-done:
		case <-time.After(100 * time.Millisecond):
		}
	}
	t.Cleanup(func() { testHookRefresh = nil })
	Enable()
	<-done
	if Active() {
		t.Error("a stale Enable refresh overwrote the signed kill switch")
	}
}
