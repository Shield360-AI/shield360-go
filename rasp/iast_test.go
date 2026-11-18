package rasp

import (
	"context"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// Passive IAST (README "Passive IAST"): the shared conformance corpus
// (testdata/iast.json), the thresholds, and how the engine arms, samples,
// dedupes and reports vulnerabilities without ever blocking.

// runIastCase runs one corpus case through the detectors with a slot armed;
// it returns the attack finding and the vulnerability noted.
func runIastCase(t *testing.T, c map[string]any) (*Finding, *vuln) {
	t.Helper()
	inputs := normalise(c["inputs"])
	slot := &iastSlot{}
	var f *Finding
	switch str(c, "check") {
	case "sql":
		f = detectSQLWith(str(c, "query"), inputs, SQLDialect(str(c, "dialect")), slot)
	case "command":
		if cmd, ok := c["command"].(string); ok {
			f = detectShellLine(cmd, inputs, true, nil, slot)
		} else {
			f = detectArgv(strList(c["argv"]), inputs, true, nil, slot)
		}
	case "path":
		f = detectPathWith(str(c, "path"), FileOp(str(c, "op")), inputs, strList(c["fileRoots"]), true, slot)
	case "ssrf":
		f = detectSSRFWith(str(c, "url"), inputs, strList(c["resolved"]), slot)
	case "code":
		f = detectCodeWith(str(c, "code"), inputs, slot)
	case "include":
		// Go has no include sink (no runtime module loading beyond
		// plugin.Open), so there is no code.include check; the rule runs on
		// its own.
		slot.note(func() *vuln { return vulnInclude(str(c, "specifier"), inputs) })
	case "deser":
		f = detectDeserializationWith(DeserFormat(str(c, "format")), str(c, "data"), inputs, slot)
	case "xml":
		re, _ := c["resolvesExternal"].(bool)
		f = detectXMLWith(str(c, "xml"), inputs, re, slot)
	default:
		t.Fatalf("unknown check %q", str(c, "check"))
	}
	return f, slot.vuln
}

func TestIastCorpus(t *testing.T) {
	corpus := loadJSON(t, "testdata/iast.json")
	if v, _ := corpus["version"].(float64); v != 1 {
		t.Fatalf("version %v", corpus["version"])
	}
	rules := map[string]bool{}
	n := 0
	for _, x := range asList(corpus["cases"]) {
		c, _ := x.(map[string]any)
		name := str(c, "name")
		exp, _ := c["expect"].(map[string]any)
		f, v := runIastCase(t, c)
		n++
		// Every case is harmless: the attack checks fire nothing.
		if f != nil {
			t.Errorf("%s: attack %s", name, f.Rule)
		}
		rule, _ := exp["rule"].(string)
		if rule == "" {
			if v != nil {
				t.Errorf("%s: got %s, want none", name, v.rule)
			}
			continue
		}
		rules[rule] = true
		if v == nil {
			t.Errorf("%s: got none, want %s", name, rule)
			continue
		}
		if v.rule != rule {
			t.Errorf("%s: rule %s, want %s", name, v.rule, rule)
		}
		if p, ok := exp["position"].(string); ok && v.position != p {
			t.Errorf("%s: position %s, want %s", name, v.position, p)
		}
		if k, ok := exp["input_key"].(string); ok && v.input.Key != k {
			t.Errorf("%s: input key %s, want %s", name, v.input.Key, k)
		}
	}
	got := make([]string, 0, len(rules))
	for r := range rules {
		got = append(got, r)
	}
	sort.Strings(got)
	want := append([]string(nil), VulnRules...)
	sort.Strings(want)
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("corpus rules %v, want %v", got, want)
	}
	fps := 0
	for _, x := range asList(corpus["fingerprints"]) {
		f, _ := x.(map[string]any)
		if got := VulnFingerprint(str(f, "route"), str(f, "sink"), str(f, "input_key"), str(f, "rule")); got != str(f, "fingerprint") {
			t.Errorf("fingerprint %s, want %s", got, str(f, "fingerprint"))
		}
		fps++
	}
	t.Logf("iast.json: %d cases, %d fingerprint vectors", n, fps)
}

func TestIastNotesNothingUnarmed(t *testing.T) {
	inputs := []Input{{Value: "alice@example.com", Key: "query.email", Source: SourceRequest}}
	var slot *iastSlot
	slot.note(func() *vuln { t.Fatal("ran unarmed"); return nil })
	if detectSQLWith("SELECT 1 FROM t WHERE e = 'alice@example.com'", inputs, DialectGeneric, nil) != nil {
		t.Error("finding")
	}
	armed := &iastSlot{}
	armed.note(func() *vuln { panic("boom") })
	if armed.vuln != nil {
		t.Error("panic noted")
	}
}

func TestIastThresholds(t *testing.T) {
	for v, want := range map[string]bool{
		"1": false, "42": false, "100": false, "true": false, "active": false, "desc": false, "aaaaaaaaaa": false, "----": false,
		"1234": true, "created_at": true, "en-GB": true, "alice@example.com": true, "Saint Paul": true, "password": true, "ÜÜ-1": true,
	} {
		if got := iastQualifies(v); got != want {
			t.Errorf("%q: %v", v, got)
		}
	}
}

func TestIastRoute(t *testing.T) {
	for in, want := range map[string]string{
		"/api/v2/reset/AbCdEfGhIjKlMnOpQrSt/confirm": "/api/v2/reset/:id/confirm",
		"/api/orders/48213":                          "/api/orders/:id",
		"/files/report.pdf":                          "/files/report.pdf",
		"/Users/alice":                               "/:id/alice",
		"/":                                          "/",
	} {
		if got := IastRouteOf(in); got != want {
			t.Errorf("%s: %s, want %s", in, got, want)
		}
	}
}

// refusingLog refuses events while refuse is set.
type refusingLog struct {
	eventLog
	mu     sync.Mutex
	refuse bool
}

func (l *refusingLog) add(e Event, k string) bool {
	l.mu.Lock()
	refuse := l.refuse
	l.mu.Unlock()
	if refuse {
		return false
	}
	return l.eventLog.add(e, k)
}

func TestIastInTheEngine(t *testing.T) {
	clock := time.Unix(1_800_000_000, 0)
	var clockMu sync.Mutex
	now := func() time.Time { clockMu.Lock(); defer clockMu.Unlock(); return clock }
	advance := func(d time.Duration) { clockMu.Lock(); clock = clock.Add(d); clockMu.Unlock() }
	email := []Input{{Value: "alice@example.com", Key: "query.email", Source: SourceRequest}}
	const query = "SELECT id FROM orders WHERE customer_email = 'alice@example.com'"
	reqCtx := func(inputs []Input, route, path string) context.Context {
		return withContext(context.Background(), &Context{inputs: inputs, inRequest: true, method: "get", route: route, path: path, framework: Framework})
	}
	runSQL := func(inputs []Input, q string) error {
		ctx := reqCtx(inputs, "/api/orders/:id", "/api/orders/48213")
		return checkSink(ctx, "pg.query", func(slot *iastSlot) *Finding { return detectSQLWith(q, inputs, DialectPostgres, slot) })
	}
	type opts struct {
		iast   bool
		rate   float64
		env    func(string) string
		mode   Mode
		envir  string
		random func() float64
	}
	setup := func(t *testing.T, o opts) *eventLog {
		t.Helper()
		if o.mode == "" {
			o.mode = ModeBlock
		}
		if o.env == nil {
			o.env = noEnv
		}
		log := setupEngine(t, engineSettings{mode: o.mode})
		configureIast(iastSettings{enabled: o.iast, sampleRate: o.rate, applicationName: "orders-api", environment: o.envir, getenv: o.env, now: now, random: o.random})
		t.Cleanup(resetIast)
		return log
	}
	vulns := func(log *eventLog) []Event {
		var out []Event
		for _, e := range log.all() {
			if e.Name == VulnerabilityName {
				out = append(out, e)
			}
		}
		return out
	}

	t.Run("is off by default", func(t *testing.T) {
		log := setup(t, opts{})
		if IastEnabled() || runSQL(email, query) != nil || len(vulns(log)) != 0 {
			t.Error("on")
		}
	})

	t.Run("reports a vulnerability once, with locations and no value, and never blocks", func(t *testing.T) {
		log := setup(t, opts{iast: true, mode: ModeBlock})
		if err := runSQL(email, query); err != nil {
			t.Fatal(err)
		}
		v := vulns(log)
		if len(v) != 1 {
			t.Fatalf("%v", log.all())
		}
		a := v[0].Attrs
		for k, want := range map[string]string{
			"shield360.rasp.kind": "vulnerability", "shield360.rasp.app": "orders-api", "shield360.rasp.rule": "vuln.sql_concat",
			"shield360.rasp.sink": "pg.query", "shield360.rasp.source": "request", "shield360.rasp.input_key": "query.email",
			"shield360.rasp.route": "/api/orders/:id", "shield360.rasp.method": "GET", "shield360.rasp.framework": Framework,
			"shield360.rasp.language": "go", "shield360.rasp.config_version": "local", "shield360.rasp.vuln.position": "string",
			"shield360.rasp.count": "1",
		} {
			if a[k] != want {
				t.Errorf("%s = %q, want %q", k, a[k], want)
			}
		}
		if a["shield360.rasp.vuln.fingerprint"] != VulnFingerprint("/api/orders/:id", "pg.query", "query.email", "vuln.sql_concat") {
			t.Error("fingerprint")
		}
		if !regexp.MustCompile(`^[a-f0-9]{32}$`).MatchString(a["shield360.rasp.event_id"]) {
			t.Error("event id")
		}
		// This test file is the app's code here.
		if !regexp.MustCompile(`^iast_test\.go:\d+$`).MatchString(a["shield360.rasp.vuln.location"]) {
			t.Errorf("location %q", a["shield360.rasp.vuln.location"])
		}
		for _, e := range log.all() {
			for k, val := range e.Attrs {
				if strings.Contains(val, "alice@example.com") {
					t.Errorf("value in %s", k)
				}
			}
		}
		if _, ok := a["shield360.rasp.snippet"]; ok {
			t.Error("snippet")
		}
		if len(log.all()) != 1 {
			t.Error("an attack event too")
		}
	})

	t.Run("reports each fingerprint at most once an hour, with the count seen since", func(t *testing.T) {
		log := setup(t, opts{iast: true})
		for i := 0; i < 3; i++ {
			_ = runSQL(email, query)
		}
		if len(vulns(log)) != 1 {
			t.Fatal(len(vulns(log)))
		}
		advance(IastReportEvery)
		_ = runSQL(email, query)
		v := vulns(log)
		if len(v) != 2 || v[1].Attrs["shield360.rasp.count"] != "3" {
			t.Errorf("%d %v", len(v), v)
		}
	})

	t.Run("reports nothing for an attack (the attack event covers it)", func(t *testing.T) {
		log := setup(t, opts{iast: true, mode: ModeMonitor})
		attack := []Input{{Value: "x' OR '1'='1", Key: "query.q", Source: SourceRequest}}
		_ = runSQL(attack, "SELECT * FROM t WHERE a = 'x' OR '1'='1'")
		if ev := log.all(); len(ev) != 1 || ev[0].Name != EventName {
			t.Errorf("%v", ev)
		}
	})

	t.Run("a blocking attack still blocks with IAST on", func(t *testing.T) {
		setup(t, opts{iast: true, mode: ModeBlock})
		attack := []Input{{Value: "x' OR '1'='1", Key: "query.q", Source: SourceRequest}}
		if AsBlocked(runSQL(attack, "SELECT * FROM t WHERE a = 'x' OR '1'='1'")) == nil {
			t.Error("not blocked")
		}
	})

	t.Run("works whatever the attack mode, even off", func(t *testing.T) {
		log := setupEngine(t, engineSettings{attacks: map[AttackType]Mode{SQLInjection: ModeOff}})
		configureIast(iastSettings{enabled: true, applicationName: "orders-api", getenv: noEnv, now: now})
		t.Cleanup(resetIast)
		_ = runSQL(email, query)
		if len(vulns(log)) != 1 {
			t.Error(log.all())
		}
	})

	t.Run("stands down with the kill switch", func(t *testing.T) {
		log := setup(t, opts{iast: true})
		Disable()
		_ = runSQL(email, query)
		Enable()
		if len(log.all()) != 0 {
			t.Error(log.all())
		}
	})

	t.Run("does nothing without request input in scope", func(t *testing.T) {
		log := setup(t, opts{iast: true})
		_ = checkSink(context.Background(), "pg.query", func(slot *iastSlot) *Finding { return detectSQLWith(query, email, DialectPostgres, slot) })
		_ = checkSink(reqCtx(nil, "/a", "/a"), "pg.query", func(slot *iastSlot) *Finding { return detectSQLWith(query, email, DialectPostgres, slot) })
		if len(log.all()) != 0 {
			t.Error(log.all())
		}
	})

	t.Run("samples checks", func(t *testing.T) {
		log := setup(t, opts{iast: true, rate: 0.5, random: func() float64 { return 0.9 }})
		_ = runSQL(email, query)
		if len(vulns(log)) != 0 {
			t.Error("not sampled out")
		}
		log = setup(t, opts{iast: true, rate: 0.5, random: func() float64 { return 0.1 }})
		_ = runSQL(email, query)
		if len(vulns(log)) != 1 {
			t.Error("sampled out")
		}
	})

	t.Run("defaults to every check, a tenth in production", func(t *testing.T) {
		setup(t, opts{iast: true})
		if IastSampleRate() != 1 {
			t.Error(IastSampleRate())
		}
		setup(t, opts{iast: true, envir: "production"})
		if IastSampleRate() != 0.1 {
			t.Error(IastSampleRate())
		}
		setup(t, opts{iast: true, env: envOf("NODE_ENV", "production", "SHIELD360_IAST_SAMPLE_RATE", "0.5")})
		if IastSampleRate() != 0.5 {
			t.Error(IastSampleRate())
		}
		setup(t, opts{iast: true, env: envOf("SHIELD360_IAST_SAMPLE_RATE", "7")})
		if IastSampleRate() != 1 {
			t.Error(IastSampleRate())
		}
		setup(t, opts{iast: true, rate: 3})
		if IastSampleRate() != 1 {
			t.Error(IastSampleRate())
		}
	})

	t.Run("is switched by the env and the signed config, env off winning", func(t *testing.T) {
		rate := 0.25
		setup(t, opts{env: envOf("SHIELD360_IAST", "on")})
		if !IastEnabled() {
			t.Error("env on")
		}
		setIastRemote(&Claims{Iast: "off", Version: "v2"})
		if IastEnabled() {
			t.Error("signed off")
		}
		log := setup(t, opts{random: func() float64 { return 0.1 }})
		setIastRemote(&Claims{Iast: "on", IastSampleRate: &rate, Version: "v3"})
		if !IastEnabled() || IastSampleRate() != 0.25 {
			t.Error("signed on")
		}
		_ = runSQL(email, query)
		if v := vulns(log); len(v) != 1 || v[0].Attrs["shield360.rasp.config_version"] != "v3" {
			t.Errorf("%v", v)
		}
		setup(t, opts{iast: true, env: envOf("SHIELD360_IAST", "off")})
		setIastRemote(&Claims{Iast: "on", Version: "v4"})
		if IastEnabled() {
			t.Error("env off lost")
		}
		setIastRemote(nil)
		if IastEnabled() {
			t.Error("env off lost")
		}
	})

	t.Run("never exports a secret-looking path segment without a route template", func(t *testing.T) {
		log := setup(t, opts{iast: true})
		ctx := reqCtx(email, "", "/api/v2/reset/AbCdEfGhIjKlMnOpQrSt/confirm")
		_ = checkSink(ctx, "pg.query", func(slot *iastSlot) *Finding { return detectSQLWith(query, email, DialectPostgres, slot) })
		v := vulns(log)
		if len(v) != 1 || v[0].Attrs["shield360.rasp.route"] != "/api/v2/reset/:id/confirm" {
			t.Fatalf("%v", v)
		}
		for _, val := range v[0].Attrs {
			if strings.Contains(val, "AbCdEfGhIjKlMnOpQrSt") {
				t.Error("path segment exported")
			}
		}
	})

	t.Run("retries a report the reporter refused, keeping the count", func(t *testing.T) {
		setup(t, opts{iast: true})
		rl := &refusingLog{refuse: true}
		setEventSink(rl)
		_ = runSQL(email, query)
		if len(rl.all()) != 0 {
			t.Fatal("sent")
		}
		rl.mu.Lock()
		rl.refuse = false
		rl.mu.Unlock()
		advance(61 * time.Second)
		_ = runSQL(email, query)
		if ev := rl.all(); len(ev) != 1 || ev[0].Attrs["shield360.rasp.count"] != "2" {
			t.Errorf("%v", ev)
		}
		_ = runSQL(email, query)
		if len(rl.all()) != 1 {
			t.Error("sent twice in the hour")
		}
	})

	t.Run("forgets the oldest fingerprint past the cap", func(t *testing.T) {
		log := setup(t, opts{iast: true})
		iastMu.Lock()
		for i := 0; i < IastMaxFingerprints; i++ {
			fp := VulnFingerprint("/x", "pg.query", "query.k", strings.Repeat("r", i%5)+string(rune(i)))
			iastSeenMap[fp] = &iastSeen{sent: true, lastSent: now(), elem: iastOrder.PushBack(fp)}
		}
		first := iastOrder.Front().Value.(string)
		iastMu.Unlock()
		_ = runSQL(email, query)
		iastMu.Lock()
		_, kept := iastSeenMap[first]
		size := len(iastSeenMap)
		iastMu.Unlock()
		if kept || size != IastMaxFingerprints || len(vulns(log)) != 1 {
			t.Errorf("kept %v size %d", kept, size)
		}
	})

	t.Run("reaches the real file and exec sinks", func(t *testing.T) {
		log := setup(t, opts{iast: true, mode: ModeMonitor})
		file := []Input{{Value: "invoice-2026-0193", Key: "query.file", Source: SourceRequest}}
		_, _ = ReadFile(reqCtx(file, "/files/:name", "/files/x"), filepath.Join(os.TempDir(), "nonexistent-shield360-iast", "invoice-2026-0193.pdf"))
		author := []Input{{Value: "alice@example.com", Key: "query.author", Source: SourceRequest}}
		_ = CheckCommand(reqCtx(author, "/log", "/log"), []string{"git", "log", "--author", "alice@example.com"})
		got := map[string]string{}
		for _, e := range vulns(log) {
			got[e.Attrs["shield360.rasp.rule"]] = e.Attrs["shield360.rasp.sink"] + " " + e.Attrs["shield360.rasp.input_key"]
		}
		if got["vuln.path_from_input"] != "os.ReadFile query.file" || !strings.HasSuffix(got["vuln.cmd_arg"], " query.author") {
			t.Errorf("%v", got)
		}
	})
}

func TestCodeLocation(t *testing.T) {
	wd, _ := os.Getwd()
	if got := formatLocation(filepath.Join(wd, "routes", "orders.go"), 42); got != "routes/orders.go:42" {
		t.Error(got)
	}
	if got := formatLocation("/opt/other/app/lib/db/run.go", 3); got != "lib/db/run.go:3" {
		t.Error(got)
	}
	if got := formatLocation(filepath.Join(wd, "a b(c).go"), 1); got != "a_b_c_.go:1" {
		t.Error(got)
	}
	for _, f := range [][2]string{
		{"runtime.goexit", "/usr/local/go/src/runtime/asm_arm64.s"},
		{sdkPackage + "/rasp.check", "/src/shield360/sdk/go/rasp/engine.go"},
		{"github.com/lib/pq.(*conn).Query", "/home/me/go/pkg/mod/github.com/lib/pq@v1.10.9/conn.go"},
		{"github.com/x/y.F", "/app/vendor/github.com/x/y/f.go"},
		{"strings.Index", stdRoot + "strings/strings.go"},
	} {
		if isAppFrame(f[0], f[1]) {
			t.Errorf("app frame: %v", f)
		}
	}
	for _, f := range [][2]string{
		{"main.handler", "/app/main.go"},
		{"example.com/shop/routes.getOrder", "/app/routes/orders.go"},
		{sdkPackage + "/rasp.TestX", "/src/shield360/sdk/go/rasp/x_test.go"},
	} {
		if !isAppFrame(f[0], f[1]) {
			t.Errorf("not an app frame: %v", f)
		}
	}
	if !isStdFunction("net/http.(*Server).Serve") || !isStdFunction("strings.Index") || isStdFunction("main.main") || isStdFunction("github.com/a/b.C") {
		t.Error("isStdFunction")
	}
	if stdRoot == "" {
		t.Log("standard library root unknown (trimmed paths)")
	}
}

func TestClaimsCarryCustomRulesAndIast(t *testing.T) {
	c, reason := parseClaims([]byte(`{"v":1,"app":"a","exp":9e9,"version":"v","customRules":[{"id":"r1"}],"iast":"on","iastSampleRate":0.25}`))
	if reason != "" || len(c.CustomRules) != 1 || c.Iast != "on" || c.IastSampleRate == nil || *c.IastSampleRate != 0.25 {
		t.Fatalf("%q %+v", reason, c)
	}
	c, _ = parseClaims([]byte(`{"v":1,"app":"a","exp":9e9,"version":"v","customRules":null,"iast":false,"iastSampleRate":"0.5"}`))
	if c.CustomRules != nil || c.Iast != "off" || c.IastSampleRate == nil || *c.IastSampleRate != 0.5 {
		t.Fatalf("%+v", c)
	}
	c, _ = parseClaims([]byte(`{"v":1,"app":"a","exp":9e9,"version":"v","iastSampleRate":null}`))
	if c.Iast != "" || c.IastSampleRate != nil {
		t.Fatalf("%+v", c)
	}
}

// A report the real reporter refuses (its rate limit) must not leave a fold
// behind that later sends a vulnerability event IAST does not know about:
// vulnerability events are deduplicated by IAST, never folded.
func TestIastRefusedReportIsNotFolded(t *testing.T) {
	clock := time.Unix(1_800_000_000, 0)
	var mu sync.Mutex
	now := func() time.Time { mu.Lock(); defer mu.Unlock(); return clock }
	advance := func(d time.Duration) { mu.Lock(); clock = clock.Add(d); mu.Unlock() }
	setupEngine(t, engineSettings{})
	rep := NewReporter(ReporterOptions{URL: "http://127.0.0.1:1", APIKey: "k", ApplicationName: "orders-api", Now: now})
	setEventSink(rep)
	configureIast(iastSettings{enabled: true, applicationName: "orders-api", getenv: noEnv, now: now})
	t.Cleanup(resetIast)
	// Use up the minute's 100 events.
	for i := 0; i < PerMinute; i++ {
		rep.Add(Event{Name: EventName, Attrs: map[string]string{}}, "filler"+strconv.Itoa(i))
	}
	email := []Input{{Value: "alice@example.com", Key: "query.email", Source: SourceRequest}}
	ctx := withContext(context.Background(), &Context{inputs: email, inRequest: true, method: "GET", route: "/api/orders/:id"})
	run := func() {
		_ = checkSink(ctx, "pg.query", func(slot *iastSlot) *Finding {
			return detectSQLWith("SELECT id FROM orders WHERE customer_email = 'alice@example.com'", email, DialectPostgres, slot)
		})
	}
	run() // refused: the minute is full
	advance(time.Second)
	run()                // refused again (inside the reporter's 10 s fold window)
	advance(time.Minute) // a new minute; any fold has closed
	run()                // sent, with every sighting since
	var vulns []Event
	for _, e := range rep.Pending() {
		if e.Name == VulnerabilityName {
			vulns = append(vulns, e)
		}
	}
	if len(vulns) != 1 || vulns[0].Attrs["shield360.rasp.count"] != "3" {
		for _, e := range vulns {
			t.Logf("count %s", e.Attrs["shield360.rasp.count"])
		}
		t.Fatalf("%d vulnerability events queued, want 1 with count 3", len(vulns))
	}
}
