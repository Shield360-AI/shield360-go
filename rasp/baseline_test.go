package rasp

import (
	"net/http"
	"reflect"
	"strings"
	"testing"
	"time"
)

// Security baseline: each rule from what it reads (pure), nothing for a
// sound set-up, monitor only even in block mode, once per process, and no
// setting's value in an event.

func soundBaseline() baselineInput {
	return baselineInput{
		getenv:       envOf("ENVIRONMENT", "production"),
		environment:  "production",
		remoteWanted: true,
		pinned:       true,
		goVersion:    "go1.26.10",
		uid:          1000,
		now:          time.Date(2026, 10, 29, 0, 0, 0, 0, time.UTC),
	}
}

func baselineRules(i baselineInput) []string {
	var out []string
	for _, f := range baselineFindings(i) {
		if f.Attack != Baseline || f.Input != nil {
			panic("baseline finding shape")
		}
		out = append(out, f.Rule)
	}
	return out
}

func TestBaselineFindings(t *testing.T) {
	if got := baselineRules(soundBaseline()); len(got) != 0 {
		t.Fatalf("sound set-up: %v", got)
	}

	cases := []struct {
		label string
		over  func(*baselineInput)
		rule  string
	}{
		{"TLS checks off on the default transport", func(i *baselineInput) { i.defaultTLSInsecure = true }, "baseline.tls_verify_off"},
		{"pprof on the default mux in production", func(i *baselineInput) { i.pprofOnDefaultMux = true }, "baseline.inspector_in_production"},
		{"gin debug mode under a production environment", func(i *baselineInput) { i.getenv = envOf("GIN_MODE", "debug") }, "baseline.development_mode_in_production"},
		{"running as root", func(i *baselineInput) { i.uid = 0 }, "baseline.running_as_root"},
		{"an unpinned config key in production", func(i *baselineInput) { i.pinned = false }, "baseline.config_key_unpinned"},
		{"an end-of-life Go line", func(i *baselineInput) { i.goVersion = "go1.22.12" }, "baseline.runtime_end_of_life"},
		{"a Go line older than the table", func(i *baselineInput) { i.goVersion = "go1.16.15" }, "baseline.runtime_end_of_life"},
	}
	for _, c := range cases {
		t.Run(c.label, func(t *testing.T) {
			in := soundBaseline()
			c.over(&in)
			if got := baselineRules(in); !reflect.DeepEqual(got, []string{c.rule}) {
				t.Errorf("rules %v, want [%s]", got, c.rule)
			}
		})
	}

	t.Run("leaves development set-ups alone where the rule is about production", func(t *testing.T) {
		in := soundBaseline()
		in.getenv = envOf("ENVIRONMENT", "development", "GIN_MODE", "debug")
		in.environment = "development"
		in.pprofOnDefaultMux = true
		in.pinned = false
		if got := baselineRules(in); len(got) != 0 {
			t.Errorf("rules %v", got)
		}
	})

	t.Run("a release line still in support passes; one past its date does not", func(t *testing.T) {
		in := soundBaseline()
		in.goVersion = "go1.24.5"
		in.now = time.Date(2026, 2, 9, 12, 0, 0, 0, time.UTC)
		if got := baselineRules(in); len(got) != 0 {
			t.Errorf("on the last day: %v", got)
		}
		in.now = time.Date(2026, 2, 10, 0, 0, 0, 0, time.UTC)
		if got := baselineRules(in); !reflect.DeepEqual(got, []string{"baseline.runtime_end_of_life"}) {
			t.Errorf("the day after: %v", got)
		}
		in.goVersion = "go1.25.11"
		in.now = time.Date(2026, 8, 18, 12, 0, 0, 0, time.UTC)
		if got := baselineRules(in); len(got) != 0 {
			t.Errorf("go1.25 on the last day: %v", got)
		}
		in.now = time.Date(2026, 8, 19, 0, 0, 0, 0, time.UTC)
		if got := baselineRules(in); !reflect.DeepEqual(got, []string{"baseline.runtime_end_of_life"}) {
			t.Errorf("go1.25 the day after: %v", got)
		}
	})

	t.Run("lines newer than the table and development builds are not judged", func(t *testing.T) {
		for _, v := range []string{"go1.26.3", "go1.27.0", "devel go1.28-abcdef", ""} {
			in := soundBaseline()
			in.goVersion = v
			if got := baselineRules(in); len(got) != 0 {
				t.Errorf("%q: %v", v, got)
			}
		}
	})

	t.Run("reads production from NODE_ENV, ENVIRONMENT, ASPNETCORE_ENVIRONMENT or the SDK option", func(t *testing.T) {
		yes := []bool{
			productionEnv("", envOf("NODE_ENV", "production")),
			productionEnv("", envOf("ENVIRONMENT", "Prod")),
			productionEnv("", envOf("ASPNETCORE_ENVIRONMENT", "Production")),
			productionEnv("production", noEnv),
		}
		for i, v := range yes {
			if !v {
				t.Errorf("case %d not production", i)
			}
		}
		if productionEnv("qa", envOf("NODE_ENV", "staging")) {
			t.Error("staging is production")
		}
	})

	if goMinor("go1.26.10") != 26 || goMinor("go1.21") != 21 || goMinor("go1.23rc1") != 23 || goMinor("devel") != -1 {
		t.Error("goMinor")
	}
}

func TestBaselineProbes(t *testing.T) {
	mux := http.NewServeMux()
	if pprofRegistered(mux) {
		t.Error("empty mux reports pprof")
	}
	mux.HandleFunc("/", func(http.ResponseWriter, *http.Request) {})
	if pprofRegistered(mux) {
		t.Error("a catch-all route reports pprof")
	}
	mux.HandleFunc("/debug/pprof/", func(http.ResponseWriter, *http.Request) {})
	if !pprofRegistered(mux) {
		t.Error("pprof handler not seen")
	}
	if pprofRegistered(nil) {
		t.Error("nil mux")
	}
	// The test binary does not import net/http/pprof or change the default
	// transport.
	if pprofRegistered(http.DefaultServeMux) || defaultTransportInsecure() {
		t.Error("default mux or transport misread")
	}
}

func TestRunBaseline(t *testing.T) {
	t.Run("reports each finding once per process, monitored even in block mode, without the setting values", func(t *testing.T) {
		log := setupEngine(t, engineSettings{mode: ModeBlock})
		resetBaseline()
		t.Cleanup(resetBaseline)
		in := soundBaseline()
		in.getenv = envOf("ENVIRONMENT", "production", "GIN_MODE", "debug")
		in.defaultTLSInsecure = true
		in.pinned = false
		runBaseline(in)
		runBaseline(in)
		var got []string
		for _, e := range log.all() {
			a := e.Attrs
			got = append(got, a["shield360.rasp.rule"])
			if a["shield360.rasp.attack"] != "baseline" || a["shield360.rasp.decision"] != "monitored" || a["shield360.rasp.sink"] != "startup" {
				t.Errorf("attrs %v", a)
			}
			if _, ok := a["shield360.rasp.input_key"]; ok {
				t.Errorf("input key in %v", a)
			}
			for _, v := range a {
				if strings.Contains(v, "debug") {
					t.Errorf("setting value in %v", a)
				}
			}
		}
		want := []string{"baseline.tls_verify_off", "baseline.development_mode_in_production", "baseline.config_key_unpinned"}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("rules %v, want %v", got, want)
		}
	})

	t.Run("block is capped at monitor for baseline", func(t *testing.T) {
		setupEngine(t, engineSettings{mode: ModeBlock, attacks: map[AttackType]Mode{Baseline: ModeBlock}})
		if m := ModeFor(Baseline); m != ModeMonitor {
			t.Errorf("mode %s", m)
		}
	})

	t.Run("does nothing while RASP is off", func(t *testing.T) {
		log := setupEngine(t, engineSettings{})
		Disable()
		t.Cleanup(Enable)
		resetBaseline()
		t.Cleanup(resetBaseline)
		in := soundBaseline()
		in.uid = 0
		runBaseline(in)
		if n := len(log.all()); n != 0 {
			t.Errorf("events %d", n)
		}
	})

	t.Run("startBaseline runs off the caller's goroutine and reports", func(t *testing.T) {
		log := setupEngine(t, engineSettings{})
		resetBaseline()
		t.Cleanup(resetBaseline)
		// Production with no pinned key: config_key_unpinned, whatever the
		// machine running the test looks like.
		startBaseline("production", noEnv, true, false)
		deadline := time.Now().Add(5 * time.Second)
		for {
			found := false
			for _, e := range log.all() {
				found = found || e.Attrs["shield360.rasp.rule"] == "baseline.config_key_unpinned"
			}
			if found {
				break
			}
			if time.Now().After(deadline) {
				t.Fatal("no baseline event")
			}
			time.Sleep(10 * time.Millisecond)
		}
		startBaseline("production", noEnv, true, false) // once per process
	})
}

func TestStartBaselineSnapshotsDefaultMux(t *testing.T) {
	log := setupEngine(t, engineSettings{})
	resetBaseline()
	t.Cleanup(resetBaseline)
	orig := http.DefaultServeMux
	startBaseline("production", noEnv, true, false)
	// An app replacing the global after Init must not race with the
	// background goroutine (go test -race).
	http.DefaultServeMux = http.NewServeMux()
	deadline := time.Now().Add(5 * time.Second)
	for len(log.all()) == 0 {
		if time.Now().After(deadline) {
			t.Fatal("no baseline event")
		}
		time.Sleep(10 * time.Millisecond)
	}
	http.DefaultServeMux = orig
}
