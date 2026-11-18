package rasp

import (
	"context"
	"net/http"
	"net/url"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
)

// Security baseline (README "Security baseline"): a one-time look, when RASP
// starts, at how the running process is set up, reported as baseline events
// (monitor only, never blocks). Each rule reads a flag, a version or an id,
// never a secret value, and reports only that a setting is risky. Adapted
// from the idea of OpenRASP's start-up security policy checks.
//
// The rules Go has: baseline.tls_verify_off (InsecureSkipVerify on
// http.DefaultTransport), baseline.inspector_in_production (net/http/pprof
// on http.DefaultServeMux in production), baseline.development_mode_in_production
// (GIN_MODE=debug under a production environment), baseline.running_as_root,
// baseline.config_key_unpinned and baseline.runtime_end_of_life.

// BaselineSink is the sink name of baseline events.
const BaselineSink = "startup"

// goEndOfLife is the last day each Go release line got security fixes: a
// line is supported until the second newer line is released. Lines older
// than the table have ended; lines newer than it are not judged until a
// date is added. Go 1.26 ends the day before Go 1.28 ships (expected
// February 2027); its date is added once that release date is known.
var goEndOfLife = map[int]string{
	18: "2023-01-31",
	19: "2023-08-07",
	20: "2024-02-05",
	21: "2024-08-12",
	22: "2025-02-10",
	23: "2025-08-11",
	24: "2026-02-09",
	25: "2026-08-18", // Go 1.27 shipped 2026-08-19
}

// goOldestListed is the oldest line in goEndOfLife.
const goOldestListed = 18

// baselineInput is what the baseline rules read. Pure data, so each rule can
// be tested on its own.
type baselineInput struct {
	getenv func(string) string
	// environment is the SDK's deployment environment.
	environment string
	// remoteWanted: a signed config was expected (URL and API key set,
	// remote on).
	remoteWanted bool
	// pinned: a config public key is pinned.
	pinned bool
	// goVersion is runtime.Version() of the binary.
	goVersion string
	// uid is the effective POSIX user id, -1 where there is none (Windows).
	uid int
	// pprofOnDefaultMux: net/http/pprof's handlers are on http.DefaultServeMux.
	pprofOnDefaultMux bool
	// defaultTLSInsecure: http.DefaultTransport skips certificate checks.
	defaultTLSInsecure bool
	now                time.Time
}

// productionEnv reports whether NODE_ENV, ENVIRONMENT,
// ASPNETCORE_ENVIRONMENT or the SDK's environment says production (the same
// variables TofuAllowed reads).
func productionEnv(environment string, getenv func(string) string) bool {
	for _, v := range []string{getenv("NODE_ENV"), getenv("ENVIRONMENT"), getenv("ASPNETCORE_ENVIRONMENT"), environment} {
		if isProduction(v) {
			return true
		}
	}
	return false
}

// goMinor returns the minor version of a "go1.N[.P]" runtime version, or -1
// (development builds, anything unparsed).
func goMinor(v string) int {
	rest, ok := strings.CutPrefix(v, "go1.")
	if !ok {
		return -1
	}
	if i := strings.IndexFunc(rest, func(r rune) bool { return r < '0' || r > '9' }); i >= 0 {
		rest = rest[:i]
	}
	n, err := strconv.Atoi(rest)
	if err != nil {
		return -1
	}
	return n
}

// baselineFindings returns the baseline rules that fire, in a fixed order.
// Pure.
func baselineFindings(i baselineInput) []Finding {
	getenv := i.getenv
	if getenv == nil {
		getenv = func(string) string { return "" }
	}
	var out []Finding
	hit := func(rule string) { out = append(out, Finding{Attack: Baseline, Rule: rule}) }
	production := productionEnv(i.environment, getenv)

	// Certificate checks switched off for every client that uses the default
	// transport (http.Get, http.DefaultClient, clients without a Transport).
	if i.defaultTLSInsecure {
		hit("baseline.tls_verify_off")
	}
	// Profiling handlers on the default mux in production expose memory,
	// goroutine stacks and the command line to anyone who reaches them.
	if production && i.pprofOnDefaultMux {
		hit("baseline.inspector_in_production")
	}
	// The SDK says production while the framework runs in debug mode.
	env := i.environment
	if env == "" {
		env = getenv("ENVIRONMENT")
	}
	if isProduction(env) && strings.ToLower(strings.TrimSpace(getenv("GIN_MODE"))) == "debug" {
		hit("baseline.development_mode_in_production")
	}
	if i.uid == 0 {
		hit("baseline.running_as_root")
	}
	// In production the signed config must be verified against a pinned key.
	if production && i.remoteWanted && !i.pinned {
		hit("baseline.config_key_unpinned")
	}
	if minor := goMinor(i.goVersion); minor >= 0 {
		eol, listed := goEndOfLife[minor]
		if !listed && minor < goOldestListed {
			eol, listed = "1970-01-01", true
		}
		if listed && i.now.UTC().Format("2006-01-02") > eol {
			hit("baseline.runtime_end_of_life")
		}
	}
	return out
}

// pprofRegistered reports whether mux routes /debug/pprof/ to a handler of
// its own (net/http/pprof registers there on import). Never panics.
func pprofRegistered(mux *http.ServeMux) (on bool) {
	defer func() {
		if recover() != nil {
			on = false
		}
	}()
	if mux == nil {
		return false
	}
	r := &http.Request{Method: http.MethodGet, URL: &url.URL{Path: "/debug/pprof/"}, Header: http.Header{}}
	_, pattern := mux.Handler(r)
	return strings.Contains(pattern, "/debug/pprof/")
}

// defaultTransportInsecure reports whether http.DefaultTransport skips
// certificate verification. Never panics.
func defaultTransportInsecure() (insecure bool) {
	defer func() {
		if recover() != nil {
			insecure = false
		}
	}()
	t, ok := http.DefaultTransport.(*http.Transport)
	return ok && t != nil && t.TLSClientConfig != nil && t.TLSClientConfig.InsecureSkipVerify
}

var baselineRan atomic.Bool

// runBaseline reports the baseline findings once per process. Never panics;
// a no-op while RASP is not active.
func runBaseline(i baselineInput) {
	if !baselineRan.CompareAndSwap(false, true) {
		return
	}
	defer func() { _ = recover() }() // fail open
	for _, f := range baselineFindings(i) {
		_, _ = Check(context.Background(), BaselineSink, func() *Finding { return &f })
	}
}

// startBaseline runs the baseline off the caller's goroutine. The globals
// http.DefaultTransport and http.DefaultServeMux are read here, at Init:
// reading them later from another goroutine would race with an app that
// replaces them after Init. Everything else (the mux's routes, behind its
// own lock, the user id, the version) is read in the background.
func startBaseline(environment string, getenv func(string) string, remoteWanted, pinned bool) {
	if baselineRan.Load() {
		return
	}
	insecure := defaultTransportInsecure()
	// The global is read here too; the background goroutine only uses the
	// mux, behind its own lock.
	mux := http.DefaultServeMux
	go func() {
		defer func() { _ = recover() }()
		runBaseline(baselineInput{
			getenv:             getenv,
			environment:        environment,
			remoteWanted:       remoteWanted,
			pinned:             pinned,
			goVersion:          runtime.Version(),
			uid:                os.Geteuid(),
			pprofOnDefaultMux:  pprofRegistered(mux),
			defaultTLSInsecure: insecure,
			now:                time.Now(),
		})
	}()
}

// resetBaseline lets the baseline run again (tests only).
func resetBaseline() { baselineRan.Store(false) }
