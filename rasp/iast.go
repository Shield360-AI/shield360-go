package rasp

import (
	"container/list"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"math"
	"math/rand/v2"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Passive IAST (README "Passive IAST"): while RASP checks its sinks during
// normal traffic, report the places where a request input reaches a sink
// verbatim and unparameterized, even when the value is harmless and no
// attack happened, so developers can fix "route X builds SQL from query.id"
// before anyone attacks it.
//
// Off by default; turned on by the signed config (iast: "on"),
// Options.Iast or SHIELD360_IAST=on. Never blocks and does not depend on the
// attack modes. It adds work only to sink checks that already run with
// request input in scope, and only for sampled checks.
//
// Each vulnerability has a fingerprint (route, sink, input key, rule) and is
// reported at most once per process per hour, with how many times it was
// seen since the last report. Events name locations, never values, and carry
// no snippet: the code location (the app's own stack frame, read once per
// fingerprint) replaces it.

// Passive IAST constants.
const (
	VulnerabilityName         = "shield360.rasp.vulnerability"
	IastReportEvery           = time.Hour
	IastMaxFingerprints       = 10_000
	IastDefaultRate           = 1.0
	IastDefaultRateProduction = 0.1
)

type iastSeen struct {
	lastSent time.Time
	sent     bool
	pending  int
	location string
	elem     *list.Element
}

type iastConfig struct {
	env        string // "on", "off" or ""
	envRate    *float64
	local      bool
	localRate  *float64
	remote     string
	remoteRate *float64
	version    string
	production bool
	app        string
	now        func() time.Time
	random     func() float64
}

var (
	iastMu sync.Mutex
	iastSt = iastConfig{version: "local", app: "default", now: time.Now, random: rand.Float64}
	// iastSeenMap and iastOrder remember fingerprints, oldest first.
	iastSeenMap = map[string]*iastSeen{}
	iastOrder   = list.New()
	// iastOn mirrors iastEnabled for the hot path.
	iastOn atomic.Bool
)

func asIastSetting(v string) string {
	switch s := strings.ToLower(strings.TrimSpace(v)); s {
	case "on", "off":
		return s
	}
	return ""
}

func asRate(v float64) *float64 {
	if math.IsNaN(v) || math.IsInf(v, 0) || v < 0 || v > 1 {
		return nil
	}
	return &v
}

func envRate(s string) *float64 {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil
	}
	f, err := strconv.ParseFloat(s, 64)
	if err != nil {
		return nil
	}
	return asRate(f)
}

type iastSettings struct {
	enabled         bool
	sampleRate      float64 // 0: the default
	applicationName string
	environment     string
	getenv          func(string) string
	now             func() time.Time
	random          func() float64
}

// configureIast reads the local option and the environment
// (SHIELD360_IAST, SHIELD360_IAST_SAMPLE_RATE) and forgets what was seen.
func configureIast(s iastSettings) {
	getenv := s.getenv
	if getenv == nil {
		getenv = os.Getenv
	}
	c := iastConfig{
		env:        asIastSetting(getenv("SHIELD360_IAST")),
		envRate:    envRate(getenv("SHIELD360_IAST_SAMPLE_RATE")),
		local:      s.enabled,
		version:    "local",
		production: productionEnv(s.environment, getenv),
		app:        s.applicationName,
		now:        s.now,
		random:     s.random,
	}
	if s.sampleRate != 0 {
		c.localRate = asRate(s.sampleRate)
	}
	if c.app == "" {
		c.app = "default"
	}
	if c.now == nil {
		c.now = time.Now
	}
	if c.random == nil {
		c.random = rand.Float64
	}
	iastMu.Lock()
	iastSt = c
	iastSeenMap = map[string]*iastSeen{}
	iastOrder = list.New()
	iastOn.Store(iastEnabledLocked())
	iastMu.Unlock()
}

// setIastRemote applies the verified signed config's switch and rate (nil
// drops them).
func setIastRemote(c *Claims) {
	iastMu.Lock()
	defer iastMu.Unlock()
	iastSt.remote, iastSt.remoteRate, iastSt.version = "", nil, "local"
	if c != nil {
		iastSt.remote = asIastSetting(c.Iast)
		if c.IastSampleRate != nil {
			iastSt.remoteRate = asRate(*c.IastSampleRate)
		}
		if c.Version != "" {
			iastSt.version = c.Version
		}
	}
	iastOn.Store(iastEnabledLocked())
}

func iastEnabledLocked() bool {
	if iastSt.env == "off" {
		return false
	}
	if iastSt.remote != "" {
		return iastSt.remote == "on"
	}
	return iastSt.local || iastSt.env == "on"
}

// IastEnabled reports whether passive IAST is on. Order: SHIELD360_IAST=off
// wins; then the signed config's iast; then Options.Iast or
// SHIELD360_IAST=on. RASP must also be active for it to run.
func IastEnabled() bool { return iastOn.Load() }

func iastSampleRateLocked() float64 {
	for _, r := range []*float64{iastSt.envRate, iastSt.remoteRate, iastSt.localRate} {
		if r != nil {
			return *r
		}
	}
	if iastSt.production {
		return IastDefaultRateProduction
	}
	return IastDefaultRate
}

// IastSampleRate is the share of checks that run the IAST rules: the env,
// then the signed config, then Options.IastSampleRate, then 1.0 (0.1 in
// production).
func IastSampleRate() float64 {
	iastMu.Lock()
	defer iastMu.Unlock()
	return iastSampleRateLocked()
}

// beginIast arms a slot for one check, or returns nil: off, not sampled, or
// no request input in scope. Check calls it only while RASP is active.
func beginIast(ctx context.Context) (slot *iastSlot) {
	if !iastOn.Load() {
		return nil
	}
	defer func() {
		if recover() != nil {
			slot = nil
		}
	}()
	rc := FromContext(ctx)
	if rc == nil || len(rc.Inputs()) == 0 {
		return nil
	}
	iastMu.Lock()
	rate := iastSampleRateLocked()
	random := iastSt.random
	iastMu.Unlock()
	if rate <= 0 || (rate < 1 && random() >= rate) {
		return nil
	}
	return &iastSlot{}
}

// endIast reports the vulnerability a slot noted, if any. Check calls it
// only when the check found no attack. Never panics.
func endIast(ctx context.Context, slot *iastSlot, sink string, extra FindingExtra) {
	if slot == nil || slot.vuln == nil {
		return
	}
	defer func() { _ = recover() }()
	reportVulnerability(ctx, slot.vuln, sink, extra)
}

var iastSinkRe = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*(?:[.:/][A-Za-z0-9_]+)*$`)

// VulnFingerprint is the first 32 hex characters of SHA-256 over route,
// sink, input key and rule joined by NUL.
func VulnFingerprint(route, sink, inputKey, rule string) string {
	sum := sha256.Sum256([]byte(strings.Join([]string{route, sink, inputKey, rule}, "\x00")))
	return hex.EncodeToString(sum[:])[:32]
}

func reportVulnerability(ctx context.Context, v *vuln, sink string, extra FindingExtra) {
	if len(sink) > 64 || !iastSinkRe.MatchString(sink) {
		return
	}
	rc := FromContext(ctx)
	p := firstNonEmpty(extra.Path, rc.Path())
	route := firstNonEmpty(extra.Route, rc.Route())
	if route == "" && p != "" {
		route = IastRouteOf(p)
	}
	route = safeRoute(route)
	inputKey := safeKey(v.input.Key)
	if inputKey == "" {
		return
	}
	fp := VulnFingerprint(route, sink, inputKey, v.rule)

	stateMu.RLock()
	es := state.sink
	stateMu.RUnlock()

	iastMu.Lock()
	defer iastMu.Unlock()
	now := iastSt.now()
	seen := iastSeenMap[fp]
	if seen != nil && seen.sent && now.Sub(seen.lastSent) < IastReportEvery {
		seen.pending++
		return
	}
	if seen == nil {
		// First sight in this process: the one time the stack is read.
		seen = &iastSeen{location: codeLocation()}
		if len(iastSeenMap) >= IastMaxFingerprints {
			if oldest := iastOrder.Front(); oldest != nil {
				delete(iastSeenMap, oldest.Value.(string))
				iastOrder.Remove(oldest)
			}
		}
		seen.elem = iastOrder.PushBack(fp)
		iastSeenMap[fp] = seen
	}
	attrs := map[string]string{
		"shield360.rasp.kind":             "vulnerability",
		"shield360.rasp.event_id":         newEventID(),
		"shield360.rasp.app":              iastSt.app,
		"shield360.rasp.rule":             v.rule,
		"shield360.rasp.sink":             sink,
		"shield360.rasp.source":           string(SourceRequest),
		"shield360.rasp.input_key":        inputKey,
		"shield360.rasp.config_version":   iastSt.version,
		"shield360.rasp.language":         Runtime,
		"shield360.rasp.vuln.fingerprint": fp,
		"shield360.rasp.vuln.position":    v.position,
		"shield360.rasp.count":            strconv.Itoa(seen.pending + 1),
	}
	opt := func(k, val string) {
		if val != "" {
			attrs[k] = val
		}
	}
	opt("shield360.rasp.route", route)
	opt("shield360.rasp.method", safeMethod(firstNonEmpty(extra.Method, rc.Method())))
	opt("shield360.rasp.framework", firstNonEmpty(extra.Framework, rc.Framework()))
	opt("shield360.rasp.vuln.location", seen.location)
	// Refused (rate limit, full queue) or nowhere to send: count it, and try
	// again at the next sighting. No fold key: IAST dedupes and counts its
	// own sightings, so a refused report must leave nothing in the reporter
	// that could be sent later behind its back.
	e := Event{Name: VulnerabilityName, Time: now.UTC().Format("2006-01-02T15:04:05.000Z"), Attrs: attrs}
	if es == nil || !es.add(e, "") {
		seen.pending++
		return
	}
	seen.lastSent, seen.sent, seen.pending = now, true, 0
}

// resetIast forgets every fingerprint seen and the configuration (tests).
func resetIast() {
	configureIast(iastSettings{})
}

// IastRouteOf is the route of a request whose router gave no template, for
// passive IAST: the event route (EventRouteOf), so a token, name or other
// value in the path never reaches a finding, which is kept as long as the
// finding.
func IastRouteOf(p string) string { return EventRouteOf(p) }

// sdkPackage is the function-name prefix of this module's packages: frames
// there are the SDK's, except its tests.
const sdkPackage = "github.com/Shield360-AI/shield360-go"

// stdRoot is the standard library's source directory as frames report it
// (GOROOT/src/), found from a standard library function's file.
var stdRoot = func() string {
	f := runtime.FuncForPC(reflect.ValueOf(strings.Index).Pointer())
	if f == nil {
		return ""
	}
	file, _ := f.FileLine(f.Entry())
	file = filepath.ToSlash(file)
	if i := strings.LastIndex(file, "/strings/"); i > 0 {
		return file[:i+1]
	}
	return ""
}()

// isAppFrame reports whether a stack frame is the app's own code: not the
// SDK (its tests are app code), not the standard library or the runtime, not
// a dependency in the module cache or vendor directory.
func isAppFrame(function, file string) bool {
	file = filepath.ToSlash(file)
	if file == "" || strings.HasPrefix(function, "runtime.") {
		return false
	}
	if strings.HasPrefix(function, sdkPackage+"/") || strings.HasPrefix(function, sdkPackage+".") {
		if !strings.HasSuffix(file, "_test.go") {
			return false
		}
	}
	if strings.Contains(file, "/pkg/mod/") || strings.Contains(file, "/vendor/") {
		return false
	}
	if stdRoot != "" {
		if strings.HasPrefix(file, stdRoot) {
			return false
		}
	} else if isStdFunction(function) {
		// Without a known GOROOT (trimmed paths), by the import path.
		return false
	}
	// A module path with a version (trimmed module cache paths).
	if strings.Contains(file, "@v") {
		return false
	}
	return true
}

// isStdFunction reports whether a function's import path is the standard
// library's: its first element has no dot, and it is not main.
func isStdFunction(fn string) bool {
	slash := strings.LastIndexByte(fn, '/')
	path := fn
	if dot := strings.IndexByte(fn[slash+1:], '.'); dot >= 0 {
		path = fn[:slash+1+dot]
	}
	first, _, _ := strings.Cut(path, "/")
	return path != "main" && !strings.Contains(first, ".")
}

var locationChars = regexp.MustCompile(`[^A-Za-z0-9_./@+~-]`)

// codeLocation returns the top stack frame in the app's own code as
// path:line, the path relative to the working directory (only the last three
// segments when outside it), or "" when there is none.
func codeLocation() string {
	pcs := make([]uintptr, 64)
	n := runtime.Callers(2, pcs)
	frames := runtime.CallersFrames(pcs[:n])
	for {
		f, more := frames.Next()
		if isAppFrame(f.Function, f.File) {
			return formatLocation(f.File, f.Line)
		}
		if !more {
			return ""
		}
	}
}

func formatLocation(file string, line int) string {
	shown := ""
	if wd, err := os.Getwd(); err == nil {
		if rel, err := filepath.Rel(wd, file); err == nil && rel != "." && !strings.HasPrefix(rel, "..") && !filepath.IsAbs(rel) {
			shown = rel
		}
	}
	if shown == "" {
		segs := strings.FieldsFunc(filepath.ToSlash(file), func(r rune) bool { return r == '/' })
		if len(segs) > 3 {
			segs = segs[len(segs)-3:]
		}
		shown = strings.Join(segs, "/")
	}
	shown = locationChars.ReplaceAllString(filepath.ToSlash(shown), "_")
	return truncChars(shown, 240) + ":" + strconv.Itoa(line)
}
