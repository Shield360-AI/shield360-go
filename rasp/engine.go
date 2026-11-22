package rasp

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"github.com/Shield360-AI/shield360-go/internal/masking"
	"os"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// The engine: the effective mode of each attack type (local options, the
// verified signed config, the kill switch), the decision for a finding, the
// event, and the block error. Detectors are pure; this file is where a
// finding becomes an event or a block.

// RemoteConfig is the part of a verified signed config the engine uses.
type RemoteConfig struct {
	Version    string
	Exp        float64 // seconds; may be fractional
	KillSwitch bool
	Snippets   bool
	// ReportTargets is the signed config's reportTargets; no local option
	// sets it.
	ReportTargets bool
	Mode          Mode // "" when the config sets none
	Attacks       map[AttackType]Mode
	// Allow lists are nil when the config does not set them.
	Allow *RemoteAllow
	// Rules replace the built-in virtual patches when non-nil.
	Rules []VirtualPatchRule
	// CustomRules are the custom rules as sent (README "Custom rules");
	// setRemoteConfig compiles those that apply to this app.
	CustomRules []json.RawMessage
	// Deception is the config's usable deception block (README
	// "Deception"); nil when off.
	Deception *DeceptionConfig
	// Uploads is the parsed upload policy (README "Upload policy and deep
	// scan"); nil when the config has none.
	Uploads *UploadPolicy
	// EdgeKeys are the keys of Edge's context header and the app's verdicts
	// (protection triangle); empty without Edge.
	EdgeKeys []EdgeKey
	// AttackAgents is the signed attackAgents block, read (README "AI attack
	// agents"); nil keeps the local option.
	AttackAgents *AttackAgentConfig
	// deceptionMode is the config's attacks.deception ("" when unset);
	// setRemoteConfig keeps it apart, as the attack list does not hold it.
	deceptionMode Mode
}

// RemoteAllow holds the signed config's allow-lists; a nil list keeps the
// local one.
type RemoteAllow struct {
	Commands      []string
	OutboundHosts []string
	FileRoots     []string
}

// Event is one record sent to /api/guard/events.
type Event struct {
	Name  string            `json:"name"`
	Time  string            `json:"time"`
	Attrs map[string]string `json:"attrs"`
}

// eventSink receives events (the reporter). An empty foldKey never folds.
type eventSink interface {
	add(e Event, foldKey string) bool
}

type localSettings struct {
	mode    Mode
	attacks map[AttackType]Mode
	allow   Allow
	// attackAgents is the local AttackAgents option, read.
	attackAgents AttackAgentConfig
}

type engineState struct {
	enabled bool
	// envOff is SHIELD360_RASP=off, read at configuration.
	envOff bool
	// monitorOnly: no pinned key while a remote config was expected, so
	// block is capped at monitor.
	monitorOnly     bool
	local           localSettings
	remote          *RemoteConfig
	applicationName string
	alwaysAllowed   []string
	sink            eventSink
	// customRules are the signed config's custom rules that apply to this
	// app, compiled.
	customRules []*CustomRule
	// localDeceptionOff: the local options set attacks.deception to off.
	localDeceptionOff bool
}

var (
	stateMu sync.RWMutex
	state   = engineState{local: localSettings{mode: ModeMonitor, attackAgents: DefaultAttackAgents}, applicationName: "default"}
	// active mirrors isActive for the hot path (one atomic load per sink).
	active          atomic.Bool
	runtimeDisabled atomic.Bool
	modelOutputOn   atomic.Bool
)

var modeRank = map[Mode]int{ModeOff: 0, ModeMonitor: 1, ModeBlock: 2}

func asMode(v string) Mode {
	switch Mode(v) {
	case ModeOff, ModeMonitor, ModeBlock:
		return Mode(v)
	}
	return ""
}

// envSetting reads SHIELD360_RASP: monitor, block or off (anything else is
// ignored).
func envSetting(getenv func(string) string) Mode {
	if getenv == nil {
		getenv = os.Getenv
	}
	return asMode(strings.ToLower(strings.TrimSpace(getenv("SHIELD360_RASP"))))
}

func cleanAttacks(in map[AttackType]Mode) map[AttackType]Mode {
	out := map[AttackType]Mode{}
	for _, a := range AttackTypes {
		if m := asMode(string(in[a])); m != "" {
			out[a] = m
		}
	}
	return out
}

func cleanStrings(v []string) []string {
	out := []string{}
	for _, s := range v {
		if s != "" && len(out) < 256 {
			out = append(out, s)
		}
	}
	return out
}

type engineSettings struct {
	enabled         bool
	applicationName string
	mode            Mode
	attacks         map[AttackType]Mode
	allow           Allow
	modelOutput     bool
	monitorOnly     bool
	alwaysAllowed   []string
	getenv          func(string) string
	// attackAgents is the local AttackAgents option (nil: the defaults).
	attackAgents *AttackAgentConfig
}

func configureEngine(s engineSettings) {
	env := envSetting(s.getenv)
	stateMu.Lock()
	state.envOff = env == ModeOff
	state.enabled = s.enabled && !state.envOff
	state.monitorOnly = s.monitorOnly
	state.localDeceptionOff = asMode(string(s.attacks[Deception])) == ModeOff
	state.remote = nil
	state.customRules = nil
	state.applicationName = s.applicationName
	if state.applicationName == "" {
		state.applicationName = "default"
	}
	mode := asMode(string(s.mode))
	if mode == "" {
		mode = ModeMonitor
		if env == ModeBlock || env == ModeMonitor {
			mode = env
		}
	}
	state.local = localSettings{
		mode:    mode,
		attacks: cleanAttacks(s.attacks),
		allow: Allow{
			Commands:      cleanStrings(s.allow.Commands),
			OutboundHosts: cleanStrings(s.allow.OutboundHosts),
			FileRoots:     cleanStrings(s.allow.FileRoots),
		},
		attackAgents: localAttackAgents(s.attackAgents),
	}
	state.alwaysAllowed = append([]string(nil), s.alwaysAllowed...)
	runtimeDisabled.Store(false)
	modelOutputOn.Store(state.enabled && s.modelOutput)
	refreshActiveLocked()
	stateMu.Unlock()
}

// localAttackAgents reads the local option the way the signed block is
// read: a value out of bounds is its default.
func localAttackAgents(a *AttackAgentConfig) AttackAgentConfig {
	if a == nil {
		return DefaultAttackAgents
	}
	raw, err := json.Marshal(a)
	if err != nil {
		return DefaultAttackAgents
	}
	return ParseAttackAgents(raw)
}

func setEventSink(s eventSink) {
	stateMu.Lock()
	state.sink = s
	stateMu.Unlock()
}

// setRemoteConfig applies a verified signed config (nil drops it: local
// options again).
func setRemoteConfig(c *RemoteConfig) {
	var cp *RemoteConfig
	if c != nil {
		v := *c
		v.deceptionMode = asMode(string(c.Attacks[Deception]))
		v.Attacks = cleanAttacks(c.Attacks)
		v.Mode = asMode(string(c.Mode))
		if c.Allow != nil {
			a := RemoteAllow{}
			if c.Allow.Commands != nil {
				a.Commands = cleanStrings(c.Allow.Commands)
			}
			if c.Allow.OutboundHosts != nil {
				a.OutboundHosts = cleanStrings(c.Allow.OutboundHosts)
			}
			if c.Allow.FileRoots != nil {
				a.FileRoots = cleanStrings(c.Allow.FileRoots)
			}
			v.Allow = &a
		}
		if c.Rules != nil {
			rules := []VirtualPatchRule{}
			for _, r := range c.Rules {
				if r.ID != "" && r.Match != nil {
					rules = append(rules, r)
				}
			}
			v.Rules = rules
		}
		cp = &v
	}
	var custom []*CustomRule
	if cp != nil && len(cp.CustomRules) > 0 {
		custom = ParseCustomRules(cp.CustomRules, ApplicationName(), nil)
	}
	stateMu.Lock()
	state.remote = cp
	state.customRules = custom
	refreshActiveLocked()
	stateMu.Unlock()
}

// CustomRules are the custom rules in force (README "Custom rules").
func CustomRules() []*CustomRule {
	stateMu.RLock()
	defer stateMu.RUnlock()
	return state.customRules
}

// testHookRefresh runs between computing and publishing the active flag
// (tests only).
var testHookRefresh func()

// refreshActiveLocked computes and publishes the active flag. The caller
// holds stateMu for writing, so a concurrent refresh can never publish a
// result computed from older state over a newer one.
func refreshActiveLocked() {
	on := state.enabled && !state.envOff && (state.remote == nil || !state.remote.KillSwitch) && !runtimeDisabled.Load()
	if testHookRefresh != nil {
		testHookRefresh()
	}
	active.Store(on)
}

// setRuntimeDisabled flips the runtime switch and republishes under the lock.
func setRuntimeDisabled(off bool) {
	stateMu.Lock()
	defer stateMu.Unlock()
	runtimeDisabled.Store(off)
	refreshActiveLocked()
}

// Active reports whether RASP checks run right now. Kill-switch order: env
// SHIELD360_RASP=off, the signed config's killSwitch, the runtime Disable.
func Active() bool { return active.Load() }

// Enabled reports whether RASP was turned on at Init (whatever the kill
// switches say now).
func Enabled() bool {
	stateMu.RLock()
	defer stateMu.RUnlock()
	return state.enabled
}

// Disable is the runtime kill switch: checks return immediately until
// Enable. The env switch and the signed config's kill switch rank above it.
func Disable() { setRuntimeDisabled(true) }

// Enable undoes Disable. SHIELD360_RASP=off and the signed config's kill
// switch still win.
func Enable() { setRuntimeDisabled(false) }

// ApplicationName is the application name events and the signed config use.
func ApplicationName() string {
	stateMu.RLock()
	defer stateMu.RUnlock()
	return state.applicationName
}

// ModeFor is the effective mode of an attack type: off when RASP is not
// active.
func ModeFor(attack AttackType) Mode {
	if !Active() {
		return ModeOff
	}
	stateMu.RLock()
	defer stateMu.RUnlock()
	return modeForLocked(attack)
}

func modeForLocked(attack AttackType) Mode {
	if state.local.attacks[attack] == ModeOff {
		return ModeOff
	}
	var m Mode
	if r := state.remote; r != nil {
		m = r.Attacks[attack]
		if m == "" {
			m = r.Mode
		}
		if m == "" {
			m = ModeMonitor
		}
	} else {
		m = state.local.attacks[attack]
		if m == "" {
			m = state.local.mode
		}
	}
	if m == ModeBlock && (MonitorOnly(attack) || state.monitorOnly) {
		m = ModeMonitor
	}
	return m
}

// AllowLists are the allow-lists in force: the signed config's, list by
// list, else the local ones.
func AllowLists() Allow {
	stateMu.RLock()
	defer stateMu.RUnlock()
	l := state.local.allow
	r := state.remote
	if r == nil || r.Allow == nil {
		return l
	}
	out := l
	if r.Allow.Commands != nil {
		out.Commands = r.Allow.Commands
	}
	if r.Allow.OutboundHosts != nil {
		out.OutboundHosts = r.Allow.OutboundHosts
	}
	if r.Allow.FileRoots != nil {
		out.FileRoots = r.Allow.FileRoots
	}
	return out
}

// AlwaysAllowedHosts are the hosts of the Shield360 URL and the OTLP
// endpoint, which outbound checks always allow.
func AlwaysAllowedHosts() []string {
	stateMu.RLock()
	defer stateMu.RUnlock()
	return state.alwaysAllowed
}

// VirtualPatches are the rules in force: the signed config's, else the
// built-in list.
func VirtualPatches() []VirtualPatchRule {
	stateMu.RLock()
	defer stateMu.RUnlock()
	if state.remote != nil && state.remote.Rules != nil {
		return state.remote.Rules
	}
	return BuiltInRules
}

// MaskSnippet masks a snippet by the shared contract (sdk/rasp/README.md,
// "Masking") and keeps at most 64 characters.
func MaskSnippet(v string) string {
	return masking.Text(v, 64)
}

// targetRules are the allow-list rules whose events may carry
// shield360.rasp.target (README "Allow-list targets").
var targetRules = map[string]bool{"shell_spawn.shell": true, "outbound.not_allowed": true, "path.outside_root": true}

// MaskTarget masks an allow-list target (README "Masking", "Allow-list
// targets"): the credential rules on the whole target, every '/'-separated
// segment holding '@' replaced by "***", then the strict long-token rule
// piece by piece. Nothing is cut: ok is false when the result is empty,
// holds a control character or is longer than 256 characters.
func MaskTarget(raw string) (string, bool) {
	return masking.Target(raw)
}

// TargetDirectory is the directory path.outside_root reports for a resolved
// path: everything before its last '/', or '/' ("X:/" for a drive) when
// that is empty or a drive letter.
func TargetDirectory(resolved string) string {
	dir := ""
	if i := strings.LastIndexByte(resolved, '/'); i >= 0 {
		dir = resolved[:i]
	}
	if dir == "" {
		return "/"
	}
	if len(dir) == 2 && dir[1] == ':' && (dir[0]|0x20) >= 'a' && (dir[0]|0x20) <= 'z' {
		return dir + "/"
	}
	return dir
}

// addTargetAttrs adds shield360.rasp.target (allow-list rules, only with the
// verified config's reportTargets) and shield360.rasp.sql.dialect (SQL
// findings).
func addTargetAttrs(attrs map[string]string, f *Finding, remote *RemoteConfig) {
	if remote != nil && remote.ReportTargets && targetRules[f.Rule] && f.Target != "" {
		if t, ok := MaskTarget(f.Target); ok {
			attrs["shield360.rasp.target"] = t
		}
	}
	if f.Attack == SQLInjection {
		for _, d := range SQLDialects {
			if f.Dialect == d {
				attrs["shield360.rasp.sql.dialect"] = string(d)
				break
			}
		}
	}
}

// Event attributes must pass the platform's shape checks
// (lib/security/rasp/events.ts).
var (
	unsafeKeyChar   = regexp.MustCompile(`[^A-Za-z0-9_.\-\[\]]`)
	badKeyStart     = regexp.MustCompile(`^[^A-Za-z0-9_]`)
	unsafeRouteChar = regexp.MustCompile(`[^\x21\x23-\x26\x28-\x3b\x3d\x3f-\x5b\x5d-\x7e]`)
	methodRe        = regexp.MustCompile(`^[A-Za-z]{3,10}$`)
	cveRe           = regexp.MustCompile(`^CVE-\d{4}-\d{4,7}$`)
)

func safeKey(k string) string {
	s := unsafeKeyChar.ReplaceAllString(k, "_")
	s = badKeyStart.ReplaceAllString(s, "_")
	return truncChars(s, 128)
}

func safeRoute(r string) string {
	s := truncChars(unsafeRouteChar.ReplaceAllString(r, "_"), 256)
	if strings.HasPrefix(s, "/") {
		return s
	}
	return ""
}

func safeMethod(m string) string {
	if methodRe.MatchString(m) {
		return strings.ToUpper(m)
	}
	return ""
}

// FindingExtra overrides what the event says about the request.
type FindingExtra struct {
	Framework, Route, Method, Path string

	// tightenedByEdge is set by HandleFinding (protection triangle).
	tightenedByEdge bool
	// agent is the client kind and reason of an ai_attack_agent event.
	agent *AttackMark
}

// edgeKeys are the signed config's keys for Edge's context header and the
// app's verdicts (protection triangle); nil without Edge.
func edgeKeys() []EdgeKey {
	stateMu.RLock()
	defer stateMu.RUnlock()
	if state.remote == nil {
		return nil
	}
	return state.remote.EdgeKeys
}

func newEventID() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}

// Strongest returns, of several findings for one call, the one whose
// decision is strongest (block over monitor; an attack type that is off never
// counts), so a finding for a type in monitor or off mode cannot hide another
// that blocks. Ties go to the earlier finding (the contract's order). It
// returns nil when no finding counts.
func Strongest(findings ...*Finding) *Finding {
	var best *Finding
	bestRank := 0
	for _, f := range findings {
		if f == nil {
			continue
		}
		mode := ModeFor(f.Attack)
		if f.Action != "" && modeRank[f.Action] < modeRank[mode] {
			mode = f.Action
		}
		if mode == ModeBlock && f.Attack == XSS {
			mode = ModeMonitor
		}
		if r := modeRank[mode]; r > bestRank {
			best, bestRank = f, r
		}
	}
	return best
}

// HandleFinding applies a finding: reports it and, when the decision is
// blocked, returns the block error. The decision is DecisionNone when the
// attack type is off.
func HandleFinding(ctx context.Context, f *Finding, sink string, extra FindingExtra) (Decision, error) {
	if f == nil {
		return DecisionNone, nil
	}
	if !Active() {
		return DecisionNone, nil
	}
	stateMu.RLock()
	mode := modeForLocked(f.Attack)
	// An upload route's own mode decides instead, capped by a local off, the
	// kill switch (Active above) and no pinned key, like attack modes.
	if f.Mode != "" && state.local.attacks[f.Attack] != ModeOff {
		mode = f.Mode
		if mode == ModeBlock && state.monitorOnly {
			mode = ModeMonitor
		}
	}
	app := state.applicationName
	remote := state.remote
	es := state.sink
	custom := state.customRules
	if len(custom) > 0 && modeForLocked(CustomRuleAttack) == ModeOff {
		custom = nil // mode off skips custom rules: nothing is evaluated
	}
	stateMu.RUnlock()
	// A rule's own action (virtual patches, custom rules) caps the mode.
	if f.Action != "" && modeRank[f.Action] < modeRank[mode] {
		mode = f.Action
	}
	if mode == ModeOff {
		return DecisionNone, nil
	}
	// SHIELD: protection triangle — a client Edge already marked (flagged,
	// deep in a honeypot, high risk) is blocked for injection-class attacks
	// this app only monitors. A rule's own action still caps it.
	rc := FromContext(ctx)
	edge := rc.Edge()
	stateMu.RLock()
	onlyMonitor := state.monitorOnly
	stateMu.RUnlock()
	tightened := mode == ModeMonitor && f.Action == "" && edgeTighten[f.Attack] && EdgeSaysSuspect(edge) && !onlyMonitor
	if tightened {
		mode = ModeBlock
		extra.tightenedByEdge = true
	}
	decision := DecisionMonitored
	if mode == ModeBlock && !MonitorOnly(f.Attack) {
		decision = DecisionBlocked
	}
	// SHIELD: AI attack agents — a finding feeds the client's behavior
	// score; a block's 403 is never an auth failure.
	if rc != nil {
		rc.mu.Lock()
		if f.Attack != AIAttackAgent && f.Attack != Deception && f.Attack != Baseline {
			rc.agentFinding = true
		}
		if decision == DecisionBlocked {
			rc.ownBlock = true
		}
		rc.mu.Unlock()
	}
	eventID := newEventID()
	emitEvent(ctx, f, sink, extra, decision, mode, eventID, app, remote, es)
	sendVerdict(rc, remote, f, decision)
	// Custom rules that look at built-in findings; the first blocking
	// decision wins, the built-in one first.
	var customBlock error
	if f.Attack != CustomRuleAttack && len(custom) > 0 {
		customBlock = runFindingRules(ctx, custom, app, f, sink, extra)
	}
	if decision == DecisionBlocked {
		return decision, &BlockedError{Attack: f.Attack, Rule: f.Rule, EventID: eventID}
	}
	if customBlock != nil {
		return DecisionBlocked, customBlock
	}
	return decision, nil
}

// Check runs a detector at a sink and applies what it finds. It fails open:
// a panic in the detector or the engine is recovered and the call goes
// through. The only error it returns is the block error. This is the entry
// point the sink wrappers use.
func Check(ctx context.Context, sink string, run func() *Finding) (d Decision, err error) {
	return check(ctx, sink, func(*iastSlot) *Finding { return run() })
}

// check is Check with passive IAST: a slot is armed for sampled checks while
// it is on, handed to the detectors, and its vulnerability reported only
// when the check found no attack (an attack event already covers the call).
func check(ctx context.Context, sink string, run func(*iastSlot) *Finding) (d Decision, err error) {
	if !Active() {
		return DecisionNone, nil
	}
	defer func() {
		if r := recover(); r != nil {
			d, err = DecisionNone, nil
		}
	}()
	slot := beginIast(ctx)
	f := run(slot)
	if f == nil {
		endIast(ctx, slot, sink, FindingExtra{})
		return DecisionNone, nil
	}
	return HandleFinding(ctx, f, sink, FindingExtra{})
}

// emitEvent sends a finding's event to the sink. Reporting never breaks the
// call.
// sendVerdict tells Edge about the detection in a signed response header,
// for a request that came through Edge (a verified context): block for a
// blocked attack, flag for a monitored one. Once per request, never panics.
func sendVerdict(rc *Context, remote *RemoteConfig, f *Finding, decision Decision) {
	defer func() { _ = recover() }()
	if rc == nil || remote == nil || len(remote.EdgeKeys) == 0 {
		return
	}
	rc.mu.Lock()
	edge, set, sent := rc.edge, rc.setHeader, rc.verdictSent
	rc.mu.Unlock()
	if edge == nil || set == nil || sent || (f.Attack == CustomRuleAttack && decision != DecisionBlocked) {
		return
	}
	act, ttl := "flag", int64(900)
	if decision == DecisionBlocked {
		act, ttl = "block", 3600
	}
	v := SignEdgeVerdict(remote.EdgeKeys, edge.Rid, act, string(f.Attack), "rasp", ttl, time.Now().Unix())
	if v == "" {
		return
	}
	set(EdgeVerdictHeader, v)
	rc.mu.Lock()
	rc.verdictSent = true
	rc.mu.Unlock()
}

func emitEvent(ctx context.Context, f *Finding, sink string, extra FindingExtra, decision Decision, mode Mode, eventID, app string, remote *RemoteConfig, es eventSink) {
	defer func() { _ = recover() }()
	rc := FromContext(ctx)
	p := firstNonEmpty(extra.Path, rc.Path())
	route := firstNonEmpty(extra.Route, rc.Route())
	if route == "" && p != "" {
		route = EventRouteOf(p)
	}
	route = safeRoute(route)
	version := "local"
	if remote != nil {
		version = remote.Version
	}
	attrs := map[string]string{
		"shield360.rasp.event_id":       eventID,
		"shield360.rasp.app":            app,
		"shield360.rasp.attack":         string(f.Attack),
		"shield360.rasp.rule":           f.Rule,
		"shield360.rasp.decision":       string(decision),
		"shield360.rasp.mode":           string(mode),
		"shield360.rasp.sink":           sink,
		"shield360.rasp.config_version": version,
		"shield360.rasp.language":       Runtime,
	}
	opt := func(k, v string) {
		if v != "" {
			attrs[k] = v
		}
	}
	if f.Input != nil {
		opt("shield360.rasp.source", string(f.Input.Source))
		opt("shield360.rasp.input_key", safeKey(f.Input.Key))
	}
	opt("shield360.rasp.route", route)
	opt("shield360.rasp.method", safeMethod(firstNonEmpty(extra.Method, rc.Method())))
	opt("shield360.rasp.framework", firstNonEmpty(extra.Framework, rc.Framework()))
	if cveRe.MatchString(f.CVE) {
		attrs["shield360.rasp.cve"] = f.CVE
	}
	if remote != nil && remote.Snippets && f.Input != nil {
		attrs["shield360.rasp.snippet"] = MaskSnippet(f.Input.Value)
	}
	// SHIELD: protection triangle — the Edge request this happened in (one
	// correlated event in Shield360), and a tightening.
	if e := rc.Edge(); e != nil {
		attrs["shield360.edge.request_id"] = e.Rid
	}
	if extra.tightenedByEdge {
		attrs["shield360.rasp.tightened_by_edge"] = "true"
	}
	addTargetAttrs(attrs, f, remote)
	addUploadAttrs(attrs, f)
	// SHIELD: AI attack agents — the client kind and the reason it was marked.
	if extra.agent != nil && f.Attack == AIAttackAgent {
		attrs["shield360.rasp.client_kind"] = extra.agent.Kind
		attrs["shield360.rasp.reason"] = extra.agent.Reason
	}
	addTraceIDs(attrs, ctx)
	if es != nil {
		key := strings.Join([]string{string(f.Attack), f.Rule, sink, route, string(decision)}, "\x00")
		es.add(Event{Name: "shield360.rasp.event", Time: time.Now().UTC().Format("2006-01-02T15:04:05.000Z"), Attrs: attrs}, key)
	}
}
