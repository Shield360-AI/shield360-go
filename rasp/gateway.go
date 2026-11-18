package rasp

import (
	"context"
	"net/http"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Gateway support: request capture and a per-app engine for a reverse proxy
// that sits in front of apps (Shield360 Edge, cli/internal/edge). One gateway
// process protects several apps, each with its own application name and
// signed config, so it cannot use the process-wide engine Init configures.
// An AppEngine is that engine for one app: the same mode resolution, the same
// event attributes and the same 403 decision, held in an instance.
//
// A gateway sees requests and responses, not sinks, so the checks it can run
// are the ones the contract runs on the request itself: virtual patches,
// file_write.upload on upload file names, and xss.reflected on HTML
// responses (monitor only). The captured inputs feed the response check.
//
// Keep the decision and the event in step with HandleFinding (engine.go).

// GatewayFramework is the framework name events from a gateway carry.
const GatewayFramework = "shield360-edge"

// Deception is the gateway-only attack type of decoy paths (sdk/rasp/README.md
// "Deception"): deception.hit when a client requests a decoy,
// deception.suspicious for that client's later requests. The SDKs never
// raise it.
const Deception AttackType = "deception"

// DeceptionSink is the sink of deception events.
const DeceptionSink = "edge.deception"

// CaptureRequest records r's inputs in a fresh request context, as
// Middleware does: query values, cookies, the input headers, and, when body
// is not nil, the body (JSON string leaves, form fields, or the raw text,
// with the contract's caps) and the names of uploaded files
// (body.<field>.filename). body is the part of the request body the caller
// buffered (at most 1 MiB); the request's own Body is not read.
// framework is the framework name events carry ("" for GatewayFramework).
func CaptureRequest(r *http.Request, body []byte, framework string) *Context {
	c, _ := captureGateway(r, body, framework)
	return c
}

// captureGateway is CaptureRequest, also returning the upload names it
// recorded (the package's own capture: once per name per request).
func captureGateway(r *http.Request, body []byte, framework string) (*Context, []upload) {
	if framework == "" {
		framework = GatewayFramework
	}
	c := captureRequest(r, framework)
	if body == nil {
		return c, nil
	}
	return c, c.captureBody(body, r.Header.Get("Content-Type"))
}

// VpRequest returns the request as virtual patches see it (zero outside a
// request).
func (c *Context) VpRequest() VpRequest {
	if c == nil {
		return VpRequest{}
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.vp == nil {
		return VpRequest{}
	}
	return c.vp.req
}

// NewContextWith returns ctx carrying c, so sink helpers called with it see
// the request's inputs.
func NewContextWith(ctx context.Context, c *Context) context.Context { return withContext(ctx, c) }

// AppOptions configure an AppEngine.
type AppOptions struct {
	// App is the application name events and the signed config use.
	App string
	// Mode is the default mode for every attack type without its own
	// (default monitor).
	Mode Mode
	// Attacks sets the mode per attack type.
	Attacks map[AttackType]Mode
	// MonitorOnly caps block at monitor: a signed config was expected but
	// no config key is pinned (the contract's "No pin").
	MonitorOnly bool
	// Runtime and RuntimeVersion are the protected app's runtime (node,
	// python, go, dotnet) and version, which virtual patches with
	// runtimes/runtimeVersions compare. Empty Runtime: the gateway does not
	// know the app's runtime, and every rule applies whatever runtime it
	// names.
	Runtime        string
	RuntimeVersion string
	// Reporter receives events; nil drops them (they are still returned).
	Reporter *Reporter
	// OnEvent, when set, also receives every event with the context of the
	// call that raised it (telemetry).
	OnEvent func(context.Context, Event)
	// Getenv reads SHIELD360_RASP (default os.Getenv).
	Getenv func(string) string
}

// AppEngine is the RASP engine of one app behind a gateway.
type AppEngine struct {
	o      AppOptions
	local  localSettings
	envOff bool

	remote atomic.Pointer[RemoteConfig]
	// deception is the signed config's attacks.deception ("" when unset);
	// the process-wide attack list does not hold it.
	deception atomic.Pointer[Mode]
	rules     atomic.Pointer[[]VirtualPatchRule]
	disabled  atomic.Bool
}

// NewAppEngine builds an engine for one app.
func NewAppEngine(o AppOptions) *AppEngine {
	env := envSetting(o.Getenv)
	if o.App == "" {
		o.App = "default"
	}
	mode := asMode(string(o.Mode))
	if mode == "" {
		mode = ModeMonitor
		if env == ModeBlock || env == ModeMonitor {
			mode = env
		}
	}
	e := &AppEngine{o: o, envOff: env == ModeOff, local: localSettings{mode: mode, attacks: cleanAttacks(o.Attacks)}}
	e.setRules(BuiltInRules)
	return e
}

// App is the application name.
func (e *AppEngine) App() string { return e.o.App }

// SetRemote applies a verified signed config (nil drops it: local options
// again). Pass it as a ConfigClient's OnConfig.
func (e *AppEngine) SetRemote(c *Claims) {
	if c == nil {
		e.remote.Store(nil)
		e.deception.Store(nil)
		e.setRules(BuiltInRules)
		return
	}
	dm := asMode(string(c.Attacks[Deception]))
	e.deception.Store(&dm)
	r := toRemote(c)
	r.Attacks = cleanAttacks(r.Attacks)
	r.Mode = asMode(string(r.Mode))
	var rules []VirtualPatchRule
	if r.Rules != nil {
		rules = []VirtualPatchRule{}
		for _, rule := range r.Rules {
			if rule.ID != "" && rule.Match != nil {
				rules = append(rules, rule)
			}
		}
		r.Rules = rules
	}
	e.remote.Store(r)
	if rules != nil {
		e.setRules(rules)
	} else {
		e.setRules(BuiltInRules)
	}
}

// setRules keeps the rules in force, without runtime restrictions when the
// app's runtime is unknown.
func (e *AppEngine) setRules(rules []VirtualPatchRule) {
	out := rules
	if e.o.Runtime == "" {
		out = make([]VirtualPatchRule, len(rules))
		for i, r := range rules {
			r.Runtimes, r.RuntimeVersions = nil, nil
			out[i] = r
		}
	}
	e.rules.Store(&out)
}

// Remote is the signed config in force, or nil.
func (e *AppEngine) Remote() *RemoteConfig { return e.remote.Load() }

// Disable and Enable are this app's runtime kill switch.
func (e *AppEngine) Disable() { e.disabled.Store(true) }

// Enable undoes Disable.
func (e *AppEngine) Enable() { e.disabled.Store(false) }

// Active reports whether checks run: not SHIELD360_RASP=off, not the signed
// config's kill switch, not Disable.
func (e *AppEngine) Active() bool {
	if e == nil || e.envOff || e.disabled.Load() {
		return false
	}
	r := e.remote.Load()
	return r == nil || !r.KillSwitch
}

// ModeFor is the effective mode of an attack type (off when not active),
// resolved as the process-wide engine resolves it.
func (e *AppEngine) ModeFor(attack AttackType) Mode {
	if !e.Active() {
		return ModeOff
	}
	if e.local.attacks[attack] == ModeOff {
		return ModeOff
	}
	var m Mode
	if r := e.remote.Load(); r != nil {
		m = r.Attacks[attack]
		if m == "" {
			m = r.Mode
		}
		if m == "" {
			m = ModeMonitor
		}
	} else {
		m = e.local.attacks[attack]
		if m == "" {
			m = e.local.mode
		}
	}
	if m == ModeBlock && (MonitorOnly(attack) || e.o.MonitorOnly) {
		m = ModeMonitor
	}
	return m
}

// Handle applies a finding for this app: reports it and returns the
// decision, with the block error when the decision is blocked. c is the
// request's context (route, method, path), or nil.
func (e *AppEngine) Handle(ctx context.Context, c *Context, f *Finding, sink string, extra FindingExtra) (Decision, *BlockedError) {
	if f == nil || !e.Active() {
		return DecisionNone, nil
	}
	mode := e.ModeFor(f.Attack)
	if f.Action != "" && modeRank[f.Action] < modeRank[mode] {
		mode = f.Action
	}
	if mode == ModeOff {
		return DecisionNone, nil
	}
	decision := DecisionMonitored
	if mode == ModeBlock && !MonitorOnly(f.Attack) {
		decision = DecisionBlocked
	}
	eventID := newEventID()
	func() {
		defer func() { _ = recover() }() // reporting never breaks the call
		ev, key := e.event(c, f, sink, extra, decision, mode, eventID)
		addTraceIDs(ev.Attrs, ctx)
		if e.o.Reporter != nil {
			e.o.Reporter.Add(ev, key)
		}
		if e.o.OnEvent != nil {
			if ctx == nil {
				ctx = context.Background()
			}
			e.o.OnEvent(ctx, ev)
		}
	}()
	if decision == DecisionBlocked {
		return decision, &BlockedError{Attack: f.Attack, Rule: f.Rule, EventID: eventID}
	}
	return decision, nil
}

// event builds the contract's shield360.rasp.event and its fold key.
func (e *AppEngine) event(c *Context, f *Finding, sink string, extra FindingExtra, decision Decision, mode Mode, eventID string) (Event, string) {
	p := firstNonEmpty(extra.Path, c.Path())
	route := firstNonEmpty(extra.Route, c.Route())
	if route == "" && p != "" {
		route = RouteOf(p)
	}
	route = safeRoute(route)
	remote := e.remote.Load()
	version := "local"
	if remote != nil {
		version = remote.Version
	}
	attrs := map[string]string{
		"shield360.rasp.event_id":       eventID,
		"shield360.rasp.app":            e.o.App,
		"shield360.rasp.attack":         string(f.Attack),
		"shield360.rasp.rule":           f.Rule,
		"shield360.rasp.decision":       string(decision),
		"shield360.rasp.mode":           string(mode),
		"shield360.rasp.sink":           sink,
		"shield360.rasp.config_version": version,
	}
	opt := func(k, v string) {
		if v != "" {
			attrs[k] = v
		}
	}
	switch e.o.Runtime {
	case "node", "python", "go", "dotnet":
		attrs["shield360.rasp.language"] = e.o.Runtime
	}
	if f.Input != nil {
		opt("shield360.rasp.source", string(f.Input.Source))
		opt("shield360.rasp.input_key", safeKey(f.Input.Key))
	}
	opt("shield360.rasp.route", route)
	opt("shield360.rasp.method", safeMethod(firstNonEmpty(extra.Method, c.Method())))
	opt("shield360.rasp.framework", firstNonEmpty(extra.Framework, c.Framework()))
	if cveRe.MatchString(f.CVE) {
		attrs["shield360.rasp.cve"] = f.CVE
	}
	if remote != nil && remote.Snippets && f.Input != nil {
		attrs["shield360.rasp.snippet"] = MaskSnippet(f.Input.Value)
	}
	addTargetAttrs(attrs, f, remote)
	key := strings.Join([]string{string(f.Attack), f.Rule, sink, route, string(decision)}, "\x00")
	return Event{Name: EventName, Time: time.Now().UTC().Format("2006-01-02T15:04:05.000Z"), Attrs: attrs}, key
}

// ReportDeception reports a deception finding for r (rule deception.hit
// or deception.suspicious). block is the gateway's own setting; the signed
// config's attacks.deception can only lower it (off reports nothing,
// monitor caps block), and no pinned key while a signed config was expected
// caps it at monitor. The
// caller blocks the client only when the decision is blocked.
func (e *AppEngine) ReportDeception(ctx context.Context, r *http.Request, rule string, block bool) (Decision, *BlockedError) {
	if !e.Active() {
		return DecisionNone, nil
	}
	mode := ModeMonitor
	if block {
		mode = ModeBlock
	}
	// The signed attacks.deception caps the gateway's action (README
	// "Deception"): off turns it off, monitor lowers block, block never
	// raises monitor.
	if dm := e.deception.Load(); dm != nil && *dm != "" && modeRank[*dm] < modeRank[mode] {
		mode = *dm
	}
	if mode == ModeOff {
		return DecisionNone, nil
	}
	if mode == ModeBlock && e.o.MonitorOnly {
		mode = ModeMonitor
	}
	decision := DecisionMonitored
	if mode == ModeBlock {
		decision = DecisionBlocked
	}
	path := r.URL.EscapedPath()
	f := &Finding{Attack: Deception, Rule: rule}
	eventID := newEventID()
	func() {
		defer func() { _ = recover() }()
		ev, key := e.event(nil, f, DeceptionSink, FindingExtra{Framework: GatewayFramework, Method: r.Method, Path: path, Route: RouteOf(path)}, decision, mode, eventID)
		addTraceIDs(ev.Attrs, ctx, r.Context())
		if e.o.Reporter != nil {
			e.o.Reporter.Add(ev, key)
		}
		if e.o.OnEvent != nil {
			if ctx == nil {
				ctx = context.Background()
			}
			e.o.OnEvent(ctx, ev)
		}
	}()
	if decision == DecisionBlocked {
		return decision, &BlockedError{Attack: Deception, Rule: rule, EventID: eventID}
	}
	return decision, nil
}

// InspectRequest captures r (with the buffered body, nil when none was
// read) and runs the request checks: file_write.upload on each upload file
// name, then the virtual patches (head rules, then body rules once the body
// is known). It returns the request's context and, when a check blocks, the
// block error. Detector and engine panics propagate to the caller, which
// decides whether to fail open.
func (e *AppEngine) InspectRequest(r *http.Request, body []byte, framework string) (*Context, *BlockedError) {
	c, uploads := captureGateway(r, body, framework)
	if !e.Active() {
		return c, nil
	}
	extra := FindingExtra{Framework: c.framework, Method: c.method, Path: c.path, Route: c.Route()}
	for _, u := range uploads {
		if f := uploadFinding(u); f != nil {
			if _, b := e.Handle(r.Context(), c, f, UploadSink, extra); b != nil {
				return c, b
			}
		}
	}
	if e.ModeFor(VirtualPatch) == ModeOff {
		return c, nil
	}
	req := c.VpRequest()
	rules := *e.rules.Load()
	phases := []VpPhase{PhaseHead}
	if body != nil {
		phases = append(phases, PhaseBody)
	}
	for _, phase := range phases {
		if f := MatchVirtualPatches(&req, rules, phase, e.o.Runtime, e.o.RuntimeVersion); f != nil {
			if _, b := e.Handle(r.Context(), c, f, VpSink, extra); b != nil {
				return c, b
			}
		}
	}
	return c, nil
}

// CheckResponse runs xss.reflected on a complete HTML response body for the
// request c captured. Monitor only: it reports and never blocks. Call it off
// the response path.
func (e *AppEngine) CheckResponse(ctx context.Context, c *Context, contentType string, body []byte) {
	if c == nil || len(body) == 0 || e.ModeFor(XSS) == ModeOff {
		return
	}
	inputs := c.Inputs()
	if len(inputs) == 0 {
		return
	}
	if f := DetectXSS(contentType, string(body), inputs); f != nil {
		e.Handle(ctx, c, f, "http.response", FindingExtra{})
	}
}

// AppRuntime is what StartApp needs to fetch and verify one app's signed
// config and report its events.
type AppRuntime struct {
	URL, APIKey     string
	Environment     string
	SDKVersion      string
	ConfigPublicKey string
	// AllowUnpinnedConfig is development only (see Options).
	AllowUnpinnedConfig bool
	CacheDir            string
	HTTPClient          *http.Client
	Getenv              func(string) string
	// Logf receives warnings (default the package logger).
	Logf func(string, ...any)
}

// AppHandle owns an app's reporter and config client.
type AppHandle struct {
	Engine   *AppEngine
	reporter *Reporter
	client   *ConfigClient
	stopOnce sync.Once
}

// StartApp builds an AppEngine for o.App with its reporter and, when a key
// is pinned (or trust on first use is allowed), its signed config client,
// following the contract's key pinning rules. Without a URL and API key the
// engine runs on its local options and events are only passed to OnEvent.
func StartApp(o AppOptions, rt AppRuntime) *AppHandle {
	getenv := rt.Getenv
	if getenv == nil {
		getenv = os.Getenv
	}
	o.Getenv = getenv
	logf := rt.Logf
	if logf == nil {
		logf = func(f string, a ...any) { logfDefault(f, a...) }
	}
	remote := rt.URL != "" && rt.APIKey != ""
	keyText := rt.ConfigPublicKey
	if keyText == "" {
		keyText = getenv("SHIELD360_CONFIG_PUBLIC_KEY")
	}
	pinned := ParsePublicKeys(keyText)
	tofu := len(pinned) == 0 && TofuAllowed(rt.AllowUnpinnedConfig, rt.Environment, getenv)
	if remote && len(pinned) == 0 && !tofu {
		o.MonitorOnly = true
		logf("Shield360 Edge: app %q: the signed config key is not pinned, so the signed config is not used and protection runs in monitor mode. Set SHIELD360_CONFIG_PUBLIC_KEY to the environment's public key.", o.App)
	}
	h := &AppHandle{}
	if remote {
		h.reporter = NewReporter(ReporterOptions{URL: rt.URL, APIKey: rt.APIKey, ApplicationName: o.App, Environment: rt.Environment, SDKVersion: rt.SDKVersion, HTTPClient: rt.HTTPClient})
		h.reporter.Start()
		o.Reporter = h.reporter
	}
	h.Engine = NewAppEngine(o)
	if remote && (len(pinned) > 0 || tofu) {
		if tofu {
			logf("Shield360 Edge: app %q: trust on first use is on for the signed config (development only).", o.App)
		}
		app := o.App
		h.client = NewConfigClient(ConfigClientOptions{
			URL: rt.URL, APIKey: rt.APIKey, App: app, Pinned: pinned, AllowUnpinned: tofu,
			CacheDir: rt.CacheDir, HTTPClient: rt.HTTPClient,
			OnConfig: h.Engine.SetRemote,
			OnWarning: func(reason string) {
				if reason != "trust_on_first_use" {
					logf("Shield360 Edge: app %q: a signed config was refused (%s); the last verified config or the local options stay in force.", app, reason)
				}
			},
		})
		h.client.Start()
	}
	return h
}

// Stop stops the config client and sends the reporter's queued events.
func (h *AppHandle) Stop(ctx context.Context) {
	h.stopOnce.Do(func() {
		if h.client != nil {
			h.client.Stop()
		}
		if h.reporter != nil {
			h.reporter.Stop(ctx)
		}
	})
}

func logfDefault(f string, a ...any) { logf(f, a...) }
