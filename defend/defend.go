// Package defend is Shield360 Defend: decide in the app whether a request
// may go on.
//
//	shield, err := defend.New(defend.Options{
//		App:    "checkout",
//		URL:    os.Getenv("SHIELD360_URL"),
//		APIKey: os.Getenv("SHIELD360_API_KEY"),
//	})
//	r := shield.Defend(defend.RequestOf(req), defend.Call{Content: []string{prompt}})
//	if answer := defend.ResponseFor(r); answer != nil {
//		// answer.Status (403, 401, or a decoy), answer.Headers, answer.Body
//	}
//
// Or wrap a handler: shield.Middleware(next).
//
// The decision is made locally from a signed policy (typ
// shield360-defend+jws, GET /api/defend/policy) fetched and cached the way
// the RASP config is (same key pinning, polled in the background): no
// network call on the request path unless SharedRateLimits is on. Fail open
// by default. Port of sdk/typescript/src/defend by way of the PHP and Rust
// SDKs (docs/latest/shield360/defend.mdx is the contract).
package defend

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log"
	"math"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/Shield360-AI/shield360-go/clienttype"
	"github.com/Shield360-AI/shield360-go/rasp"
)

// Shield360 endpoints and Defend's block body.
const (
	// DecidePath is where shared rate limits are asked.
	DecidePath = "/api/defend/decide"
	// DecisionsPath is the decisions feed: a block made anywhere reaches
	// this process within about 5 s.
	DecisionsPath = "/api/defend/decisions"
	// BlockBody is the body of Defend's 403 and 401.
	BlockBody      = `{"error":"Forbidden"}`
	decisionsEvery = 5 * time.Second
)

// AgentVerifier checks a request's agent proof (a Shield360 agent passport
// or a Web Bot Auth signature); called only when the request carries one.
type AgentVerifier func(Request, *Facts) *AgentCheck

// Classifier is a classifier of your own.
type Classifier func(*Facts, clienttype.Signals) *clienttype.Classification

// Options configure Defend.
type Options struct {
	// App is the app's name in Shield360 (required).
	App string
	// URL and APIKey: with both, the signed policy is fetched and decisions
	// are reported.
	URL, APIKey string
	// ConfigPublicKey is the environment's policy-signing public key (JWK,
	// JWKS or bare x); also SHIELD360_CONFIG_PUBLIC_KEY. Without it no
	// policy is used and the fail mode applies.
	ConfigPublicKey string
	// AllowUnpinnedConfig is trust on first use, development only (also
	// SHIELD360_CONFIG_TOFU=dev); refused in production.
	AllowUnpinnedConfig bool
	// Mode: Monitor never denies (also SHIELD360_DEFEND=monitor;
	// SHIELD360_DEFEND=off allows everything). Default Enforce.
	Mode Mode
	// FailMode: default FailOpen.
	FailMode FailMode
	// Facts say how the client address and its location are read.
	Facts  FactsOptions
	Agents AgentVerifier
	// Classify is your own classifier; ClassifyOff turns classification
	// off (default: the shared signatures, Edge's context and breadth).
	Classify    Classifier
	ClassifyOff bool
	// SensitiveData: default SensitiveMonitor.
	SensitiveData SensitiveData
	// DisableReport: decisions are reported by default with a URL and key.
	DisableReport bool
	// SharedRateLimits asks Shield360 for rate decisions shared by every
	// instance, with this timeout (0: per-process buckets).
	SharedRateLimits time.Duration
	// HoneypotWords are words from the app's own routes for crumb paths.
	HoneypotWords []string
	// DisableHoneypotHeader: don't add the X-Debug-Trace crumb header to
	// allowed responses.
	DisableHoneypotHeader bool
	// DisableHoneypotFiles: don't answer the decoy files (/.env, ...).
	DisableHoneypotFiles bool
	// Policy is a hand-built policy (used until a signed one arrives).
	Policy *Policy
	// CacheDir is where the last verified policy is cached (default: a
	// shield360-defend folder in the temp directory).
	CacheDir string
	// HTTPClient for Shield360 calls (tests); Getenv reads the environment
	// (tests); Now is the clock (tests).
	HTTPClient *http.Client
	Getenv     func(string) string
	Now        func() time.Time
}

// Response is what to answer instead of the app.
type Response struct {
	Status  int
	Headers [][2]string
	Body    string
}

type current struct {
	p *Policy
	c *compiled
}

// Defend is Shield360 Defend.
type Defend struct {
	app    string
	o      Options
	remote bool

	mu       sync.RWMutex
	cur      *current
	feedEtag string

	rates   *RateTable
	breadth *clienttype.BreadthCounter
	marks   *rasp.SuspiciousTable
	replay  *rasp.EdgeReplayCache

	hpMu      sync.Mutex
	hpFor     *HoneypotSettings
	honeypots *Honeypots

	client   *rasp.ConfigClient
	reporter *reporter
	http     *http.Client

	stopOnce sync.Once
	stop     chan struct{}
	done     chan struct{}
}

func isProduction(v string) bool {
	v = strings.ToLower(strings.TrimSpace(v))
	return v == "prod" || v == "production"
}

// PrivateIP says whether ip is private, loopback or link-local: never
// trapped.
func PrivateIP(ip string) bool {
	v := strings.TrimPrefix(ip, "::ffff:")
	for _, p := range []string{"10.", "127.", "192.168.", "169.254.", "0."} {
		if strings.HasPrefix(v, p) {
			return true
		}
	}
	if rest, ok := strings.CutPrefix(v, "172."); ok {
		if dot := strings.IndexByte(rest, '.'); dot > 0 {
			n := 0
			for _, c := range rest[:dot] {
				if c < '0' || c > '9' {
					n = -1
					break
				}
				n = n*10 + int(c-'0')
			}
			if n >= 16 && n <= 31 {
				return true
			}
		}
	}
	l := strings.ToLower(v)
	return l == "::1" || strings.HasPrefix(l, "fe80:") || strings.HasPrefix(l, "fc") || strings.HasPrefix(l, "fd")
}

// New starts Defend. With a URL, an API key and a pinned key, the signed
// policy is polled in the background and decisions are reported.
func New(o Options) (*Defend, error) {
	d, err := build(o)
	if err != nil {
		return nil, err
	}
	d.start()
	return d, nil
}

func build(o Options) (*Defend, error) {
	o.App = strings.TrimSpace(o.App)
	if o.App == "" {
		return nil, errors.New("defend: App (the app name in Shield360) is required")
	}
	if o.Mode == "" {
		o.Mode = Enforce
	}
	if o.FailMode == "" {
		o.FailMode = FailOpen
	}
	if o.SensitiveData == "" {
		o.SensitiveData = SensitiveMonitor
	}
	if o.Getenv == nil {
		o.Getenv = os.Getenv
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	if o.HTTPClient == nil {
		o.HTTPClient = &http.Client{Timeout: 10 * time.Second}
	}
	d := &Defend{
		app: o.App, o: o, remote: o.URL != "" && o.APIKey != "",
		rates: NewRateTable(0), breadth: clienttype.NewBreadthCounter(0, 0),
		marks: rasp.NewSuspiciousTable(0, o.Now), replay: rasp.NewEdgeReplayCache(0),
		http: o.HTTPClient,
	}
	if o.Policy != nil {
		d.cur = &current{o.Policy, compile(o.Policy)}
	}
	if d.remote {
		pin := o.ConfigPublicKey
		if pin == "" {
			pin = o.Getenv("SHIELD360_CONFIG_PUBLIC_KEY")
		}
		pinned := rasp.ParsePublicKeys(pin)
		asked := o.AllowUnpinnedConfig || strings.EqualFold(strings.TrimSpace(o.Getenv("SHIELD360_CONFIG_TOFU")), "dev")
		prod := false
		for _, k := range []string{"APP_ENV", "NODE_ENV", "ENVIRONMENT", "GO_ENV"} {
			prod = prod || isProduction(o.Getenv(k))
		}
		tofu := len(pinned) == 0 && asked && !prod
		if len(pinned) > 0 || tofu {
			cache := o.CacheDir
			if cache == "" {
				cache = filepath.Join(os.TempDir(), "shield360-defend")
			}
			d.client = rasp.NewConfigClient(rasp.ConfigClientOptions{
				URL: o.URL, APIKey: o.APIKey, App: o.App, Pinned: pinned, AllowUnpinned: tofu, CacheDir: cache,
				OnConfig: func(c *rasp.Claims) {
					var next *current
					if c != nil {
						if p := ParsePolicy(c.Raw); p != nil {
							next = &current{p, compile(p)}
						}
					}
					d.mu.Lock()
					d.cur = next
					d.mu.Unlock()
				},
				OnWarning: func(reason string) {
					if reason != "trust_on_first_use" {
						log.Printf("Shield360 Defend: a signed policy was refused (%s); the last verified policy stays in force.", reason)
					}
				},
				HTTPClient: o.HTTPClient, Now: o.Now, Path: PolicyPath, JWSType: JWSType,
			})
		} else if o.Policy == nil {
			log.Print("Shield360 Defend: the signed policy key is not pinned, so no policy is used and the fail mode applies. Set Options.ConfigPublicKey (or SHIELD360_CONFIG_PUBLIC_KEY).")
		}
		if !o.DisableReport {
			d.reporter = newReporter(o.URL, o.APIKey, o.App, o.HTTPClient, func() int64 { return o.Now().UnixMilli() })
		}
	}
	return d, nil
}

func (d *Defend) start() {
	if d.client != nil {
		d.client.Start()
		d.stop, d.done = make(chan struct{}), make(chan struct{})
		go func() {
			defer close(d.done)
			t := time.NewTicker(decisionsEvery)
			defer t.Stop()
			for {
				select {
				case <-d.stop:
					return
				case <-t.C:
					d.checkFeed()
				}
			}
		}()
	}
	if d.reporter != nil {
		d.reporter.start()
	}
}

func (d *Defend) mode() (Mode, bool) {
	switch strings.ToLower(strings.TrimSpace(d.o.Getenv("SHIELD360_DEFEND"))) {
	case "off":
		return "", false
	case "monitor":
		return Monitor, true
	case "enforce":
		return Enforce, true
	}
	return d.o.Mode, true
}

func (d *Defend) current() *current {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.cur
}

// Policy is the policy in force, or nil.
func (d *Defend) Policy() *Policy {
	if c := d.current(); c != nil {
		return c.p
	}
	return nil
}

// SetPolicy replaces the policy in force (a hand-built one; a signed
// policy arriving later replaces it).
func (d *Defend) SetPolicy(p *Policy) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if p == nil {
		d.cur = nil
		return
	}
	d.cur = &current{p, compile(p)}
}

func (d *Defend) nowMs() float64 { return float64(d.o.Now().UnixMilli()) }

func (d *Defend) trapHitFor(ip string) bool {
	return ip != "" && (d.marks.Suspicious(ip) || rasp.DeceptionMarked(ip))
}

// checkFeed checks the decisions feed now: a cheap version check; the
// signed policy is read again only when its lists changed.
func (d *Defend) checkFeed() {
	defer func() { _ = recover() }()
	cur := d.current()
	if d.client == nil || cur == nil {
		return
	}
	u := strings.TrimRight(d.o.URL, "/") + DecisionsPath + "?app=" + url.QueryEscape(d.app)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return
	}
	req.Header.Set("Authorization", "Bearer "+d.o.APIKey)
	req.Header.Set("Accept", "application/json")
	d.mu.RLock()
	etag := d.feedEtag
	d.mu.RUnlock()
	if etag != "" {
		req.Header.Set("If-None-Match", etag)
	}
	res, err := d.http.Do(req)
	if err != nil {
		return
	}
	defer res.Body.Close()
	if res.StatusCode < 200 || res.StatusCode >= 300 {
		return
	}
	d.mu.Lock()
	d.feedEtag = res.Header.Get("ETag")
	d.mu.Unlock()
	var body struct {
		Version *string `json:"version"`
	}
	if json.NewDecoder(io.LimitReader(res.Body, 64*1024)).Decode(&body) != nil {
		return
	}
	if body.Version != nil && *body.Version != cur.p.ListsVersion {
		d.client.Poll(context.Background())
	}
}

func (d *Defend) sharedOver(p *Policy, f *Facts, base *input) map[string]bool {
	timeout := d.o.SharedRateLimits
	if timeout <= 0 || !d.remote || f.IP == "" {
		return nil
	}
	var ids []string
	for _, r := range rateRulesFor(base) {
		ids = append(ids, r.ID)
	}
	if len(ids) == 0 {
		return nil
	}
	body, err := json.Marshal(map[string]any{"app": d.app, "ip": f.IP, "ruleIds": ids, "version": p.Version})
	if err != nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), max(timeout, 10*time.Millisecond))
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(d.o.URL, "/")+DecidePath, bytes.NewReader(body))
	if err != nil {
		return nil
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+d.o.APIKey)
	res, err := d.http.Do(req)
	if err != nil {
		return nil
	}
	defer res.Body.Close()
	if res.StatusCode < 200 || res.StatusCode >= 300 {
		return nil
	}
	var v struct {
		Over map[string]any `json:"over"`
	}
	if json.NewDecoder(io.LimitReader(res.Body, 64*1024)).Decode(&v) != nil || v.Over == nil {
		return nil
	}
	out := map[string]bool{}
	for _, id := range ids {
		if b, ok := v.Over[id].(bool); ok {
			out[id] = b
		}
	}
	return out
}

func trim256(s string) string {
	if r := []rune(s); len(r) > 256 {
		return string(r[:256])
	}
	return s
}

func (d *Defend) report(r Result, f *Facts) {
	if d.reporter == nil {
		return
	}
	decision := r.Effective()
	trap := contains(r.Reasons, "trap_hit")
	if decision == Allow && !trap && !contains(r.Reasons, "rule:monitor") {
		return
	}
	d.reporter.add(Event{
		Kind: "decision", Decision: string(decision), Monitored: r.WouldBe != "", ClientType: r.ClientType,
		IP: f.IP, Path: trim256(f.Path), Method: f.Method,
		Reasons: append([]string(nil), r.Reasons...), RuleIDs: append([]string(nil), r.RuleIDs...),
	})
}

func (d *Defend) honeypotsFor(p *Policy) *Honeypots {
	s := p.Honeypots
	if s == nil {
		return nil
	}
	d.hpMu.Lock()
	defer d.hpMu.Unlock()
	if d.hpFor != nil && *d.hpFor == *s && d.honeypots != nil {
		return d.honeypots
	}
	hp := NewHoneypots(*s, d.o.HoneypotWords, d.o.Now)
	cp := *s
	d.hpFor, d.honeypots = &cp, hp
	return hp
}

func decoyCode(s string) string {
	var b strings.Builder
	for _, c := range s {
		if b.Len() >= 40 {
			break
		}
		if c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || strings.ContainsRune("_.:-", c) {
			b.WriteRune(c)
		}
	}
	if b.Len() == 0 {
		return "path"
	}
	return b.String()
}

// honeypotStep: a crumb or decoy in this request: report it, mark the client
// by level and mode, answer decoys with fake data.
func (d *Defend) honeypotStep(hp *Honeypots, p *Policy, f *Facts, mode Mode, r Result) Result {
	ip := f.IP
	ua := f.Headers["user-agent"]
	fp := Fingerprint(ip, ua)
	hit := hp.Check(f.Path, f.Query, f.Headers, hex.EncodeToString(fp[:]))
	var decoy *Decoy
	if !d.o.DisableHoneypotFiles {
		decoy = hp.Serve(f.Path, ip, ua)
	}
	if hit == nil {
		if decoy != nil {
			r.Decoy = decoy
		} else if !d.o.DisableHoneypotHeader {
			r.CrumbHeader = hp.CrumbsFor(ip, ua).HeaderValue
		}
		return r
	}
	action := hp.ActionFor(hit.Level)
	ttl := p.Traps.TTLSeconds
	if action != "monitor" {
		d.marks.Mark(ip, time.Duration(ttl)*time.Second)
	}
	reasons := []string{"trap:honeypot", "level:" + itoa(hit.Level), "crumb:" + hit.State}
	if hit.Foreign {
		reasons = append(reasons, "crumb:foreign")
	}
	reasons = append(reasons, "decoy:"+decoyCode(hit.Decoy))
	if d.reporter != nil {
		d.reporter.add(Event{Kind: "trap_hit", ClientType: clienttype.SuspectedAIAgent, IP: ip, Path: trim256(f.Path), Method: f.Method, Reasons: append([]string(nil), reasons...)})
	}
	r.Reasons = append(r.Reasons, reasons...)
	r.ClientType = clienttype.SuspectedAIAgent
	// SHIELD: decoy and trap verdicts — a trap hit always blocks the client fleet-wide at Edge, whatever the local action or mode.
	r.Verdict = rasp.HitVerdict(p.EdgeKeys, f.edge, ip, "block", "trap", "defend", int64(ttl), d.o.Now().Unix())
	// A decoy keeps answering with fake data (the client learns nothing); a
	// fake credential on a real route is refused now when the mode blocks.
	if decoy != nil {
		r.Decoy = decoy
		return r
	}
	verdict := Challenge
	if action == "block" {
		verdict = Deny
	}
	if action == "monitor" || mode == Monitor {
		if action != "monitor" {
			r.WouldBe = verdict
		}
		return r
	}
	out := newResult(verdict, r.Reasons, r.RuleIDs, ttl)
	out.ClientType = r.ClientType
	out.Verdict = r.Verdict
	return out
}

func itoa(n int) string {
	b, _ := json.Marshal(n)
	return string(b)
}

// Defend is the decision for a request. Never panics.
func (d *Defend) Defend(req Request, call Call) (out Result) {
	mode, on := d.mode()
	if !on {
		return newResult(Allow, []string{"off"}, nil, 0)
	}
	defer func() {
		if recover() != nil {
			out = failResult(d.o.FailMode, "error", mode)
			d.report(out, &Facts{Method: "GET", Path: "/"})
		}
	}()
	r, f := d.decide(req, call, mode)
	d.report(r, &f)
	return r
}

func safeAgent(v AgentVerifier, req Request, f *Facts) (a *AgentCheck) {
	defer func() {
		if recover() != nil {
			a = nil
		}
	}()
	return v(req, f)
}

func safeClassify(c Classifier, f *Facts) (out *clienttype.Classification) {
	defer func() {
		if recover() != nil {
			out = nil
		}
	}()
	return c(f, clienttype.Signals{})
}

func (d *Defend) decide(req Request, call Call, mode Mode) (Result, Facts) {
	f := FactsOf(req, call, d.o.Facts)
	nowMs := d.nowMs()
	cur := d.current()
	if cur != nil && cur.p.Exp+60 <= nowMs/1000 {
		cur = nil
	}
	var agent *AgentCheck
	if d.o.Agents != nil && CarriesAgentProof(f.Headers) {
		agent = safeAgent(d.o.Agents, req, &f)
	}
	// Protection triangle: what Edge, in front, says about this client
	// (verified, never trusted unverified; Defend keeps its own replay
	// cache, so RASP behind it still verifies the same header).
	if cur != nil {
		if v := f.Headers[strings.ToLower(rasp.EdgeContextHeader)]; v != "" && len(cur.p.EdgeKeys) > 0 {
			rid := f.Headers[strings.ToLower(rasp.RequestIDHeader)]
			if e := rasp.VerifyEdgeContextAt(cur.p.EdgeKeys, v, f.Method, f.RawPath, rid, int64(math.Floor(nowMs/1000)), d.replay); e != nil {
				f.Edge = &clienttype.EdgeSignal{ClientType: e.ClientType, Trap: e.Trap, Flagged: e.Flagged, Risk: e.Risk}
				f.edge = e
			}
		}
	}
	// A client Edge's honeypots already caught following a trail (level 2+)
	// is a trap hit here too.
	edgeCT := ""
	if f.Edge != nil {
		edgeCT = f.Edge.ClientType
	}
	edgeVerified := edgeCT == "verified_agent" || edgeCT == "verified_crawler"
	trapHit := !edgeVerified && (d.trapHitFor(f.IP) || (f.Edge != nil && f.Edge.Trap >= 2))
	verified := agent != nil && agent.Verified
	var classification *clienttype.Classification
	if !verified && !trapHit && !d.o.ClassifyOff {
		if d.o.Classify != nil {
			classification = safeClassify(d.o.Classify, &f)
		} else {
			s := clienttype.Signals{Edge: f.Edge}
			if f.IP != "" {
				s.Breadth = d.breadth.See(f.IP, f.Path, int64(nowMs))
			}
			c := clienttype.Classify(f.Headers, s)
			classification = &c
		}
	}
	in := &input{
		facts: &f, mode: mode, failMode: d.o.FailMode, agent: agent, trapHit: trapHit,
		classification: classification, content: CheckContent(f.Content, d.o.SensitiveData),
		sensitiveData: d.o.SensitiveData, rates: d.rates, nowMs: nowMs,
	}
	if cur != nil {
		in.policy, in.compiled = cur.p, cur.c
		in.sharedOver = d.sharedOver(cur.p, &f, in)
	}
	result := decide(in)
	// Honeypots: the same stateless crumbs as Edge. Never for verified
	// agents, trusted clients or private addresses.
	if cur != nil && f.IP != "" && !verified && !isTrusted(cur.c, f.IP) && !PrivateIP(f.IP) && result.Decision == Allow {
		if hp := d.honeypotsFor(cur.p); hp != nil {
			result = d.honeypotStep(hp, cur.p, &f, mode, result)
		}
	}
	return result, f
}

// ResponseFor is the response to answer with instead of the app, or nil to
// go on.
func ResponseFor(r Result) *Response {
	if r.Decision == Allow {
		if r.Decoy == nil {
			return nil
		}
		return withVerdict(&Response{Status: r.Decoy.Status, Headers: [][2]string{{"Content-Type", r.Decoy.ContentType}, {"Cache-Control", "no-store"}}, Body: r.Decoy.Body}, r)
	}
	status := http.StatusForbidden
	if r.Decision == RequireSignIn {
		status = http.StatusUnauthorized
	}
	return withVerdict(&Response{
		Status:  status,
		Headers: [][2]string{{"Content-Type", "application/json"}, {"Shield360-Defend", string(r.Decision)}, {"Cache-Control", "no-store"}},
		Body:    BlockBody,
	}, r)
}

// withVerdict adds a trap hit's verdict to Defend's own answer (SHIELD: decoy and trap verdicts).
func withVerdict(resp *Response, r Result) *Response {
	if r.Verdict != "" {
		resp.Headers = append(resp.Headers, [2]string{rasp.EdgeVerdictHeader, r.Verdict})
	}
	return resp
}

func validTrap(s string) bool {
	return len(s) >= 1 && len(s) <= 48 && allBytes(s, func(c byte) bool {
		return c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '_' || c == '.' || c == '-'
	})
}

// TrapHit: the app saw a trap hit by this request's client; it is marked
// suspected for the policy's trap TTL and the hit is reported.
func (d *Defend) TrapHit(req Request, trap string, call Call) {
	defer func() { _ = recover() }()
	f := FactsOf(req, call, d.o.Facts)
	ttl := DefaultTrapTTL
	if p := d.Policy(); p != nil {
		ttl = p.Traps.TTLSeconds
	}
	d.marks.Mark(f.IP, time.Duration(ttl)*time.Second)
	if !validTrap(trap) {
		trap = "trap"
	}
	if d.reporter != nil {
		d.reporter.add(Event{Kind: "trap_hit", ClientType: clienttype.SuspectedAIAgent, IP: f.IP, Path: trim256(f.Path), Method: f.Method, Reasons: []string{"trap:" + trap}})
	}
}

// Crumbs are the honeypot crumbs made for this request's client, to place
// where agents look and people don't. Nil while honeypots are off, and for
// trusted clients and private addresses.
func (d *Defend) Crumbs(req Request, call Call) (out *ClientCrumbs) {
	defer func() {
		if recover() != nil {
			out = nil
		}
	}()
	cur := d.current()
	if cur == nil {
		return nil
	}
	f := FactsOf(req, call, d.o.Facts)
	if f.IP == "" || PrivateIP(f.IP) || isTrusted(cur.c, f.IP) {
		return nil
	}
	hp := d.honeypotsFor(cur.p)
	if hp == nil {
		return nil
	}
	c := hp.CrumbsFor(f.IP, f.Headers["user-agent"])
	return &c
}

// FailedLogin: the app saw a failed sign-in from this request's client;
// reported (never the user name or password).
func (d *Defend) FailedLogin(req Request, call Call) {
	defer func() { _ = recover() }()
	if d.reporter == nil {
		return
	}
	f := FactsOf(req, call, d.o.Facts)
	d.reporter.add(Event{Kind: "failed_login", IP: f.IP, Path: trim256(f.Path), Method: f.Method, Reasons: []string{"failed_login"}})
}

// PendingEvents are the events not sent yet (tests, diagnostics).
func (d *Defend) PendingEvents() []Event {
	if d.reporter == nil {
		return nil
	}
	return d.reporter.pending()
}

// Flush sends queued events now.
func (d *Defend) Flush() {
	if d.reporter != nil {
		d.reporter.flush()
	}
}

// Close stops polling the policy and sends queued events.
func (d *Defend) Close() {
	d.stopOnce.Do(func() {
		if d.stop != nil {
			close(d.stop)
			<-d.done
		}
		if d.client != nil {
			d.client.Stop()
		}
		if d.reporter != nil {
			d.reporter.close()
		}
	})
}
