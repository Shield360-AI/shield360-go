package rasp

import (
	"container/list"
	"context"
	"encoding/json"
	"math"
	"net/http"
	"strings"
	"sync"
	"time"
	"unicode/utf8"
)

// Deception: decoy paths from the signed config's `deception` block
// (README "Deception"). A request to a decoy never reaches the handler: it
// gets the app's normal not-found answer and marks the client's address
// suspicious; that address's later requests are reported, and blocked when
// the block's action is block. Matching is Shield360 Edge's, case by case
// (testdata/deception.json).

// DeceptionHTTPSink is the sink of the SDK middleware's deception events
// (Edge uses DeceptionSink).
const DeceptionHTTPSink = "http.deception"

// The limits of the signed config's deception block.
const (
	MaxDecoys               = 64
	MaxDecoyLength          = 256
	DefaultDeceptionTTL     = 900
	MaxDeceptionTTL         = 86400
	DefaultSuspiciousCap    = 10_000
	deceptionActionBlock    = "block"
	deceptionActionMonitor  = "monitor"
	deceptionRuleHit        = "deception.hit"
	deceptionRuleSuspicious = "deception.suspicious"
)

// DeceptionConfig is a usable deception block: at least one decoy.
type DeceptionConfig struct {
	Paths      []string
	Action     string // "block" or "monitor"
	TTLSeconds int
}

// ParseDeception reads the signed config's `deception` value (nil when
// absent). It returns nil when deception is off: not an object, or no usable
// path.
func ParseDeception(raw json.RawMessage) *DeceptionConfig {
	if len(raw) == 0 {
		return nil
	}
	var m map[string]json.RawMessage
	if json.Unmarshal(raw, &m) != nil || m == nil {
		return nil
	}
	var entries []json.RawMessage
	if json.Unmarshal(m["paths"], &entries) != nil || entries == nil {
		return nil
	}
	cfg := &DeceptionConfig{Action: deceptionActionMonitor, TTLSeconds: DefaultDeceptionTTL}
	for _, e := range entries {
		var p string
		if json.Unmarshal(e, &p) != nil {
			continue
		}
		if utf8.RuneCountInString(p) > MaxDecoyLength || !strings.HasPrefix(p, "/") {
			continue
		}
		p = strings.TrimSuffix(p, "/")
		if p == "" || p == "/" {
			continue
		}
		cfg.Paths = append(cfg.Paths, p)
		if len(cfg.Paths) == MaxDecoys {
			break
		}
	}
	if len(cfg.Paths) == 0 {
		return nil
	}
	var action string
	if json.Unmarshal(m["action"], &action) == nil && action == deceptionActionBlock {
		cfg.Action = deceptionActionBlock
	}
	var ttl any
	if json.Unmarshal(m["ttlSeconds"], &ttl) == nil {
		if f, ok := ttl.(float64); ok && !math.IsNaN(f) && f >= 1 {
			cfg.TTLSeconds = int(math.Min(math.Floor(f), MaxDeceptionTTL))
		}
	}
	return cfg
}

// decodePath percent-decodes a path once (every %XX, %2F included); false
// on an invalid escape.
func decodePath(p string) (string, bool) {
	if !strings.Contains(p, "%") {
		return p, true
	}
	var b strings.Builder
	b.Grow(len(p))
	for i := 0; i < len(p); i++ {
		if p[i] != '%' {
			b.WriteByte(p[i])
			continue
		}
		if i+2 >= len(p) {
			return "", false
		}
		hi, ok1 := unhex(p[i+1])
		lo, ok2 := unhex(p[i+2])
		if !ok1 || !ok2 {
			return "", false
		}
		b.WriteByte(hi<<4 | lo)
		i += 2
	}
	return b.String(), true
}

// MatchDecoy returns the decoy a request target (origin form: path and an
// optional query) hits, or "" (README "Deception", "Matching").
func MatchDecoy(decoys []string, target string) string {
	if i := strings.IndexByte(target, '?'); i >= 0 {
		target = target[:i]
	}
	path, ok := decodePath(target)
	if !ok {
		return ""
	}
	return matchDecoded(decoys, path)
}

// matchDecoded matches a path that is already decoded (Edge's IsDecoy).
func matchDecoded(decoys []string, path string) string {
	for _, d := range decoys {
		if path == d || strings.HasPrefix(path, d+"/") {
			return d
		}
	}
	return ""
}

// SuspiciousTable holds the addresses that hit a decoy, in memory and per
// process: ordered by expiry, at most cap entries. Marking a new address
// when it is full drops the expired marks, then the mark closest to
// expiring. (Ordering by expiry, not by marking, keeps that right after a
// config lowers the TTL: newer marks may then expire before older ones.)
type SuspiciousTable struct {
	mu    sync.Mutex
	cap   int
	now   func() time.Time
	order *list.List // of *suspect, soonest expiry first
	byIP  map[string]*list.Element
}

type suspect struct {
	ip    string
	until time.Time
}

// NewSuspiciousTable builds a table (cap <= 0: DefaultSuspiciousCap; now
// nil: time.Now).
func NewSuspiciousTable(cap int, now func() time.Time) *SuspiciousTable {
	if cap <= 0 {
		cap = DefaultSuspiciousCap
	}
	if now == nil {
		now = time.Now
	}
	return &SuspiciousTable{cap: cap, now: now, order: list.New(), byIP: map[string]*list.Element{}}
}

// Mark makes ip suspicious for ttl (marking again restarts the time).
func (t *SuspiciousTable) Mark(ip string, ttl time.Duration) {
	if ip == "" {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	now := t.now()
	if e, ok := t.byIP[ip]; ok {
		t.drop(e)
	}
	if t.order.Len() >= t.cap {
		// Every expired mark is at the front, then the one closest to expiring.
		for f := t.order.Front(); f != nil && !now.Before(f.Value.(*suspect).until); f = t.order.Front() {
			t.drop(f)
		}
		for t.order.Len() >= t.cap {
			t.drop(t.order.Front())
		}
	}
	s := &suspect{ip: ip, until: now.Add(ttl)}
	// After the last mark that expires no later; with one TTL that is the
	// back, so this walks only after a TTL change.
	at := t.order.Back()
	for at != nil && at.Value.(*suspect).until.After(s.until) {
		at = at.Prev()
	}
	if at == nil {
		t.byIP[ip] = t.order.PushFront(s)
	} else {
		t.byIP[ip] = t.order.InsertAfter(s, at)
	}
}

func (t *SuspiciousTable) drop(e *list.Element) {
	t.order.Remove(e)
	delete(t.byIP, e.Value.(*suspect).ip)
}

// Suspicious reports whether ip is marked; an expired mark is dropped.
func (t *SuspiciousTable) Suspicious(ip string) bool {
	if ip == "" {
		return false
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	e, ok := t.byIP[ip]
	if !ok {
		return false
	}
	if !t.now().Before(e.Value.(*suspect).until) {
		t.drop(e)
		return false
	}
	return true
}

// Len is the number of marks held.
func (t *SuspiciousTable) Len() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.order.Len()
}

var (
	suspectsMu sync.RWMutex
	suspects   = NewSuspiciousTable(0, nil)
)

func suspiciousTable() *SuspiciousTable {
	suspectsMu.RLock()
	defer suspectsMu.RUnlock()
	return suspects
}

// setSuspiciousTable swaps the table (tests).
func setSuspiciousTable(t *SuspiciousTable) {
	suspectsMu.Lock()
	suspects = t
	suspectsMu.Unlock()
}

// deceptionState is the block in force and its effective mode; nil when
// deception is off (inactive, no decoys, or attacks.deception off).
func deceptionState() (*DeceptionConfig, Mode) {
	if !Active() {
		return nil, ModeOff
	}
	stateMu.RLock()
	defer stateMu.RUnlock()
	r := state.remote
	if r == nil || r.Deception == nil || state.localDeceptionOff {
		return nil, ModeOff
	}
	mode := ModeMonitor
	if r.Deception.Action == deceptionActionBlock {
		mode = ModeBlock
	}
	switch r.deceptionMode {
	case ModeOff:
		return nil, ModeOff
	case ModeMonitor:
		mode = ModeMonitor
	}
	if mode == ModeBlock && state.monitorOnly {
		mode = ModeMonitor
	}
	return r.Deception, mode
}

// deceptionVerdict is what the middleware does with a request.
type deceptionVerdict int

const (
	deceptionPass deceptionVerdict = iota
	deceptionNotFound
	deceptionBlocked
)

// checkDeception runs deception for a request, first thing in the
// middleware. The client address is request.ip's: the peer address, never
// X-Forwarded-For. It fails open.
func checkDeception(ctx context.Context, r *http.Request, framework string) (v deceptionVerdict, blocked *BlockedError, page, verdict string) {
	defer func() {
		if recover() != nil {
			v, blocked, page, verdict = deceptionPass, nil, "", ""
		}
	}()
	// SHIELD: AI attack agents — the tripwire URL is answered first (README "AI attack agents").
	if hit, b := checkTripwire(ctx, r, framework); hit {
		if b != nil {
			return deceptionBlocked, b, "", ""
		}
		return deceptionNotFound, nil, "", ""
	}
	cfg, mode := deceptionState()
	if cfg == nil {
		return deceptionPass, nil, "", ""
	}
	ip := peerIP(r.RemoteAddr)
	table := suspiciousTable()
	// net/http has decoded the path once (an invalid escape never gets
	// here): the same URL.Path Edge matches.
	if decoy := matchDecoded(cfg.Paths, r.URL.Path); decoy != "" {
		table.Mark(ip, time.Duration(cfg.TTLSeconds)*time.Second)
		reportDeception(ctx, r, deceptionRuleHit, framework, decoy, mode)
		// SHIELD: AI attack agents — a decoy hit adds to the behavior score; the 404 may carry the tripwire page.
		// SHIELD: decoy and trap verdicts — behind Edge, the 404 tells every Edge to block the client, in monitor too.
		return deceptionNotFound, nil, agentsDecoy(ctx, r, framework), decoyVerdict(r, ip, cfg.TTLSeconds)
	}
	if !table.Suspicious(ip) {
		return deceptionPass, nil, "", ""
	}
	path := r.URL.EscapedPath()
	if b := reportDeception(ctx, r, deceptionRuleSuspicious, framework, EventRouteOf(path), mode); b != nil {
		return deceptionBlocked, b, "", ""
	}
	return deceptionPass, nil, "", ""
}

// decoyVerdict is the verdict a decoy hit sends Edge (README "Deception",
// "Protection triangle"): always block, whatever the app's own action (its
// answer to the request is unchanged), for the deception TTL. Edge's context
// is verified without a replay cache (the request never reaches the handler).
// "" without one.
func decoyVerdict(r *http.Request, ip string, ttl int) string {
	v := r.Header.Get(EdgeContextHeader)
	keys := edgeKeys()
	if v == "" || len(keys) == 0 {
		return ""
	}
	now := time.Now().Unix()
	e := verifyEdgeContext(keys, v, r.Method, r.URL.EscapedPath(), r.Header.Get(RequestIDHeader), now, nil)
	return HitVerdict(keys, e, ip, "block", "deception", "rasp", int64(ttl), now)
}

// reportDeception sends a deception event and returns the block error when
// the decision is blocked.
func reportDeception(ctx context.Context, r *http.Request, rule, framework, route string, mode Mode) *BlockedError {
	decision := DecisionMonitored
	if mode == ModeBlock {
		decision = DecisionBlocked
	}
	eventID := newEventID()
	stateMu.RLock()
	app, remote, es := state.applicationName, state.remote, state.sink
	stateMu.RUnlock()
	emitEvent(ctx, &Finding{Attack: Deception, Rule: rule}, DeceptionHTTPSink,
		FindingExtra{Framework: framework, Method: r.Method, Path: r.URL.EscapedPath(), Route: route},
		decision, mode, eventID, app, remote, es)
	if decision == DecisionBlocked {
		return &BlockedError{Attack: Deception, Rule: rule, EventID: eventID}
	}
	return nil
}
