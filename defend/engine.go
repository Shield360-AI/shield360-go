package defend

import (
	"container/list"
	"math"
	"sync"

	"github.com/Shield360-AI/shield360-go/clienttype"
)

// The decision order (docs/latest/shield360/defend.mdx): kill switch, deny
// list, agent policy, trap hit, challenge list, rules in order (first
// match wins, allow and monitor go on), then sensitive data. Port of
// defend/engine.ts.

// ListTTL is the TTL (seconds) of a list decision.
const ListTTL = 60

// Verdict is Defend's decision.
type Verdict string

// The verdicts, weakest first.
const (
	Allow         Verdict = "allow"
	RequireSignIn Verdict = "require_sign_in"
	Challenge     Verdict = "challenge"
	Deny          Verdict = "deny"
)

func (v Verdict) rank() int {
	switch v {
	case RequireSignIn:
		return 1
	case Challenge:
		return 2
	case Deny:
		return 3
	}
	return 0
}

// Result is Defend's answer for a request.
type Result struct {
	Decision Verdict
	Reasons  []string
	RuleIDs  []string
	// TTL is how long (seconds) the decision may be cached; 0 for none.
	TTL int
	// WouldBe is the decision monitor mode did not enforce ("" for none).
	WouldBe    Verdict
	ClientType string
	// Decoy is the honeypot's fake file to answer with (nil for none).
	Decoy *Decoy
	// CrumbHeader is the X-Debug-Trace value to add to an allowed response.
	CrumbHeader string
	// Verdict is the signed X-Shield360-Verdict a trap hit sends Edge, for
	// the response (SHIELD: decoy and trap verdicts); "" for none.
	Verdict string
}

func newResult(d Verdict, reasons, ruleIDs []string, ttl int) Result {
	if reasons == nil {
		reasons = []string{}
	}
	if ruleIDs == nil {
		ruleIDs = []string{}
	}
	return Result{Decision: d, Reasons: reasons, RuleIDs: ruleIDs, TTL: ttl}
}

// Effective is the decision as enforced, or as it would be outside monitor
// mode.
func (r Result) Effective() Verdict {
	if r.WouldBe != "" {
		return r.WouldBe
	}
	return r.Decision
}

// Mode is enforce (the default) or monitor (never denies).
type Mode string

// The modes.
const (
	Enforce Mode = "enforce"
	Monitor Mode = "monitor"
)

// FailMode is what happens without a usable policy: open (allow, the
// default) or closed (deny).
type FailMode string

// The fail modes.
const (
	FailOpen   FailMode = "open"
	FailClosed FailMode = "closed"
)

// SensitiveData is what sensitive data in the content does: monitor (the
// default; a reason only), block, or off (not checked).
type SensitiveData string

// The sensitive-data modes.
const (
	SensitiveMonitor SensitiveData = "monitor"
	SensitiveBlock   SensitiveData = "block"
	SensitiveOff     SensitiveData = "off"
)

// AgentCheck is the answer of an agent verifier.
type AgentCheck struct {
	Verified bool
	Blocked  bool
	Reason   string
}

// ContentFindings are what the content check found.
type ContentFindings struct {
	PromptInjection bool
	SensitiveData   bool
}

// RateTable holds per-process token buckets, the oldest dropped past the
// cap.
type RateTable struct {
	cap     int
	mu      sync.Mutex
	buckets map[string]*list.Element
	order   *list.List
}

type bucket struct {
	key    string
	tokens float64
	at     float64
}

// NewRateTable makes a table (cap 0: 10 000 buckets).
func NewRateTable(cap int) *RateTable {
	if cap <= 0 {
		cap = 10_000
	}
	return &RateTable{cap: cap, buckets: map[string]*list.Element{}, order: list.New()}
}

// Take takes a token from key's bucket; false when it is empty.
func (t *RateTable) Take(key string, rps, burst, nowMs float64) bool {
	size := burst
	if size <= 0 {
		size = math.Ceil(rps)
	}
	size = math.Max(size, 1)
	t.mu.Lock()
	defer t.mu.Unlock()
	e, ok := t.buckets[key]
	var b *bucket
	if !ok {
		if len(t.buckets) >= t.cap {
			if old := t.order.Front(); old != nil {
				t.order.Remove(old)
				delete(t.buckets, old.Value.(*bucket).key)
			}
		}
		b = &bucket{key: key, tokens: size, at: nowMs}
		t.buckets[key] = t.order.PushBack(b)
	} else {
		b = e.Value.(*bucket)
		b.tokens = math.Min(size, b.tokens+((nowMs-b.at)/1000)*rps)
		b.at = nowMs
	}
	if b.tokens >= 1 {
		b.tokens--
		return true
	}
	return false
}

type input struct {
	policy         *Policy
	compiled       *compiled
	facts          *Facts
	mode           Mode
	failMode       FailMode
	agent          *AgentCheck
	trapHit        bool
	classification *clienttype.Classification
	content        ContentFindings
	sensitiveData  SensitiveData
	rates          *RateTable
	nowMs          float64
	sharedOver     map[string]bool
}

func inAny(ip string, nets []netRange) bool {
	if ip == "" {
		return false
	}
	for _, n := range nets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

func isTrusted(c *compiled, ip string) bool { return c != nil && inAny(ip, c.allow) }

// PathUnder says whether path is prefix or below it on a segment boundary.
func PathUnder(path, prefix string) bool {
	if prefix == "/" || path == prefix {
		return true
	}
	if prefix[len(prefix)-1] == '/' {
		return len(path) >= len(prefix) && path[:len(prefix)] == prefix
	}
	return len(path) > len(prefix) && path[:len(prefix)] == prefix && path[len(prefix)] == '/'
}

func geoMatches(r *Rule, f *Facts) bool {
	if len(r.Countries) == 0 && len(r.ASNs) == 0 {
		return true
	}
	if f.Country == "" && f.ASN == 0 {
		return false
	}
	inside := f.Country != "" && contains(r.Countries, f.Country)
	if !inside && f.ASN != 0 {
		for _, a := range r.ASNs {
			inside = inside || a == f.ASN
		}
	}
	if r.Except {
		return !inside
	}
	return inside
}

func matches(r *Rule, in *input, rnets []netRange) bool {
	f := in.facts
	if len(r.CIDRs) > 0 && !inAny(f.IP, rnets) {
		return false
	}
	if !geoMatches(r, f) {
		return false
	}
	if len(r.Paths) > 0 {
		any := false
		for _, p := range r.Paths {
			any = any || PathUnder(f.Path, p)
		}
		if !any {
			return false
		}
	}
	if len(r.Methods) > 0 && !contains(r.Methods, f.Method) {
		return false
	}
	if len(r.ClientTypes) > 0 && (in.classification == nil || !ClientTypeMatches(r.ClientTypes, in.classification.ClientType)) {
		return false
	}
	if len(r.Attacks) > 0 && !(contains(r.Attacks, "prompt_injection") && in.content.PromptInjection) {
		return false
	}
	return true
}

func rateRulesFor(in *input) []*Rule {
	if in.policy == nil {
		return nil
	}
	var out []*Rule
	for i := range in.policy.Rules {
		r := &in.policy.Rules[i]
		if r.Rate != nil && matches(r, in, in.compiled.rules[i]) {
			out = append(out, r)
		}
	}
	return out
}

func failResult(fail FailMode, reason string, mode Mode) Result {
	d := Allow
	if fail == FailClosed {
		d = Deny
	}
	return finish(newResult(d, []string{reason}, nil, 0), mode)
}

func finish(r Result, mode Mode) Result {
	if mode == Monitor && r.Decision != Allow {
		r.WouldBe = r.Decision
		r.Decision = Allow
	}
	return r
}

func decide(in *input) (out Result) {
	defer func() {
		if recover() != nil {
			out = failResult(in.failMode, "error", in.mode)
		}
	}()
	mode := in.mode
	policy, c := in.policy, in.compiled
	if policy == nil {
		return failResult(in.failMode, "policy_unavailable", mode)
	}
	if policy.KillSwitch {
		return newResult(Allow, []string{"kill_switch"}, nil, 0)
	}
	f := in.facts
	reasons := []string{}
	ruleIDs := []string{}
	verified := in.agent != nil && in.agent.Verified
	clientType := ""
	switch {
	case verified:
		clientType = clienttype.VerifiedAgent
	case in.trapHit:
		clientType = clienttype.SuspectedAIAgent
	case in.classification != nil:
		clientType = in.classification.ClientType
	}
	result := func(d Verdict, ttl int) Result {
		r := newResult(d, reasons, ruleIDs, ttl)
		r.ClientType = clientType
		return finish(r, mode)
	}
	ip := f.IP
	trusted := inAny(ip, c.allow)
	exempt := trusted || verified
	if in.classification != nil && !verified && !in.trapHit {
		for i, r := range in.classification.Reasons {
			if i >= 8 {
				break
			}
			reasons = append(reasons, "client:"+r)
		}
	}
	if !trusted && inAny(ip, c.deny) {
		reasons = append(reasons, "deny_list")
		return result(Deny, ListTTL)
	}
	if in.agent != nil && in.agent.Blocked {
		reasons = append(reasons, "agent_policy")
		if in.agent.Reason != "" {
			reasons = append(reasons, "agent:"+in.agent.Reason)
		}
		return result(Deny, 0)
	}
	if verified {
		reasons = append(reasons, "agent_verified")
	} else if in.agent != nil && in.agent.Reason != "" {
		reasons = append(reasons, "agent:"+in.agent.Reason)
	}
	if in.trapHit && !exempt {
		reasons = append(reasons, "trap_hit")
		if policy.Traps.Action != "monitor" {
			d := Challenge
			if policy.Traps.Action == "block" {
				d = Deny
			}
			return result(d, policy.Traps.TTLSeconds)
		}
	}
	if !exempt && inAny(ip, c.challenge) {
		reasons = append(reasons, "challenge_list")
		return result(Challenge, ListTTL)
	}
	if in.content.PromptInjection {
		reasons = append(reasons, "prompt_injection")
	}
	decision := Allow
	ttl := 0
	for i := range policy.Rules {
		rule := &policy.Rules[i]
		if !matches(rule, in, c.rules[i]) {
			continue
		}
		if rule.Rate != nil {
			if ip == "" {
				continue
			}
			over, asked := in.sharedOver[rule.ID]
			if !asked {
				over = !in.rates.Take(rule.ID+"|"+ip, rule.Rate.RPS, float64(rule.Rate.Burst), in.nowMs)
			}
			if !over {
				continue
			}
			reasons = append(reasons, "rate_limit")
			ttl = int(math.Max(math.Ceil(1/rule.Rate.RPS), 1))
		}
		ruleIDs = append(ruleIDs, rule.ID)
		if rule.Action == ActionAllow {
			reasons = append(reasons, "rule:allow")
			return result(Allow, 0)
		}
		if rule.Action == ActionMonitor || exempt {
			if exempt && rule.Action != ActionMonitor {
				reasons = append(reasons, "rule:"+string(rule.Action)+":exempt")
			} else {
				reasons = append(reasons, "rule:monitor")
			}
			continue
		}
		reasons = append(reasons, "rule:"+string(rule.Action))
		if rule.Action == ActionBlock {
			decision = Deny
		} else {
			decision = Challenge
		}
		break
	}
	if in.content.SensitiveData {
		reasons = append(reasons, "sensitive_data")
		if in.sensitiveData == SensitiveBlock && !exempt && Deny.rank() > decision.rank() {
			decision = Deny
		}
	}
	if decision == Allow {
		ttl = 0
	}
	return result(decision, ttl)
}
