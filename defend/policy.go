package defend

import (
	"encoding/json"
	"math"
	"strings"
	"time"
	"unicode"

	"github.com/Shield360-AI/shield360-go/clienttype"
	"github.com/Shield360-AI/shield360-go/rasp"
)

// The signed policy (typ shield360-defend+jws). Anything malformed is
// dropped, never widened: a rule whose condition cannot be read is left out
// entirely, a list entry that is not an address is skipped. Port of
// defend/policy.ts.

// JWSType is the JWS typ of the signed policy.
const JWSType = "shield360-defend+jws"

// PolicyPath is where the policy is fetched.
const PolicyPath = "/api/defend/policy"

const (
	maxRules     = 200
	maxList      = 2000
	maxCIDRs     = 50
	maxPaths     = 10
	maxPathLen   = 256
	maxMethods   = 10
	maxCountries = 50
	maxASNs      = 50
	maxAttacks   = 16
	maxRPS       = 100_000.0
	maxBurst     = 1_000_000
	// DefaultTrapTTL is the trap TTL (seconds) when the policy sets none.
	DefaultTrapTTL = 900
	// MaxTrapTTL is the longest trap TTL (seconds).
	MaxTrapTTL = 86_400
)

// RuleAction is what a rule does when it matches.
type RuleAction string

// The rule actions. Monitor only adds its reason.
const (
	ActionBlock     RuleAction = "block"
	ActionChallenge RuleAction = "challenge"
	ActionAllow     RuleAction = "allow"
	ActionMonitor   RuleAction = "monitor"
)

// Rate is at most RPS requests a second per client, with a burst (0:
// ceil(RPS)).
type Rate struct {
	RPS   float64
	Burst int
}

// Rule is one rule. Every condition set must match; an empty list is no
// condition.
type Rule struct {
	ID        string
	Action    RuleAction
	CIDRs     []string
	Countries []string
	ASNs      []uint32
	// Except is everyone outside the countries and networks named.
	Except bool
	// Paths are path prefixes, on a segment boundary.
	Paths   []string
	Methods []string
	// Attacks: prompt_injection matches the content the caller passed.
	Attacks     []string
	ClientTypes []string
	Rate        *Rate
}

// TrapSettings say what a trap hit does: Action block (the default),
// challenge or monitor, for TTLSeconds.
type TrapSettings struct {
	Action     string
	TTLSeconds int
}

// Policy is the Defend policy.
type Policy struct {
	Version string
	// Exp is in seconds.
	Exp          float64
	ListsVersion string
	KillSwitch   bool
	Rules        []Rule
	// Deny, Challenge and Allow are address ranges; allowed (trusted)
	// clients are never trapped or stopped.
	Deny, Challenge, Allow []string
	Traps                  TrapSettings
	// Honeypots is nil when off.
	Honeypots *HoneypotSettings
	// EdgeKeys verify Edge's context header (protection triangle).
	EdgeKeys []rasp.EdgeKey
}

// NewPolicy is a policy with defaults, for tests and apps that build one by
// hand: version v1, valid for an hour, nothing denied.
func NewPolicy() *Policy {
	return &Policy{
		Version:      "v1",
		Exp:          float64(time.Now().Unix() + 3600),
		ListsVersion: "l1",
		Traps:        TrapSettings{Action: "block", TTLSeconds: DefaultTrapTTL},
	}
}

func isRuleID(s string) bool {
	if s == "" || len(s) > 48 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		ok := c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || i > 0 && (c == '_' || c == '-')
		if !ok {
			return false
		}
	}
	return true
}

func allBytes(s string, ok func(byte) bool) bool {
	for i := 0; i < len(s); i++ {
		if !ok(s[i]) {
			return false
		}
	}
	return true
}

func upper(c byte) bool { return c >= 'A' && c <= 'Z' }

func isMethod(s string) bool { return len(s) >= 3 && len(s) <= 10 && allBytes(s, upper) }

func isCountry(s string) bool { return len(s) == 2 && allBytes(s, upper) }

func isAttack(s string) bool {
	return len(s) >= 1 && len(s) <= 32 && allBytes(s, func(c byte) bool { return c >= 'a' && c <= 'z' || c == '_' })
}

func isCIDR(s string) bool {
	if len(s) > 64 {
		return false
	}
	_, ok := rasp.ParseIPNet(s)
	return ok
}

func isPath(s string) bool {
	if len(s) > maxPathLen || !strings.HasPrefix(s, "/") {
		return false
	}
	for _, r := range s {
		if unicode.IsSpace(r) || strings.ContainsRune("?#\"'\\", r) {
			return false
		}
	}
	return true
}

func isClientType(s string) bool {
	for _, t := range clienttype.Types {
		if t == s {
			return true
		}
	}
	return false
}

func isNull(raw json.RawMessage) bool {
	return len(raw) == 0 || string(raw) == "null"
}

// stringList reads a list of distinct strings, each passing ok, at most max
// read; empty for null or absent, false when unreadable.
func stringList(raw json.RawMessage, max int, ok func(string) bool) ([]string, bool) {
	if isNull(raw) {
		return []string{}, true
	}
	var list []any
	if json.Unmarshal(raw, &list) != nil {
		return nil, false
	}
	out := []string{}
	for i, x := range list {
		if i >= max {
			break
		}
		s, isStr := x.(string)
		if !isStr || !ok(s) {
			return nil, false
		}
		if !contains(out, s) {
			out = append(out, s)
		}
	}
	return out, true
}

// ClientTypeMatches reports whether a rule's client types cover a
// classified client. Scanner and AIAttackAgent are subtypes of
// UnverifiedAutomation (sdk/rasp/README.md "AI attack agents"): a rule naming
// unverified_automation still matches attack tools; a rule naming a subtype
// matches only it.
func ClientTypeMatches(ruleTypes []string, clientType string) bool {
	if clientType == "" {
		return false
	}
	if contains(ruleTypes, clientType) {
		return true
	}
	return (clientType == clienttype.Scanner || clientType == clienttype.AIAttackAgent) && contains(ruleTypes, clienttype.UnverifiedAutomation)
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

// wholeNumber reads a JSON integer (no fraction or exponent).
func wholeNumber(raw json.RawMessage) (float64, bool) {
	s := strings.TrimSpace(string(raw))
	if s == "" || strings.ContainsAny(s, ".eE") {
		return 0, false
	}
	var f float64
	if json.Unmarshal(raw, &f) != nil {
		return 0, false
	}
	return f, true
}

// ParseRule reads one rule; false when any of its conditions cannot be read
// (it is then not enforced at all).
func ParseRule(raw json.RawMessage) (Rule, bool) {
	var m map[string]json.RawMessage
	if json.Unmarshal(raw, &m) != nil || m == nil {
		return Rule{}, false
	}
	var r Rule
	if json.Unmarshal(m["id"], &r.ID) != nil || !isRuleID(r.ID) {
		return Rule{}, false
	}
	var action string
	if json.Unmarshal(m["action"], &action) != nil {
		return Rule{}, false
	}
	switch RuleAction(action) {
	case ActionBlock, ActionChallenge, ActionAllow, ActionMonitor:
		r.Action = RuleAction(action)
	default:
		return Rule{}, false
	}
	var ok bool
	if r.CIDRs, ok = stringList(m["cidrs"], maxCIDRs, isCIDR); !ok {
		return Rule{}, false
	}
	if r.Countries, ok = stringList(m["countries"], maxCountries, isCountry); !ok {
		return Rule{}, false
	}
	if r.Paths, ok = stringList(m["paths"], maxPaths, isPath); !ok {
		return Rule{}, false
	}
	if r.Methods, ok = stringList(m["methods"], maxMethods, isMethod); !ok {
		return Rule{}, false
	}
	if r.Attacks, ok = stringList(m["attacks"], maxAttacks, isAttack); !ok {
		return Rule{}, false
	}
	if r.ClientTypes, ok = stringList(m["clientTypes"], len(clienttype.Types), isClientType); !ok {
		return Rule{}, false
	}
	if !isNull(m["asns"]) {
		var list []json.RawMessage
		if json.Unmarshal(m["asns"], &list) != nil {
			return Rule{}, false
		}
		for _, x := range list {
			n, whole := wholeNumber(x)
			if !whole || n <= 0 || n > 4_294_967_295 {
				return Rule{}, false
			}
			r.ASNs = append(r.ASNs, uint32(n))
		}
		if len(r.ASNs) > maxASNs {
			r.ASNs = r.ASNs[:maxASNs]
		}
	}
	if e, has := m["except"]; has {
		if json.Unmarshal(e, &r.Except) != nil || isNull(e) {
			return Rule{}, false
		}
	}
	// "Everyone outside" with nothing named would match everyone: refused.
	if r.Except && len(r.Countries) == 0 && len(r.ASNs) == 0 {
		return Rule{}, false
	}
	if rr, has := m["rate"]; has {
		var rm map[string]json.RawMessage
		if json.Unmarshal(rr, &rm) != nil || rm == nil {
			return Rule{}, false
		}
		var rps float64
		if json.Unmarshal(rm["rps"], &rps) != nil || math.IsNaN(rps) || math.IsInf(rps, 0) || rps <= 0 || rps > maxRPS {
			return Rule{}, false
		}
		rate := &Rate{RPS: rps}
		if b, has := rm["burst"]; has {
			n, whole := wholeNumber(b)
			if !whole || n < 0 || n > maxBurst {
				return Rule{}, false
			}
			rate.Burst = int(n)
		}
		r.Rate = rate
	}
	for i, p := range r.Paths {
		if len(p) > 1 && strings.HasSuffix(p, "/") {
			r.Paths[i] = p[:len(p)-1]
		}
	}
	return r, true
}

func addressList(raw json.RawMessage) []string {
	var list []any
	_ = json.Unmarshal(raw, &list)
	out := []string{}
	for _, x := range list {
		if len(out) >= maxList {
			break
		}
		if s, ok := x.(string); ok && isCIDR(s) && !contains(out, s) {
			out = append(out, s)
		}
	}
	return out
}

// ParsePolicy reads the policy from verified claims (JSON); nil when the
// claims hold no usable policy.
func ParsePolicy(claims []byte) *Policy {
	var m map[string]json.RawMessage
	if json.Unmarshal(claims, &m) != nil || m == nil {
		return nil
	}
	p := &Policy{}
	if json.Unmarshal(m["version"], &p.Version) != nil {
		return nil
	}
	var exp any
	if json.Unmarshal(m["exp"], &exp) != nil {
		return nil
	}
	f, ok := exp.(float64)
	if !ok {
		return nil
	}
	p.Exp = f
	var rules []json.RawMessage
	_ = json.Unmarshal(m["rules"], &rules)
	p.Rules = []Rule{}
	for i, raw := range rules {
		if i >= maxRules {
			break
		}
		if r, ok := ParseRule(raw); ok {
			dup := false
			for _, x := range p.Rules {
				dup = dup || x.ID == r.ID
			}
			if !dup {
				p.Rules = append(p.Rules, r)
			}
		}
	}
	var t map[string]json.RawMessage
	_ = json.Unmarshal(m["traps"], &t)
	// Absent: block. A trap hit is near certain (no person or verified
	// agent ever reaches one), so it stops the client at once.
	var action string
	_ = json.Unmarshal(t["action"], &action)
	if action != "monitor" && action != "challenge" {
		action = "block"
	}
	ttl := DefaultTrapTTL
	var x float64
	if json.Unmarshal(t["ttlSeconds"], &x) == nil && !math.IsInf(x, 0) && x >= 1 {
		ttl = int(math.Min(math.Floor(x), MaxTrapTTL))
	}
	p.Traps = TrapSettings{Action: action, TTLSeconds: ttl}
	var lv string
	if json.Unmarshal(m["listsVersion"], &lv) == nil {
		if r := []rune(lv); len(r) > 64 {
			lv = string(r[:64])
		}
		p.ListsVersion = lv
	}
	var ks bool
	p.KillSwitch = json.Unmarshal(m["killSwitch"], &ks) == nil && ks
	p.Deny = addressList(m["deny"])
	p.Challenge = addressList(m["challenge"])
	p.Allow = addressList(m["allow"])
	p.Honeypots = ParseHoneypots(m["honeypots"])
	p.EdgeKeys = rasp.ParseEdgeKeys(m["edgeContext"])
	return p
}

type netRange = rasp.IPNet

// compiled is a policy's address lists, parsed once.
type compiled struct {
	deny, challenge, allow []netRange
	rules                  [][]netRange
}

func nets(list []string) []netRange {
	var out []netRange
	for _, s := range list {
		if n, ok := rasp.ParseIPNet(s); ok {
			out = append(out, n)
		}
	}
	return out
}

func compile(p *Policy) *compiled {
	c := &compiled{deny: nets(p.Deny), challenge: nets(p.Challenge), allow: nets(p.Allow)}
	for _, r := range p.Rules {
		c.rules = append(c.rules, nets(r.CIDRs))
	}
	return c
}
