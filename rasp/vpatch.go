package rasp

import (
	"encoding/json"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
)

// Virtual patches (README "Virtual patches"): rules that match the documented
// request shape of a public advisory. The one place RASP matches request
// signatures; every other check is structural. Run once per request, when its
// input is captured, before the handler.
//
// The built-in list is data/default-rules.json, a byte-identical copy of
// sdk/rasp/rules/default-rules.json. The signed config's rules replace it
// when present.

// MatchClause is one clause of a rule's all-of match.
type MatchClause struct {
	Target     string
	Op         string
	Values     []string
	Value      string
	IgnoreCase bool
}

// VirtualPatchRule is one virtual patch.
type VirtualPatchRule struct {
	ID              string
	Title           string
	CVEs            []string
	Severity        string
	Example         bool
	Runtimes        []string // nil = every runtime
	RuntimeVersions map[string][][2]string
	Action          Mode
	Match           []MatchClause
}

// VpRequest is the request as the rules see it. Header names are lower-case.
type VpRequest struct {
	Method string
	Path   string
	// Query is the raw query string, without ?.
	Query   string
	Headers map[string]string
	// Cookie is the raw Cookie header.
	Cookie string
	// Body is the raw body text, or the JSON of a parsed body; "" when unknown.
	Body string
}

const (
	// MaxVpText is how much of the body (and of a regex target) rules see.
	MaxVpText  = 64 * 1024
	maxPattern = 1024
	// Runtime is this SDK's runtime name in rules and events.
	Runtime = "go"
)

// BuiltInRules and BuiltInRulesVersion are the embedded default rules.
var BuiltInRules, BuiltInRulesVersion = func() ([]VirtualPatchRule, string) {
	var f struct {
		Version string            `json:"version"`
		Rules   []json.RawMessage `json:"rules"`
	}
	_ = json.Unmarshal(defaultRulesJSON, &f)
	return parseRules(f.Rules), f.Version
}()

// RuntimeVersion is the Go version rules compare (runtime.Version without
// the "go" prefix).
func RuntimeVersion() string {
	v := strings.TrimPrefix(runtime.Version(), "go")
	if i := strings.IndexAny(v, " +"); i >= 0 {
		v = v[:i]
	}
	return v
}

func stringsOf(raw json.RawMessage) ([]string, bool) {
	var vals []any
	if json.Unmarshal(raw, &vals) != nil {
		return nil, false
	}
	out := []string{}
	for _, v := range vals {
		if s, ok := v.(string); ok {
			out = append(out, s)
		}
	}
	return out, true
}

// parseRule reads one rule leniently: a rule without a string id or a match
// array is dropped (false); malformed optional fields are ignored.
func parseRule(raw json.RawMessage) (VirtualPatchRule, bool) {
	var m map[string]json.RawMessage
	if json.Unmarshal(raw, &m) != nil || m == nil {
		return VirtualPatchRule{}, false
	}
	var r VirtualPatchRule
	if json.Unmarshal(m["id"], &r.ID) != nil {
		return r, false
	}
	var clauses []json.RawMessage
	if json.Unmarshal(m["match"], &clauses) != nil || clauses == nil {
		return r, false
	}
	_ = json.Unmarshal(m["title"], &r.Title)
	_ = json.Unmarshal(m["severity"], &r.Severity)
	_ = json.Unmarshal(m["example"], &r.Example)
	if cves, ok := stringsOf(m["cves"]); ok {
		r.CVEs = cves
	}
	if rts, ok := stringsOf(m["runtimes"]); ok {
		r.Runtimes = rts
	}
	var action string
	if json.Unmarshal(m["action"], &action) == nil {
		r.Action = Mode(action)
	}
	var rv map[string]json.RawMessage
	if json.Unmarshal(m["runtimeVersions"], &rv) == nil && rv != nil {
		r.RuntimeVersions = map[string][][2]string{}
		for rt, rangesRaw := range rv {
			var ranges []json.RawMessage
			if json.Unmarshal(rangesRaw, &ranges) != nil {
				continue // not an array: the rule is not version-limited for rt
			}
			list := [][2]string{}
			for _, rg := range ranges {
				var pair []any
				if json.Unmarshal(rg, &pair) != nil {
					continue
				}
				var p [2]string
				for i := 0; i < 2; i++ {
					if i < len(pair) {
						p[i] = jsString(pair[i])
					} else {
						p[i] = "undefined"
					}
				}
				list = append(list, p)
			}
			r.RuntimeVersions[rt] = list
		}
	}
	for _, c := range clauses {
		var cm map[string]json.RawMessage
		if json.Unmarshal(c, &cm) != nil || cm == nil {
			r.Match = append(r.Match, MatchClause{}) // an invalid clause never matches
			continue
		}
		var mc MatchClause
		_ = json.Unmarshal(cm["target"], &mc.Target)
		_ = json.Unmarshal(cm["op"], &mc.Op)
		_ = json.Unmarshal(cm["value"], &mc.Value)
		_ = json.Unmarshal(cm["ignoreCase"], &mc.IgnoreCase)
		if vals, ok := stringsOf(cm["values"]); ok {
			mc.Values = vals
		}
		r.Match = append(r.Match, mc)
	}
	return r, true
}

// jsString is JavaScript's String(v) for JSON scalars.
func jsString(v any) string {
	switch x := v.(type) {
	case string:
		return x
	case float64:
		return strconv.FormatFloat(x, 'f', -1, 64)
	case bool:
		return strconv.FormatBool(x)
	case nil:
		return "null"
	}
	return ""
}

func parseRules(raw []json.RawMessage) []VirtualPatchRule {
	out := []VirtualPatchRule{}
	for _, r := range raw {
		if rule, ok := parseRule(r); ok {
			out = append(out, rule)
		}
	}
	return out
}

// leadingInt is JavaScript's parseInt(x, 10) || 0.
func leadingInt(s string) int {
	s = strings.TrimLeft(s, " \t\n\r")
	neg := false
	if strings.HasPrefix(s, "-") || strings.HasPrefix(s, "+") {
		neg = s[0] == '-'
		s = s[1:]
	}
	n := 0
	for i := 0; i < len(s) && isDigitByte(s[i]); i++ {
		n = n*10 + int(s[i]-'0')
		if n > 1<<40 {
			break
		}
	}
	if neg {
		return -n
	}
	return n
}

func cmpVersion(a, b string) int {
	pa, pb := strings.Split(a, "."), strings.Split(b, ".")
	for i := 0; i < max(len(pa), len(pb)); i++ {
		x, y := 0, 0
		if i < len(pa) {
			x = leadingInt(pa[i])
		}
		if i < len(pb) {
			y = leadingInt(pb[i])
		}
		if x != y {
			return x - y
		}
	}
	return 0
}

// RuleApplies reports whether the rule applies in this runtime and version
// ([from, to) ranges).
func RuleApplies(rule VirtualPatchRule, rt, version string) bool {
	if rule.Runtimes != nil {
		in := false
		for _, r := range rule.Runtimes {
			in = in || r == rt
		}
		if !in {
			return false
		}
	}
	if ranges, ok := rule.RuntimeVersions[rt]; ok {
		for _, r := range ranges {
			if cmpVersion(version, r[0]) >= 0 && cmpVersion(version, r[1]) < 0 {
				return true
			}
		}
		return false
	}
	return true
}

// NeedsBody reports whether a rule reads the body (it can only be judged once
// the body is known).
func NeedsBody(rule VirtualPatchRule) bool {
	for _, c := range rule.Match {
		if c.Target == "body" || c.Target == "request" {
			return true
		}
	}
	return false
}

func capText(s string) string {
	if len(s) > MaxVpText {
		return truncChars(s, MaxVpText)
	}
	return s
}

func targetText(req *VpRequest, target string) (string, bool) {
	switch target {
	case "method":
		return req.Method, true
	case "path":
		return req.Path, true
	case "query":
		return req.Query, true
	case "cookie":
		return req.Cookie, true
	case "body":
		return capText(req.Body), true
	case "request":
		return req.Path + "?" + req.Query + "\n" + req.Cookie + "\n" + capText(req.Body), true
	}
	if strings.HasPrefix(target, "header:") {
		v, ok := req.Headers[strings.ToLower(target[7:])]
		return v, ok
	}
	return "", false
}

var (
	regexMu    sync.Mutex
	regexCache = map[string]*regexp.Regexp{}
	refusedRe  = regexp.MustCompile(`\\[1-9]|\\k<|\(\?<?[=!]`)
)

// compileRule compiles a rule pattern; it refuses backreferences and
// lookaround (contract) and overlong patterns. Go's regexp (RE2) cannot
// express either anyway, and never backtracks.
func compileRule(p string) *regexp.Regexp {
	regexMu.Lock()
	defer regexMu.Unlock()
	if re, ok := regexCache[p]; ok {
		return re
	}
	var re *regexp.Regexp
	if len(p) <= maxPattern && !refusedRe.MatchString(p) {
		re, _ = regexp.Compile(p)
	}
	if len(regexCache) > 512 {
		regexCache = map[string]*regexp.Regexp{}
	}
	regexCache[p] = re
	return re
}

// ClauseMatches reports whether one clause matches the request.
func ClauseMatches(req *VpRequest, c MatchClause) bool {
	if c.Target == "" {
		return false
	}
	text, present := targetText(req, c.Target)
	if c.Op == "present" {
		return present
	}
	if !present {
		return false
	}
	switch c.Op {
	case "equals":
		lt := strings.ToLower(text)
		for _, v := range c.Values {
			if strings.ToLower(v) == lt {
				return true
			}
		}
	case "contains_any":
		t := text
		if c.IgnoreCase {
			t = strings.ToLower(text)
		}
		for _, v := range c.Values {
			if v == "" {
				continue
			}
			if c.IgnoreCase {
				v = strings.ToLower(v)
			}
			if strings.Contains(t, v) {
				return true
			}
		}
	case "regex":
		if c.Value == "" {
			return false
		}
		if re := compileRule(c.Value); re != nil {
			return re.MatchString(capText(text))
		}
	}
	return false
}

// VpPhase selects which rules a match judges.
type VpPhase string

// The phases: head rules never read the body; body rules do; all is both.
const (
	PhaseAll  VpPhase = "all"
	PhaseHead VpPhase = "head"
	PhaseBody VpPhase = "body"
)

// MatchVirtualPatches returns the first rule the request matches, as a
// finding, judged in runtime rt at version.
func MatchVirtualPatches(req *VpRequest, rules []VirtualPatchRule, phase VpPhase, rt, version string) *Finding {
	for _, r := range rules {
		if r.ID == "" || len(r.Match) == 0 {
			continue
		}
		if phase != PhaseAll && NeedsBody(r) != (phase == PhaseBody) {
			continue
		}
		if !RuleApplies(r, rt, version) {
			continue
		}
		all := true
		for _, c := range r.Match {
			if !ClauseMatches(req, c) {
				all = false
				break
			}
		}
		if !all {
			continue
		}
		action := ModeBlock
		if r.Action == ModeOff || r.Action == ModeMonitor {
			action = r.Action
		}
		f := &Finding{Attack: VirtualPatch, Rule: r.ID, Action: action}
		if len(r.CVEs) > 0 {
			f.CVE = r.CVEs[0]
		}
		return f
	}
	return nil
}
