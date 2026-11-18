package rasp

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"sync"
)

// Custom rules (README "Custom rules"): the organization's own rules,
// written in the expression language of ruleexpr.go and delivered inside the
// signed config (customRules). They are data: each expression is parsed and
// type-checked when the config arrives and evaluated against the request (or
// a built-in finding) as a value. An invalid rule is skipped with one
// warning and never breaks the config; evaluation fails open.

// Custom rule limits.
const (
	MaxCustomRules   = 64
	MaxRuleApps      = 32
	CustomRulePrefix = "custom."
)

// customRuleID is lower-case, so the event rule custom.<id> fits the
// platform's rule shape.
var customRuleID = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,47}$`)

// CustomRule is a compiled custom rule.
type CustomRule struct {
	ID     string
	Name   string
	Action string // block, monitor or alert
	Apps   []string
	Expr   *RuleExpr
}

// SkippedRule says why a rule of the signed config was left out.
type SkippedRule struct {
	Index  int
	ID     string
	Reason string
}

var (
	ruleWarnMu sync.Mutex
	ruleWarned = map[string]bool{}
)

func defaultRuleWarn(s SkippedRule) {
	name := fmt.Sprintf("#%d", s.Index+1)
	if s.ID != "" {
		name = `"` + s.ID + `"`
	}
	logf("Shield360 RASP: custom rule %s was skipped (%s); the other rules apply.", name, s.Reason)
}

// resetCustomRuleWarnings lets the once-per-rule warnings fire again (tests).
func resetCustomRuleWarnings() {
	ruleWarnMu.Lock()
	ruleWarned = map[string]bool{}
	ruleWarnMu.Unlock()
}

// ParseCustomRules returns the rules of a signed config that apply to app:
// invalid rules are skipped (one warning per rule and reason, per process),
// disabled rules and rules scoped to other apps are left out silently. At
// most 64. warn nil logs.
func ParseCustomRules(raw []json.RawMessage, app string, warn func(SkippedRule)) []*CustomRule {
	if warn == nil {
		warn = defaultRuleWarn
	}
	var out []*CustomRule
	ids := map[string]bool{}
	skip := func(s SkippedRule, expression any) {
		idx := s.ID
		if idx == "" {
			idx = fmt.Sprint(s.Index)
		}
		e, _ := expression.(string)
		key := idx + "\x00" + s.Reason + "\x00" + e
		ruleWarnMu.Lock()
		seen := ruleWarned[key]
		if !seen {
			if len(ruleWarned) > 1024 {
				ruleWarned = map[string]bool{}
			}
			ruleWarned[key] = true
		}
		ruleWarnMu.Unlock()
		if !seen {
			func() {
				defer func() { _ = recover() }()
				warn(s)
			}()
		}
	}
	for index, item := range raw {
		var r map[string]any
		if json.Unmarshal(item, &r) != nil || r == nil {
			skip(SkippedRule{Index: index, Reason: "not an object"}, nil)
			continue
		}
		id, _ := r["id"].(string)
		if !customRuleID.MatchString(id) {
			skip(SkippedRule{Index: index, Reason: "invalid id"}, nil)
			continue
		}
		if ids[id] {
			skip(SkippedRule{Index: index, ID: id, Reason: "duplicate id"}, nil)
			continue
		}
		ids[id] = true
		enabled, ok := r["enabled"].(bool)
		if !ok {
			skip(SkippedRule{Index: index, ID: id, Reason: "invalid enabled flag"}, nil)
			continue
		}
		action, _ := r["action"].(string)
		if action != "block" && action != "monitor" && action != "alert" {
			skip(SkippedRule{Index: index, ID: id, Reason: "invalid action"}, nil)
			continue
		}
		name := id
		if v, present := r["name"]; present {
			s, ok := v.(string)
			if !ok {
				skip(SkippedRule{Index: index, ID: id, Reason: "invalid name"}, nil)
				continue
			}
			name = s
		}
		var apps []string
		if v := r["apps"]; v != nil {
			list, ok := v.([]any)
			if ok && len(list) <= MaxRuleApps {
				for _, a := range list {
					s, isStr := a.(string)
					if !isStr {
						ok = false
						break
					}
					apps = append(apps, s)
				}
			}
			if !ok || len(list) > MaxRuleApps {
				skip(SkippedRule{Index: index, ID: id, Reason: "invalid apps"}, nil)
				continue
			}
		}
		expr, err := CompileRuleExpr(r["expression"])
		if err != nil {
			skip(SkippedRule{Index: index, ID: id, Reason: "expression: " + err.Code}, r["expression"])
			continue
		}
		if !enabled {
			continue
		}
		if len(apps) > 0 && !containsString(apps, app) {
			continue
		}
		if len(out) >= MaxCustomRules {
			skip(SkippedRule{Index: index, ID: id, Reason: "more than 64 rules"}, nil)
			continue
		}
		out = append(out, &CustomRule{ID: id, Name: name, Action: action, Apps: apps, Expr: expr})
	}
	return out
}

func containsString(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

// customFinding is the finding a matched rule reports (attack type
// custom_rule, rule custom.<id>). alert reports like monitor (the platform
// raises the alert).
func customFinding(rule *CustomRule, input *Input) *Finding {
	action := ModeMonitor
	if rule.Action == "block" {
		action = ModeBlock
	}
	f := &Finding{Attack: CustomRuleAttack, Rule: CustomRulePrefix + rule.ID, Action: action}
	if input != nil {
		c := *input
		f.Input = &c
	}
	return f
}

// ruleState is the per-request custom rule state, kept on the context. Its
// lock is held while rules evaluate, so goroutines sharing a request share
// the matched set and the work budget safely.
type ruleState struct {
	mu      sync.Mutex
	matched map[string]bool
	budget  RuleBudget
}

func (c *Context) rules() *ruleState {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.ruleSt == nil {
		c.ruleSt = &ruleState{matched: map[string]bool{}, budget: RuleBudget{Steps: DefaultRuleBudget}}
	}
	return c.ruleSt
}

// requestSubject is the request as the language sees it (README "Custom
// rules: fields").
func requestSubject(c *Context, app string) *RuleSubject {
	s := &RuleSubject{App: &app}
	if c == nil {
		return s
	}
	inputs := c.Inputs()
	s.Inputs = append([]Input(nil), inputs...)
	if !c.inRequest {
		return s
	}
	req := &RuleRequest{Headers: map[string]string{}, Query: map[string]string{}, Body: map[string]string{}}
	c.mu.Lock()
	if c.vp != nil {
		for k, v := range c.vp.req.Headers {
			req.Headers[strings.ToLower(k)] = v
		}
	}
	ip := c.ip
	c.mu.Unlock()
	for _, in := range inputs {
		if in.Source != SourceRequest {
			continue
		}
		if k, ok := strings.CutPrefix(in.Key, "query."); ok {
			if _, dup := req.Query[k]; !dup {
				req.Query[k] = in.Value
			}
		} else if k, ok := strings.CutPrefix(in.Key, "body."); ok {
			if _, dup := req.Body[k]; !dup {
				req.Body[k] = in.Value
			}
		}
	}
	if c.method != "" {
		m := strings.ToUpper(c.method)
		req.Method = &m
	}
	if c.path != "" {
		p := c.path
		req.Path = &p
	}
	if route := c.Route(); route != "" {
		req.Route = &route
	} else if c.path != "" {
		route := RouteOf(c.path)
		req.Route = &route
	}
	if ip != "" {
		req.IP = &ip
	}
	s.Request = req
	return s
}

type ruleMatch struct {
	rule  *CustomRule
	input *Input
}

// matchRequestRules returns the request rules matching in a phase, in order.
// Head: every request rule that does not read the body. Body: rules that
// read the body, and rules reading input.* that did not match at head (the
// body added inputs). A rule matches at most once per request.
func matchRequestRules(rules []*CustomRule, c *Context, phase VpPhase, subject *RuleSubject) []ruleMatch {
	st := c.rules()
	st.mu.Lock()
	defer st.mu.Unlock()
	var out []ruleMatch
	for _, rule := range rules {
		e := rule.Expr
		if st.budget.Steps < 0 {
			break
		}
		if e.Phase != PhaseRequest || st.matched[rule.ID] {
			continue
		}
		if phase == PhaseHead && e.UsesBody {
			continue
		}
		if phase == PhaseBody && !(e.UsesBody || e.UsesInput) {
			continue
		}
		r := EvaluateRuleExpr(e, subject, &st.budget)
		if r.Exhausted {
			break
		}
		if !r.Matched {
			continue
		}
		st.matched[rule.ID] = true
		out = append(out, ruleMatch{rule, r.Input})
	}
	return out
}

// matchFindingRules returns the finding rules a built-in finding matches, in
// order.
func matchFindingRules(rules []*CustomRule, subject *RuleSubject, budget *RuleBudget) []ruleMatch {
	var out []ruleMatch
	for _, rule := range rules {
		if budget.Steps < 0 {
			break
		}
		if rule.Expr.Phase != PhaseFinding {
			continue
		}
		r := EvaluateRuleExpr(rule.Expr, subject, budget)
		if r.Exhausted {
			break
		}
		if r.Matched {
			out = append(out, ruleMatch{rule, r.Input})
		}
	}
	return out
}

// runRequestRules runs the custom request rules of a phase: each match is
// reported in order; the first that blocks returns the block error. Any
// other failure lets the request through.
func runRequestRules(c *Context, phase VpPhase, extra FindingExtra) error {
	var matches []ruleMatch
	func() {
		defer func() {
			if recover() != nil {
				matches = nil
			}
		}()
		rules := CustomRules()
		// Mode off skips custom rules: nothing is evaluated.
		if len(rules) == 0 || ModeFor(CustomRuleAttack) == ModeOff {
			return
		}
		matches = matchRequestRules(rules, c, phase, requestSubject(c, ApplicationName()))
	}()
	ctx := withContext(context.Background(), c)
	for _, m := range matches {
		if _, err := handleFindingSafe(ctx, customFinding(m.rule, m.input), extra); err != nil {
			return err
		}
	}
	return nil
}

// runFindingRules reports each custom finding rule a built-in finding
// matches and returns the block error of the first that blocks. Never
// panics.
func runFindingRules(ctx context.Context, rules []*CustomRule, app string, f *Finding, sink string, extra FindingExtra) (blocked error) {
	defer func() {
		if recover() != nil {
			blocked = nil
		}
	}()
	rc := FromContext(ctx)
	subject := requestSubject(rc, app)
	subject.Sink = &sink
	attack, rule := string(f.Attack), f.Rule
	subject.Attack = &RuleAttack{Type: &attack, Rule: &rule}
	var matches []ruleMatch
	if rc != nil {
		st := rc.rules()
		st.mu.Lock()
		matches = matchFindingRules(rules, subject, &st.budget)
		st.mu.Unlock()
	} else {
		matches = matchFindingRules(rules, subject, &RuleBudget{Steps: DefaultRuleBudget})
	}
	for _, m := range matches {
		in := m.input
		if in == nil {
			in = f.Input
		}
		if _, err := HandleFinding(ctx, customFinding(m.rule, in), sink, extra); err != nil {
			return err
		}
	}
	return nil
}
