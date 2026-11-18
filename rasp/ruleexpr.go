package rasp

import (
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"
)

// Custom rule expressions (README "Custom rules"): a small, sandboxed,
// CEL-style language with a fixed set of fields, string literals,
// comparison, `in`, a handful of string methods, a safe regular-expression
// subset matched in linear time, and CIDR matching, joined by &&, || and !.
// No loops, no function definitions, no I/O, nothing outside the fields.
// Expressions are parsed and type-checked once and evaluated as data;
// nothing downloaded is ever run as code.
//
// This is a port of sdk/typescript/src/rasp/rule-expr.ts (the platform's
// validator is byte-identical to it), with the same grammar, limits, error
// codes and regex engine (a Pike VM with the same step budget), so a rule
// the platform accepts runs identically here. testdata/custom-rules.json is
// the conformance corpus.

// RuleExprLimits are the hard limits, identical on the platform and in every
// SDK.
var RuleExprLimits = struct {
	ExpressionBytes, Depth, Nodes, StringBytes, ListItems int
	Regexes, RegexBytes, RegexAtoms, RegexRepeat          int
	MatchCodePoints                                       int
}{
	ExpressionBytes: 2048,
	Depth:           12,
	Nodes:           128,
	StringBytes:     1024,
	ListItems:       64,
	Regexes:         8,
	RegexBytes:      256,
	RegexAtoms:      256,
	RegexRepeat:     100,
	MatchCodePoints: 4096,
}

// DefaultRuleBudget is the regex VM steps one request may spend on custom
// rules.
const DefaultRuleBudget = 4_000_000

// RuleExprError is why an expression does not compile: Code is one of the
// contract's error codes (empty, too_long, syntax, depth, nodes,
// string_too_long, list_too_long, unknown_field, unknown_method, type,
// regex, too_many_regexes, cidr); Pos is a byte offset.
type RuleExprError struct {
	Code string
	Pos  int
}

func (e *RuleExprError) Error() string { return "rule expression: " + e.Code }

// ruleFields are the fields an expression may read: true for map fields.
var ruleFields = map[string]bool{
	"request.method":  false,
	"request.path":    false,
	"request.route":   false,
	"request.ip":      false,
	"request.headers": true,
	"request.query":   true,
	"request.body":    true,
	"input.value":     false,
	"input.key":       false,
	"input.source":    false,
	"sink.name":       false,
	"attack.type":     false,
	"attack.rule":     false,
	"app.name":        false,
}

// RuleContext is where an expression runs, which decides the fields it may
// read (README "Collector contexts"). The zero value is an app's RASP.
type RuleContext string

// The contexts of the contract.
const (
	// ContextApp: an app's RASP custom rules (the fields above).
	ContextApp RuleContext = ""
	// ContextAgentTool: a coding agent's tool call, judged by the collector's
	// hooks before it runs.
	ContextAgentTool RuleContext = "agent_tool"
	// ContextAIProxy: a request through the Shield360 AI proxy.
	ContextAIProxy RuleContext = "ai_proxy"
)

// collectorFields are the fields of each collector context. None is a map.
var collectorFields = map[RuleContext]map[string]bool{
	ContextAgentTool: {
		"tool.name":    false,
		"tool.command": false,
		"tool.path":    false,
		"agent.name":   false,
		"user.id":      false,
		"device.os":    false,
	},
	ContextAIProxy: {
		"ai.provider": false,
		"ai.model":    false,
		"ai.tokens":   false,
		"user.id":     false,
		"device.os":   false,
	},
}

// RuleContextFields are the field names an expression may read in ctx,
// sorted; nil for a context this SDK does not know.
func RuleContextFields(ctx RuleContext) []string {
	fields := ruleFields
	if ctx != ContextApp {
		var ok bool
		if fields, ok = collectorFields[ctx]; !ok {
			return nil
		}
	}
	out := make([]string, 0, len(fields))
	for f := range fields {
		out = append(out, f)
	}
	sort.Strings(out)
	return out
}

// RulePhase is when a rule runs.
type RulePhase string

// The phases of the contract.
const (
	PhaseRequest RulePhase = "request"
	PhaseFinding RulePhase = "finding"
)

type nodeKind uint8

const (
	nStr nodeKind = iota
	nBool
	nNull
	nField
	nNot
	nAnd
	nOr
	nCmp
	nIn
	nStrMethod
	nLower
	nMatches
	nCidr
)

type rnode struct {
	k nodeKind
	// s: a literal's value, a field's name, a comparison operator or a
	// string method's name.
	s      string
	key    string
	hasKey bool
	b      bool
	// xs: the operands (and/or), the operand (not, lower, methods, in), or
	// the two sides (cmp).
	xs    []*rnode
	items []string
	arg   string
	prog  []inst
	net   ipNet
}

// RuleExpr is a compiled expression.
type RuleExpr struct {
	ast *rnode
	// Fields are the field names read (without map keys), sorted.
	Fields []string
	// Phase is finding when the expression reads sink.* or attack.*.
	Phase RulePhase
	// UsesInput: reads input.*, so it is evaluated once per input.
	UsesInput bool
	// UsesBody: reads request.body[...].
	UsesBody bool
	// Context is the context the expression was compiled for.
	Context RuleContext
}

type exprError struct {
	code string
	pos  int
}

func fail(code string, pos int) { panic(exprError{code, pos}) }

// ---- lexer ------------------------------------------------------------------

type tokKind uint8

const (
	tIdent tokKind = iota
	tStr
	tOp
	tEOF
)

type tok struct {
	t   tokKind
	v   string
	pos int
}

func isIdentStart(c byte) bool { return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '_' }
func isIdentPart(c byte) bool  { return isIdentStart(c) || (c >= '0' && c <= '9') }

func hex4(s string) (int, bool) {
	if len(s) != 4 {
		return 0, false
	}
	for i := 0; i < 4; i++ {
		if !isHexByte(s[i]) {
			return 0, false
		}
	}
	n, err := strconv.ParseUint(s, 16, 32)
	return int(n), err == nil
}

// lexExpr reads the tokens. Every operator and quote is ASCII, so the source
// is read byte by byte; other bytes only ever appear inside strings.
func lexExpr(src string) []tok {
	var toks []tok
	i := 0
	for i < len(src) {
		c := src[i]
		if c == ' ' || c == '\t' || c == '\n' || c == '\r' {
			i++
			continue
		}
		start := i
		raw := (c == 'r' || c == 'R') && i+1 < len(src) && (src[i+1] == '"' || src[i+1] == '\'')
		if c == '"' || c == '\'' || raw {
			if raw {
				i++
			}
			quote := src[i]
			i++
			var b strings.Builder
			for {
				if i >= len(src) {
					fail("syntax", start)
				}
				d := src[i]
				if d == quote {
					i++
					break
				}
				if d < 0x20 {
					fail("syntax", i)
				}
				if d == '\\' && !raw {
					e := byteAt(src, i+1)
					switch e {
					case '\\', '"', '\'':
						b.WriteByte(e)
					case 'n':
						b.WriteByte('\n')
					case 'r':
						b.WriteByte('\r')
					case 't':
						b.WriteByte('\t')
					case 'u':
						h := ""
						if i+6 <= len(src) {
							h = src[i+2 : i+6]
						}
						code, ok := hex4(h)
						if !ok || (code >= 0xd800 && code <= 0xdfff) {
							fail("syntax", i)
						}
						b.WriteRune(rune(code))
						i += 4
					default:
						fail("syntax", i)
					}
					i += 2
					continue
				}
				b.WriteByte(d)
				i++
			}
			v := b.String()
			if len(v) > RuleExprLimits.StringBytes {
				fail("string_too_long", start)
			}
			toks = append(toks, tok{tStr, v, start})
			continue
		}
		if isIdentStart(c) {
			for i < len(src) && isIdentPart(src[i]) {
				i++
			}
			toks = append(toks, tok{tIdent, src[start:i], start})
			continue
		}
		if i+2 <= len(src) {
			switch two := src[i : i+2]; two {
			case "==", "!=", "<=", ">=", "&&", "||":
				toks = append(toks, tok{tOp, two, start})
				i += 2
				continue
			}
		}
		if strings.IndexByte("()[],.<>!", c) >= 0 {
			toks = append(toks, tok{tOp, string(c), start})
			i++
			continue
		}
		fail("syntax", i)
	}
	return append(toks, tok{tEOF, "", len(src)})
}

// ---- parser -----------------------------------------------------------------

type exprParser struct {
	// fields are the fields of the context being compiled for.
	fields  map[string]bool
	toks    []tok
	i       int
	nodes   int
	parens  int
	nots    int
	regexes int
}

func (p *exprParser) peek(o int) tok {
	k := p.i + o
	if k > len(p.toks)-1 {
		k = len(p.toks) - 1
	}
	return p.toks[k]
}

func (p *exprParser) next() tok {
	t := p.peek(0)
	if p.i < len(p.toks)-1 {
		p.i++
	}
	return t
}

func (p *exprParser) isOp(v string, o int) bool {
	t := p.peek(o)
	return t.t == tOp && t.v == v
}

func (p *exprParser) expectOp(v string) tok {
	t := p.next()
	if t.t != tOp || t.v != v {
		fail("syntax", t.pos)
	}
	return t
}

func (p *exprParser) count(n, pos int) {
	p.nodes += n
	if p.nodes > RuleExprLimits.Nodes {
		fail("nodes", pos)
	}
}

func (p *exprParser) parse() *rnode {
	n := p.or()
	if t := p.peek(0); t.t != tEOF {
		fail("syntax", t.pos)
	}
	return n
}

func (p *exprParser) or() *rnode {
	pos := p.peek(0).pos
	xs := []*rnode{p.and()}
	for p.isOp("||", 0) {
		p.next()
		xs = append(xs, p.and())
	}
	if len(xs) == 1 {
		return xs[0]
	}
	p.count(1, pos)
	return &rnode{k: nOr, xs: xs}
}

func (p *exprParser) and() *rnode {
	pos := p.peek(0).pos
	xs := []*rnode{p.relation()}
	for p.isOp("&&", 0) {
		p.next()
		xs = append(xs, p.relation())
	}
	if len(xs) == 1 {
		return xs[0]
	}
	p.count(1, pos)
	return &rnode{k: nAnd, xs: xs}
}

func (p *exprParser) relation() *rnode {
	l := p.unary()
	t := p.peek(0)
	if t.t == tOp {
		switch t.v {
		case "==", "!=", "<", "<=", ">", ">=":
			p.next()
			r := p.unary()
			p.count(1, t.pos)
			return &rnode{k: nCmp, s: t.v, xs: []*rnode{l, r}}
		}
	}
	if t.t == tIdent && t.v == "in" {
		p.next()
		p.expectOp("[")
		items := []string{}
		for !p.isOp("]", 0) {
			s := p.next()
			if s.t != tStr {
				fail("syntax", s.pos)
			}
			items = append(items, s.v)
			if len(items) > RuleExprLimits.ListItems {
				fail("list_too_long", s.pos)
			}
			if p.isOp(",", 0) {
				p.next()
			} else if !p.isOp("]", 0) {
				fail("syntax", p.peek(0).pos)
			}
		}
		p.next()
		p.count(2+len(items), t.pos)
		return &rnode{k: nIn, xs: []*rnode{l}, items: items}
	}
	return l
}

func (p *exprParser) unary() *rnode {
	t := p.peek(0)
	if p.isOp("!", 0) {
		p.next()
		p.nots++
		if p.nots > RuleExprLimits.Depth {
			fail("depth", t.pos)
		}
		x := p.unary()
		p.nots--
		p.count(1, t.pos)
		return &rnode{k: nNot, xs: []*rnode{x}}
	}
	return p.member()
}

func (p *exprParser) member() *rnode {
	n := p.primary()
	for p.isOp(".", 0) {
		p.next()
		name := p.next()
		if name.t != tIdent {
			fail("syntax", name.pos)
		}
		if !p.isOp("(", 0) {
			fail("syntax", p.peek(0).pos)
		}
		p.next()
		arg, hasArg := "", false
		if p.peek(0).t == tStr {
			arg, hasArg = p.next().v, true
		}
		p.expectOp(")")
		switch name.v {
		case "startsWith", "endsWith", "contains", "lowerAscii", "matches", "inCidr":
		default:
			fail("unknown_method", name.pos)
		}
		if name.v == "lowerAscii" {
			if hasArg {
				fail("type", name.pos)
			}
			p.count(1, name.pos)
			n = &rnode{k: nLower, xs: []*rnode{n}}
			continue
		}
		if !hasArg {
			fail("type", name.pos)
		}
		p.count(2, name.pos)
		switch name.v {
		case "startsWith", "endsWith", "contains":
			n = &rnode{k: nStrMethod, s: name.v, xs: []*rnode{n}, arg: arg}
		case "matches":
			p.regexes++
			if p.regexes > RuleExprLimits.Regexes {
				fail("too_many_regexes", name.pos)
			}
			prog := compileRegex(arg)
			if prog == nil {
				fail("regex", name.pos)
			}
			n = &rnode{k: nMatches, xs: []*rnode{n}, prog: prog}
		default:
			net, ok := parseCidr(arg)
			if !ok {
				fail("cidr", name.pos)
			}
			n = &rnode{k: nCidr, xs: []*rnode{n}, net: net}
		}
	}
	return n
}

func (p *exprParser) primary() *rnode {
	t := p.next()
	if t.t == tStr {
		p.count(1, t.pos)
		return &rnode{k: nStr, s: t.v}
	}
	if t.t == tOp && t.v == "(" {
		p.parens++
		if p.parens > RuleExprLimits.Depth {
			fail("depth", t.pos)
		}
		n := p.or()
		p.parens--
		p.expectOp(")")
		return n
	}
	if t.t == tIdent {
		switch t.v {
		case "true", "false":
			p.count(1, t.pos)
			return &rnode{k: nBool, b: t.v == "true"}
		case "null":
			p.count(1, t.pos)
			return &rnode{k: nNull}
		case "in":
			fail("syntax", t.pos)
		}
		// A dotted field name; a segment followed by `(` is a method call.
		name := t.v
		for p.isOp(".", 0) && p.peek(1).t == tIdent && !(p.peek(2).t == tOp && p.peek(2).v == "(") {
			p.next()
			name += "." + p.next().v
		}
		isMap, known := p.fields[name]
		if !known {
			fail("unknown_field", t.pos)
		}
		n := &rnode{k: nField, s: name}
		if p.isOp("[", 0) {
			open := p.next()
			s := p.next()
			if s.t != tStr {
				fail("syntax", s.pos)
			}
			p.expectOp("]")
			if !isMap {
				fail("type", open.pos)
			}
			// Header names are case-insensitive: ASCII lower-cased here, as
			// the SDKs record them.
			n.key, n.hasKey = s.v, true
			if name == "request.headers" {
				n.key = asciiLower(s.v)
			}
		} else if isMap {
			fail("type", t.pos)
		}
		p.count(1, t.pos)
		return n
	}
	fail("syntax", t.pos)
	return nil
}

// ---- types ------------------------------------------------------------------

type ty uint8

const (
	tyString ty = iota
	tyBool
	tyNull
)

func typeOf(n *rnode) ty {
	switch n.k {
	case nStr, nField:
		return tyString
	case nBool:
		return tyBool
	case nNull:
		return tyNull
	case nNot, nAnd, nOr:
		for _, x := range n.xs {
			if typeOf(x) != tyBool {
				fail("type", 0)
			}
		}
		return tyBool
	case nCmp:
		l, r := typeOf(n.xs[0]), typeOf(n.xs[1])
		if n.s == "==" || n.s == "!=" {
			strish := func(t ty) bool { return t == tyString || t == tyNull }
			if !((strish(l) && strish(r)) || (l == tyBool && r == tyBool)) {
				fail("type", 0)
			}
		} else if l != tyString || r != tyString {
			fail("type", 0)
		}
		return tyBool
	case nIn, nStrMethod, nMatches, nCidr:
		if typeOf(n.xs[0]) != tyString {
			fail("type", 0)
		}
		return tyBool
	case nLower:
		if typeOf(n.xs[0]) != tyString {
			fail("type", 0)
		}
		return tyString
	}
	fail("type", 0)
	return tyNull
}

func depthOf(n *rnode) int {
	switch n.k {
	case nNot, nLower:
		return 1 + depthOf(n.xs[0])
	case nAnd, nOr, nCmp:
		d := 0
		for _, x := range n.xs {
			d = max(d, depthOf(x))
		}
		return 1 + d
	case nIn:
		return 1 + max(depthOf(n.xs[0]), 2)
	case nStrMethod, nMatches, nCidr:
		return 1 + max(depthOf(n.xs[0]), 1)
	}
	return 1
}

func collectFields(n *rnode, out map[string]bool) {
	if n.k == nField {
		out[n.s] = true
		return
	}
	for _, x := range n.xs {
		collectFields(x, out)
	}
}

// CompileRuleExpr parses and type-checks an expression. Every limit is
// checked here; an expression that compiles is safe to evaluate on any
// input. src that is not a string is refused with code empty.
func CompileRuleExpr(src any) (expr *RuleExpr, err *RuleExprError) {
	return CompileRuleExprIn(src, ContextApp)
}

// CompileRuleExprIn is CompileRuleExpr for a context: the grammar, types and
// limits are the same, only the fields differ (README "Collector contexts").
// A context this SDK does not know is refused with code context.
func CompileRuleExprIn(src any, ctx RuleContext) (expr *RuleExpr, err *RuleExprError) {
	fields := ruleFields
	if ctx != ContextApp {
		var known bool
		if fields, known = collectorFields[ctx]; !known {
			return nil, &RuleExprError{Code: "context"}
		}
	}
	s, ok := src.(string)
	if !ok || jsTrim(s) == "" {
		return nil, &RuleExprError{Code: "empty"}
	}
	if len(s) > RuleExprLimits.ExpressionBytes {
		return nil, &RuleExprError{Code: "too_long"}
	}
	defer func() {
		if r := recover(); r != nil {
			expr = nil
			if e, ok := r.(exprError); ok {
				err = &RuleExprError{Code: e.code, Pos: e.pos}
			} else {
				err = &RuleExprError{Code: "syntax"}
			}
		}
	}()
	p := &exprParser{fields: fields, toks: lexExpr(s)}
	ast := p.parse()
	if typeOf(ast) != tyBool {
		fail("type", 0)
	}
	if depthOf(ast) > RuleExprLimits.Depth {
		fail("depth", 0)
	}
	set := map[string]bool{}
	collectFields(ast, set)
	e := &RuleExpr{ast: ast, Phase: PhaseRequest, Context: ctx}
	for f := range set {
		e.Fields = append(e.Fields, f)
		if strings.HasPrefix(f, "sink.") || strings.HasPrefix(f, "attack.") {
			e.Phase = PhaseFinding
		}
		if strings.HasPrefix(f, "input.") {
			e.UsesInput = true
		}
	}
	sort.Strings(e.Fields)
	e.UsesBody = set["request.body"]
	return e, nil
}

// ---- evaluation -------------------------------------------------------------

// RuleBudget is the work left for evaluations (regex steps); exhausting it
// ends an evaluation as no match.
type RuleBudget struct{ Steps int64 }

type budgetExhausted struct{}

// RuleRequest is the request as the language sees it. A nil pointer reads
// as null.
type RuleRequest struct {
	Method, Path, Route, IP *string
	// Headers are keyed by lower-case name.
	Headers map[string]string
	// Query maps a parameter name to its first value.
	Query map[string]string
	// Body maps a flattened body path (user.name) to its first string leaf.
	Body map[string]string
}

// RuleSubject is what an expression is evaluated against. Missing parts read
// as null.
type RuleSubject struct {
	App     *string
	Request *RuleRequest
	Inputs  []Input
	Sink    *string
	Attack  *RuleAttack
	// Collector holds the fields of the collector contexts.
	Collector *RuleCollector
}

// RuleCollector is a collector context's subject (README "Collector
// contexts"). A nil pointer reads as null.
type RuleCollector struct {
	// agent_tool: the tool's name as the agent reports it, the shell command
	// it runs, the file path it reads or writes, and the coding agent.
	ToolName, ToolCommand, ToolPath, AgentName *string
	// ai_proxy: the upstream provider, the requested model, and the request's
	// estimated input tokens as a decimal string.
	AIProvider, AIModel, AITokens *string
	// Both: the person and the device's operating system.
	UserID, DeviceOS *string
}

// RuleAttack is the built-in finding a finding rule sees.
type RuleAttack struct{ Type, Rule *string }

type val struct {
	t ty
	s string
	b bool
}

var (
	vNull  = val{t: tyNull}
	vTrue  = val{t: tyBool, b: true}
	vFalse = val{t: tyBool}
)

func vBool(b bool) val {
	if b {
		return vTrue
	}
	return vFalse
}

func vStr(p *string) val {
	if p == nil {
		return vNull
	}
	return val{t: tyString, s: *p}
}

func vMap(m map[string]string, key string) val {
	if v, ok := m[key]; ok {
		return val{t: tyString, s: v}
	}
	return vNull
}

func asciiLower(s string) string {
	b := []byte(s)
	for i, c := range b {
		if c >= 'A' && c <= 'Z' {
			b[i] = c + 32
		}
	}
	return string(b)
}

func fieldVal(n *rnode, s *RuleSubject, input *Input) val {
	r := s.Request
	switch n.s {
	case "request.method", "request.path", "request.route", "request.ip", "request.headers", "request.query", "request.body":
		if r == nil {
			return vNull
		}
	}
	switch n.s {
	case "request.method":
		return vStr(r.Method)
	case "request.path":
		return vStr(r.Path)
	case "request.route":
		return vStr(r.Route)
	case "request.ip":
		return vStr(r.IP)
	case "request.headers":
		return vMap(r.Headers, n.key)
	case "request.query":
		return vMap(r.Query, n.key)
	case "request.body":
		return vMap(r.Body, n.key)
	case "input.value", "input.key", "input.source":
		if input == nil {
			return vNull
		}
		switch n.s {
		case "input.value":
			return val{t: tyString, s: input.Value}
		case "input.key":
			return val{t: tyString, s: input.Key}
		}
		return val{t: tyString, s: string(input.Source)}
	case "sink.name":
		return vStr(s.Sink)
	case "attack.type":
		if s.Attack == nil {
			return vNull
		}
		return vStr(s.Attack.Type)
	case "attack.rule":
		if s.Attack == nil {
			return vNull
		}
		return vStr(s.Attack.Rule)
	case "app.name":
		return vStr(s.App)
	}
	c := s.Collector
	if c == nil {
		return vNull
	}
	switch n.s {
	case "tool.name":
		return vStr(c.ToolName)
	case "tool.command":
		return vStr(c.ToolCommand)
	case "tool.path":
		return vStr(c.ToolPath)
	case "agent.name":
		return vStr(c.AgentName)
	case "ai.provider":
		return vStr(c.AIProvider)
	case "ai.model":
		return vStr(c.AIModel)
	case "ai.tokens":
		return vStr(c.AITokens)
	case "user.id":
		return vStr(c.UserID)
	case "device.os":
		return vStr(c.DeviceOS)
	}
	return vNull
}

// codePoints returns the code points of s, at most max.
func codePoints(s string, max int) []rune {
	out := make([]rune, 0, min(len(s), max))
	for _, r := range s {
		if len(out) >= max {
			break
		}
		out = append(out, r)
	}
	return out
}

func ev(n *rnode, s *RuleSubject, input *Input, budget *RuleBudget) val {
	switch n.k {
	case nStr:
		return val{t: tyString, s: n.s}
	case nBool:
		return vBool(n.b)
	case nNull:
		return vNull
	case nField:
		return fieldVal(n, s, input)
	case nNot:
		return vBool(!ev(n.xs[0], s, input, budget).b)
	case nAnd:
		for _, x := range n.xs {
			if !ev(x, s, input, budget).b {
				return vFalse
			}
		}
		return vTrue
	case nOr:
		for _, x := range n.xs {
			if ev(x, s, input, budget).b {
				return vTrue
			}
		}
		return vFalse
	case nCmp:
		l := ev(n.xs[0], s, input, budget)
		r := ev(n.xs[1], s, input, budget)
		switch n.s {
		case "==":
			return vBool(l == r)
		case "!=":
			return vBool(l != r)
		}
		if l.t != tyString || r.t != tyString {
			return vFalse
		}
		// Go compares strings byte-wise; for UTF-8 that is code point order.
		c := strings.Compare(l.s, r.s)
		switch n.s {
		case "<":
			return vBool(c < 0)
		case "<=":
			return vBool(c <= 0)
		case ">":
			return vBool(c > 0)
		}
		return vBool(c >= 0)
	case nIn:
		l := ev(n.xs[0], s, input, budget)
		if l.t != tyString {
			return vFalse
		}
		for _, it := range n.items {
			if it == l.s {
				return vTrue
			}
		}
		return vFalse
	case nStrMethod:
		t := ev(n.xs[0], s, input, budget)
		if t.t != tyString {
			return vFalse
		}
		switch n.s {
		case "startsWith":
			return vBool(strings.HasPrefix(t.s, n.arg))
		case "endsWith":
			return vBool(strings.HasSuffix(t.s, n.arg))
		}
		return vBool(strings.Contains(t.s, n.arg))
	case nLower:
		t := ev(n.xs[0], s, input, budget)
		if t.t != tyString {
			return vNull
		}
		return val{t: tyString, s: asciiLower(t.s)}
	case nMatches:
		t := ev(n.xs[0], s, input, budget)
		return vBool(t.t == tyString && runRegex(n.prog, codePoints(t.s, RuleExprLimits.MatchCodePoints), budget))
	case nCidr:
		t := ev(n.xs[0], s, input, budget)
		return vBool(t.t == tyString && inCidr(t.s, n.net))
	}
	return vNull
}

// RuleEvalResult is the outcome of an evaluation.
type RuleEvalResult struct {
	Matched bool
	// Input is the input that made an input.* expression true.
	Input *Input
	// Exhausted: the budget ran out (no match).
	Exhausted bool
}

// EvaluateRuleExpr evaluates a compiled expression. An expression that reads
// input.* is evaluated once per input, in order, and matches when any input
// makes it true (with no inputs, once with the input fields null). It never
// panics: an evaluation that runs out of budget, or fails in any way, is no
// match. A nil budget means DefaultRuleBudget.
func EvaluateRuleExpr(expr *RuleExpr, subject *RuleSubject, budget *RuleBudget) (res RuleEvalResult) {
	if expr == nil || subject == nil {
		return res
	}
	if budget == nil {
		budget = &RuleBudget{Steps: DefaultRuleBudget}
	}
	defer func() {
		if r := recover(); r != nil {
			_, ex := r.(budgetExhausted)
			res = RuleEvalResult{Exhausted: ex}
		}
	}()
	if !expr.UsesInput || len(subject.Inputs) == 0 {
		return RuleEvalResult{Matched: ev(expr.ast, subject, nil, budget) == vTrue}
	}
	for i := range subject.Inputs {
		in := &subject.Inputs[i]
		if ev(expr.ast, subject, in, budget) == vTrue {
			c := *in
			return RuleEvalResult{Matched: true, Input: &c}
		}
	}
	return res
}

// ---- regular expressions ----------------------------------------------------

type rxKind uint8

const (
	rChar rxKind = iota
	rAny
	rClass
	rBol
	rEol
	rCat
	rAlt
	rRep
)

type rx struct {
	t        rxKind
	c        rune
	r        []rune // class ranges, lo/hi pairs
	neg      bool
	xs       []*rx
	min, max int // max -1: unbounded
}

type instOp uint8

const (
	iChar instOp = iota
	iAny
	iClass
	iSplit
	iJmp
	iBol
	iEol
	iMatch
)

type inst struct {
	op   instOp
	c    rune
	r    []rune
	neg  bool
	x, y int
}

const maxCP = 0x10ffff

var (
	classDigit = []rune{0x30, 0x39}
	classWord  = []rune{0x30, 0x39, 0x41, 0x5a, 0x5f, 0x5f, 0x61, 0x7a}
	classSpace = []rune{0x09, 0x0d, 0x20, 0x20}
)

const (
	rxMeta      = `\.^$|?*+()[]{}`
	rxEscapable = `\.^$|?*+()[]{}/-`
)

type regexError struct{}

func complementRanges(r []rune) []rune {
	type pair struct{ lo, hi rune }
	ps := make([]pair, 0, len(r)/2)
	for i := 0; i+1 < len(r); i += 2 {
		ps = append(ps, pair{r[i], r[i+1]})
	}
	for i := 1; i < len(ps); i++ {
		for j := i; j > 0 && ps[j].lo < ps[j-1].lo; j-- {
			ps[j], ps[j-1] = ps[j-1], ps[j]
		}
	}
	var out []rune
	next := rune(0)
	for _, p := range ps {
		if p.lo > next {
			out = append(out, next, p.lo-1)
		}
		next = max(next, p.hi+1)
	}
	if next <= maxCP {
		out = append(out, next, maxCP)
	}
	return out
}

type rxParser struct {
	cp []rune
	i  int
}

func rxFail() { panic(regexError{}) }

func (p *rxParser) at(k int) (rune, bool) {
	if k < len(p.cp) {
		return p.cp[k], true
	}
	return 0, false
}

func (p *rxParser) ch(c rune) bool { r, ok := p.at(p.i); return ok && r == c }

func (p *rxParser) parse() *rx {
	n := p.alt()
	if p.i < len(p.cp) {
		rxFail()
	}
	return n
}

func (p *rxParser) alt() *rx {
	xs := []*rx{p.cat()}
	for p.ch('|') {
		p.i++
		xs = append(xs, p.cat())
	}
	if len(xs) == 1 {
		return xs[0]
	}
	return &rx{t: rAlt, xs: xs}
}

func (p *rxParser) cat() *rx {
	var xs []*rx
	for p.i < len(p.cp) && !p.ch('|') && !p.ch(')') {
		xs = append(xs, p.piece())
	}
	if len(xs) == 1 {
		return xs[0]
	}
	return &rx{t: rCat, xs: xs}
}

func (p *rxParser) piece() *rx {
	atom := p.atom()
	q, ok := p.quant()
	if !ok {
		return atom
	}
	if atom.t == rBol || atom.t == rEol {
		rxFail()
	}
	if hasRep(atom) {
		rxFail() // nested quantifier
	}
	if atomsOf(atom) == 0 {
		rxFail() // nothing to repeat
	}
	return &rx{t: rRep, xs: []*rx{atom}, min: q[0], max: q[1]}
}

func (p *rxParser) num() (int, bool) {
	n, digits := 0, 0
	for {
		c, ok := p.at(p.i)
		if !ok || c < '0' || c > '9' {
			break
		}
		n = n*10 + int(c-'0')
		digits++
		p.i++
		if digits > 3 {
			rxFail()
		}
	}
	return n, digits > 0
}

func (p *rxParser) quant() ([2]int, bool) {
	var q [2]int
	switch {
	case p.ch('*'):
		q = [2]int{0, -1}
		p.i++
	case p.ch('+'):
		q = [2]int{1, -1}
		p.i++
	case p.ch('?'):
		q = [2]int{0, 1}
		p.i++
	case p.ch('{'):
		p.i++
		lo, ok := p.num()
		if !ok {
			rxFail()
		}
		hi := lo
		if p.ch(',') {
			p.i++
			m, ok := p.num()
			if ok {
				hi = m
			} else {
				hi = -1
			}
		}
		if !p.ch('}') {
			rxFail()
		}
		p.i++
		L := RuleExprLimits.RegexRepeat
		if lo > L || hi > L || (hi != -1 && hi < lo) {
			rxFail()
		}
		q = [2]int{lo, hi}
	default:
		return q, false
	}
	if p.ch('?') {
		p.i++ // lazy: the same language, so the same answer
	}
	if p.ch('*') || p.ch('+') || p.ch('?') || p.ch('{') {
		rxFail()
	}
	return q, true
}

func (p *rxParser) escape() *rx {
	p.i++ // the backslash
	c, ok := p.at(p.i)
	if !ok {
		rxFail()
	}
	p.i++
	// Only ASCII has meaning after a backslash.
	if c >= 0x80 {
		rxFail()
	}
	switch c {
	case 'd', 'D':
		return &rx{t: rClass, r: append([]rune(nil), classDigit...), neg: c == 'D'}
	case 'w', 'W':
		return &rx{t: rClass, r: append([]rune(nil), classWord...), neg: c == 'W'}
	case 's', 'S':
		return &rx{t: rClass, r: append([]rune(nil), classSpace...), neg: c == 'S'}
	case 'n':
		return &rx{t: rChar, c: 0x0a}
	case 'r':
		return &rx{t: rChar, c: 0x0d}
	case 't':
		return &rx{t: rChar, c: 0x09}
	case 'f':
		return &rx{t: rChar, c: 0x0c}
	case 'v':
		return &rx{t: rChar, c: 0x0b}
	case 'x', 'u':
		n := 2
		if c == 'u' {
			n = 4
		}
		if p.i+n > len(p.cp) {
			rxFail()
		}
		code := 0
		for _, d := range p.cp[p.i : p.i+n] {
			if d >= 0x80 || !isHexByte(byte(d)) {
				rxFail()
			}
			v, _ := strconv.ParseUint(string(d), 16, 8)
			code = code*16 + int(v)
		}
		if code >= 0xd800 && code <= 0xdfff {
			rxFail()
		}
		p.i += n
		return &rx{t: rChar, c: rune(code)}
	}
	if strings.ContainsRune(rxEscapable, c) {
		return &rx{t: rChar, c: c}
	}
	rxFail()
	return nil
}

func (p *rxParser) atom() *rx {
	c, _ := p.at(p.i)
	// Operators are ASCII; any other code point is a literal.
	switch c {
	case '(':
		p.i++
		if p.ch('?') {
			p.i++
			if !p.ch(':') {
				rxFail() // lookaround, named groups, flags
			}
			p.i++
		}
		inner := p.alt()
		if !p.ch(')') {
			rxFail()
		}
		p.i++
		return inner
	case '[':
		return p.cls()
	case '.':
		p.i++
		return &rx{t: rAny}
	case '^':
		p.i++
		return &rx{t: rBol}
	case '$':
		p.i++
		return &rx{t: rEol}
	case '\\':
		return p.escape()
	}
	if c < 0x80 && strings.ContainsRune(rxMeta, c) {
		rxFail()
	}
	p.i++
	return &rx{t: rChar, c: c}
}

func (p *rxParser) clsItem() *rx {
	c, ok := p.at(p.i)
	if !ok {
		rxFail()
	}
	if c == '\\' {
		return p.escape()
	}
	if c == '[' {
		rxFail() // unescaped [ inside a class
	}
	p.i++
	return &rx{t: rChar, c: c}
}

func (p *rxParser) cls() *rx {
	p.i++ // [
	neg := false
	if p.ch('^') {
		neg = true
		p.i++
	}
	var r []rune
	for !p.ch(']') {
		if p.i >= len(p.cp) {
			rxFail()
		}
		a := p.clsItem()
		// `-` between two items is a range; at the start or right before `]`
		// it is literal.
		if nx, ok := p.at(p.i + 1); p.ch('-') && ok && nx != ']' {
			p.i++ // -
			b := p.clsItem()
			if a.t != rChar || b.t != rChar || a.c > b.c {
				rxFail()
			}
			r = append(r, a.c, b.c)
		} else if a.t == rChar {
			r = append(r, a.c, a.c)
		} else if a.t == rClass {
			if a.neg {
				r = append(r, complementRanges(a.r)...)
			} else {
				r = append(r, a.r...)
			}
		} else {
			rxFail()
		}
	}
	p.i++ // ]
	if len(r) == 0 {
		rxFail()
	}
	return &rx{t: rClass, r: r, neg: neg}
}

func hasRep(n *rx) bool {
	if n.t == rRep {
		return true
	}
	if n.t == rCat || n.t == rAlt {
		for _, x := range n.xs {
			if hasRep(x) {
				return true
			}
		}
	}
	return false
}

// atomsOf counts atoms once counted repetitions are expanded (README
// "Regular expressions").
func atomsOf(n *rx) int {
	switch n.t {
	case rChar, rAny, rClass:
		return 1
	case rCat, rAlt:
		s := 0
		for _, x := range n.xs {
			s += atomsOf(x)
		}
		return s
	case rRep:
		// The copies the program holds: min, then one loop (unbounded) or
		// max - min optional ones.
		if n.max == -1 {
			return atomsOf(n.xs[0]) * (n.min + 1)
		}
		return atomsOf(n.xs[0]) * n.max
	}
	return 0
}

func emit(n *rx, prog *[]inst) {
	switch n.t {
	case rChar:
		*prog = append(*prog, inst{op: iChar, c: n.c})
	case rAny:
		*prog = append(*prog, inst{op: iAny})
	case rClass:
		*prog = append(*prog, inst{op: iClass, r: n.r, neg: n.neg})
	case rBol:
		*prog = append(*prog, inst{op: iBol})
	case rEol:
		*prog = append(*prog, inst{op: iEol})
	case rCat:
		for _, x := range n.xs {
			emit(x, prog)
		}
	case rAlt:
		// split L1, next; L1: x0; jmp end; next: split ... ; last
		var jumps []int
		for k, x := range n.xs {
			if k < len(n.xs)-1 {
				split := len(*prog)
				*prog = append(*prog, inst{op: iSplit, x: split + 1, y: -1})
				emit(x, prog)
				jumps = append(jumps, len(*prog))
				*prog = append(*prog, inst{op: iJmp, x: -1})
				(*prog)[split].y = len(*prog)
			} else {
				emit(x, prog)
			}
		}
		for _, j := range jumps {
			(*prog)[j].x = len(*prog)
		}
	case rRep:
		x := n.xs[0]
		for k := 0; k < n.min; k++ {
			emit(x, prog)
		}
		if n.max == -1 {
			// L: split body, end; body; jmp L
			L := len(*prog)
			*prog = append(*prog, inst{op: iSplit, x: L + 1, y: -1})
			emit(x, prog)
			*prog = append(*prog, inst{op: iJmp, x: L})
			(*prog)[L].y = len(*prog)
		} else {
			for k := n.min; k < n.max; k++ {
				split := len(*prog)
				*prog = append(*prog, inst{op: iSplit, x: split + 1, y: -1})
				emit(x, prog)
				(*prog)[split].y = len(*prog)
			}
		}
	}
}

// compileRegex checks a pattern against the safe subset and compiles it;
// nil when refused.
func compileRegex(pattern string) (prog []inst) {
	defer func() {
		if recover() != nil {
			prog = nil
		}
	}()
	if len(pattern) > RuleExprLimits.RegexBytes {
		return nil
	}
	ast := (&rxParser{cp: []rune(pattern)}).parse()
	if atomsOf(ast) > RuleExprLimits.RegexAtoms {
		return nil
	}
	emit(ast, &prog)
	return append(prog, inst{op: iMatch})
}

// IsSafeRegex reports whether a pattern is in the custom rules' safe regex
// subset.
func IsSafeRegex(pattern string) bool { return compileRegex(pattern) != nil }

func classHas(r []rune, c rune) bool {
	for k := 0; k+1 < len(r); k += 2 {
		if c >= r[k] && c <= r[k+1] {
			return true
		}
	}
	return false
}

// runRegex is the Pike VM: every thread advances in lock step, one code
// point at a time, so the work is at most (subject length + 1) x (program
// size). True when some substring of the subject (respecting ^ and $) is in
// the pattern's language. Each instruction visited costs one budget step,
// exactly as in rule-expr.ts.
func runRegex(prog []inst, subject []rune, budget *RuleBudget) bool {
	size := len(prog)
	mark := make([]int, size)
	for i := range mark {
		mark[i] = -1
	}
	gen := 0
	var clist, nlist, spare []int
	stack := make([]int, 0, 16)
	n := len(subject)

	add := func(list *[]int, pc0, pos int) bool {
		stack = append(stack[:0], pc0)
		for len(stack) > 0 {
			pc := stack[len(stack)-1]
			stack = stack[:len(stack)-1]
			if mark[pc] == gen {
				continue
			}
			mark[pc] = gen
			budget.Steps--
			if budget.Steps < 0 {
				panic(budgetExhausted{})
			}
			in := &prog[pc]
			switch in.op {
			case iJmp:
				stack = append(stack, in.x)
			case iSplit:
				stack = append(stack, in.y, in.x)
			case iBol:
				if pos == 0 {
					stack = append(stack, pc+1)
				}
			case iEol:
				if pos == n {
					stack = append(stack, pc+1)
				}
			case iMatch:
				return true
			default:
				*list = append(*list, pc)
			}
		}
		return false
	}

	for pos := 0; ; pos++ {
		// Threads already in clist were marked with this generation when added.
		if add(&clist, 0, pos) {
			return true
		}
		if pos == n {
			return false
		}
		c := subject[pos]
		gen++
		nlist = spare[:0]
		for _, pc := range clist {
			in := &prog[pc]
			ok := in.op == iAny || (in.op == iChar && in.c == c) || (in.op == iClass && classHas(in.r, c) != in.neg)
			if ok && add(&nlist, pc+1, pos+1) {
				return true
			}
		}
		spare, clist = clist, nlist
	}
}

// ---- CIDR -------------------------------------------------------------------

type ipNet struct {
	bytes  [16]byte
	prefix int
}

// decPart reads `0|[1-9][0-9]{0,2}`.
func decPart(s string) (int, bool) {
	if s == "" || len(s) > 3 || (len(s) > 1 && s[0] == '0') {
		return 0, false
	}
	n := 0
	for i := 0; i < len(s); i++ {
		if !isDigitByte(s[i]) {
			return 0, false
		}
		n = n*10 + int(s[i]-'0')
	}
	return n, true
}

func parseV4Strict(s string) ([]byte, bool) {
	parts := strings.Split(s, ".")
	if len(parts) != 4 {
		return nil, false
	}
	out := make([]byte, 4)
	for i, p := range parts {
		n, ok := decPart(p)
		if !ok || n > 255 {
			return nil, false
		}
		out[i] = byte(n)
	}
	return out, true
}

func hexGroup(p string) (int, bool) {
	if p == "" || len(p) > 4 {
		return 0, false
	}
	n := 0
	for i := 0; i < len(p); i++ {
		if !isHexByte(p[i]) {
			return 0, false
		}
		v, _ := strconv.ParseUint(p[i:i+1], 16, 8)
		n = n*16 + int(v)
	}
	return n, true
}

// parseIPBytes reads an IPv4 or IPv6 address as 16 bytes (IPv4 as
// ::ffff:a.b.c.d).
func parseIPBytes(s string) ([16]byte, bool) {
	var out [16]byte
	if len(s) > 64 || !utf8.ValidString(s) {
		return out, false
	}
	if v4, ok := parseV4Strict(s); ok {
		out[10], out[11] = 0xff, 0xff
		copy(out[12:], v4)
		return out, true
	}
	if !strings.Contains(s, ":") {
		return out, false
	}
	halves := strings.Split(s, "::")
	if len(halves) > 2 {
		return out, false
	}
	groups := func(h string) ([]int, bool) {
		if h == "" {
			return nil, true
		}
		var g []int
		parts := strings.Split(h, ":")
		for k, p := range parts {
			if k == len(parts)-1 && strings.Contains(p, ".") {
				t, ok := parseV4Strict(p)
				if !ok {
					return nil, false
				}
				g = append(g, int(t[0])<<8|int(t[1]), int(t[2])<<8|int(t[3]))
				continue
			}
			n, ok := hexGroup(p)
			if !ok {
				return nil, false
			}
			g = append(g, n)
		}
		return g, true
	}
	head, ok1 := groups(halves[0])
	var tail []int
	ok2 := true
	if len(halves) == 2 {
		tail, ok2 = groups(halves[1])
	}
	if !ok1 || !ok2 {
		return out, false
	}
	if len(halves) == 2 && halves[0] != "" && strings.Contains(halves[0], ".") {
		return out, false
	}
	var words []int
	if len(halves) == 2 {
		if len(head)+len(tail) > 7 {
			return out, false
		}
		words = append(words, head...)
		words = append(words, make([]int, 8-len(head)-len(tail))...)
		words = append(words, tail...)
	} else {
		if len(head) != 8 {
			return out, false
		}
		words = head
	}
	for i, w := range words {
		out[2*i], out[2*i+1] = byte(w>>8), byte(w)
	}
	return out, true
}

// parseCidr reads a.b.c.d/n, x:y::z/n, or a bare address (all bits).
func parseCidr(s string) (ipNet, bool) {
	var n ipNet
	addr := s
	slash := strings.IndexByte(s, '/')
	if slash >= 0 {
		addr = s[:slash]
	}
	if strings.Contains(addr, "%") {
		return n, false
	}
	b, ok := parseIPBytes(addr)
	if !ok {
		return n, false
	}
	_, v4 := parseV4Strict(addr)
	n.bytes, n.prefix = b, 128
	if slash >= 0 {
		p, ok := decPart(s[slash+1:])
		if !ok {
			return n, false
		}
		if (v4 && p > 32) || p > 128 {
			return n, false
		}
		if v4 {
			p += 96
		}
		n.prefix = p
	}
	return n, true
}

func inCidr(ip string, net ipNet) bool {
	if pct := strings.IndexByte(ip, '%'); pct >= 0 {
		ip = ip[:pct]
	}
	b, ok := parseIPBytes(ip)
	if !ok {
		return false
	}
	bits := net.prefix
	for k := 0; k < 16 && bits > 0; k, bits = k+1, bits-8 {
		mask := byte(0xff)
		if bits < 8 {
			mask = byte(0xff << (8 - bits))
		}
		if b[k]&mask != net.bytes[k]&mask {
			return false
		}
	}
	return true
}
