package rasp

import (
	"reflect"
	"strings"
	"testing"
	"time"
)

// Custom rule expressions (README "Custom rules"): the shared conformance
// corpus (testdata/custom-rules.json), the limits, the safe regex subset and
// its linear-time matcher, CIDR matching, and fail-open evaluation.

func strPtr(s string) *string { return &s }

func optStr(m map[string]any, k string) *string {
	if s, ok := m[k].(string); ok {
		return &s
	}
	return nil
}

func strMap(v any) map[string]string {
	m, ok := v.(map[string]any)
	if !ok {
		return nil
	}
	out := map[string]string{}
	for k, x := range m {
		if s, ok := x.(string); ok {
			out[k] = s
		}
	}
	return out
}

// subjectFrom builds a RuleSubject from a corpus subject.
func subjectFrom(raw any) *RuleSubject {
	m, _ := raw.(map[string]any)
	s := &RuleSubject{App: optStr(m, "app"), Sink: optStr(m, "sink")}
	if r, ok := m["request"].(map[string]any); ok {
		s.Request = &RuleRequest{
			Method: optStr(r, "method"), Path: optStr(r, "path"), Route: optStr(r, "route"), IP: optStr(r, "ip"),
			Headers: strMap(r["headers"]), Query: strMap(r["query"]), Body: strMap(r["body"]),
		}
	}
	if a, ok := m["attack"].(map[string]any); ok {
		s.Attack = &RuleAttack{Type: optStr(a, "type"), Rule: optStr(a, "rule")}
	}
	for _, x := range asList(m["inputs"]) {
		in, _ := x.(map[string]any)
		s.Inputs = append(s.Inputs, Input{Value: str(in, "value"), Key: str(in, "key"), Source: Source(str(in, "source"))})
	}
	return s
}

func mustCompile(t *testing.T, src string) *RuleExpr {
	t.Helper()
	e, err := CompileRuleExpr(src)
	if err != nil {
		t.Fatalf("%q: %s", src, err.Code)
	}
	return e
}

func TestCustomRuleCorpus(t *testing.T) {
	corpus := loadJSON(t, "testdata/custom-rules.json")
	if v, _ := corpus["version"].(float64); v != 1 {
		t.Fatalf("version %v", corpus["version"])
	}
	limits, _ := corpus["limits"].(map[string]any)
	L := RuleExprLimits
	want := map[string]int{
		"expressionBytes": L.ExpressionBytes, "depth": L.Depth, "nodes": L.Nodes, "stringBytes": L.StringBytes,
		"listItems": L.ListItems, "regexes": L.Regexes, "regexBytes": L.RegexBytes, "regexAtoms": L.RegexAtoms,
		"regexRepeat": L.RegexRepeat, "matchCodePoints": L.MatchCodePoints,
	}
	if len(limits) != len(want) {
		t.Fatalf("limits %v", limits)
	}
	for k, v := range want {
		if got, _ := limits[k].(float64); int(got) != v {
			t.Errorf("limit %s: corpus %v, Go %d", k, limits[k], v)
		}
	}
	subjects, _ := corpus["subjects"].(map[string]any)
	valid, invalid, cases := 0, 0, 0
	for _, x := range asList(corpus["valid"]) {
		c, _ := x.(map[string]any)
		name := str(c, "name")
		e, err := CompileRuleExpr(c["expression"])
		if err != nil {
			t.Errorf("valid %q: %s", name, err.Code)
			continue
		}
		valid++
		if p, ok := c["phase"].(string); ok && string(e.Phase) != p {
			t.Errorf("valid %q: phase %s, want %s", name, e.Phase, p)
		}
		if u, ok := c["usesInput"].(bool); ok && e.UsesInput != u {
			t.Errorf("valid %q: usesInput %v", name, e.UsesInput)
		}
		if u, ok := c["usesBody"].(bool); ok && e.UsesBody != u {
			t.Errorf("valid %q: usesBody %v", name, e.UsesBody)
		}
		for _, k := range asList(c["cases"]) {
			kc, _ := k.(map[string]any)
			raw := kc["subject"]
			label := "inline"
			if s, ok := raw.(string); ok {
				label, raw = s, subjects[s]
			}
			exp, _ := kc["expect"].(bool)
			if got := EvaluateRuleExpr(e, subjectFrom(raw), nil).Matched; got != exp {
				t.Errorf("valid %q on %s: got %v, want %v", name, label, got, exp)
			}
			cases++
		}
	}
	for _, x := range asList(corpus["invalid"]) {
		c, _ := x.(map[string]any)
		_, err := CompileRuleExpr(c["expression"])
		code := "ok"
		if err != nil {
			code = err.Code
		}
		if code != str(c, "error") {
			t.Errorf("invalid %q: got %s, want %s", str(c, "name"), code, str(c, "error"))
		}
		invalid++
	}
	if valid < 60 || invalid < 60 {
		t.Fatalf("corpus too small: %d valid, %d invalid", valid, invalid)
	}
	t.Logf("custom-rules.json: %d valid expressions (%d evaluations), %d invalid", valid, cases, invalid)
}

func TestCompileRuleExpr(t *testing.T) {
	for _, v := range []any{nil, 1, map[string]any{}, []any{}} {
		if _, err := CompileRuleExpr(v); err == nil || err.Code != "empty" {
			t.Errorf("%v: %v", v, err)
		}
	}
	_, err := CompileRuleExpr(`request.method == "GET" &&& true`)
	if err == nil || err.Code != "syntax" || err.Pos <= 20 {
		t.Errorf("syntax position: %+v", err)
	}
	if e := mustCompile(t, `request.path == "/"`); e.Phase != PhaseRequest {
		t.Error(e.Phase)
	}
	if e := mustCompile(t, `attack.type == "ssrf"`); e.Phase != PhaseFinding {
		t.Error(e.Phase)
	}
	e := mustCompile(t, `sink.name == "fs.readFile" && input.key == "query.f"`)
	if e.Phase != PhaseFinding || !e.UsesInput || e.UsesBody {
		t.Errorf("%+v", e)
	}
	if !mustCompile(t, `request.body["a"] == "b"`).UsesBody {
		t.Error("usesBody")
	}
	if f := mustCompile(t, `request.headers["X-A"] == "1" && app.name == "a"`).Fields; !reflect.DeepEqual(f, []string{"app.name", "request.headers"}) {
		t.Error(f)
	}
	// The parser refuses runaway nesting before any deep recursion.
	for _, src := range []string{strings.Repeat("(", 1000) + "true" + strings.Repeat(")", 1000), strings.Repeat("!", 2000) + "true"} {
		if _, err := CompileRuleExpr(src); err == nil || err.Code != "depth" {
			t.Errorf("deep: %v", err)
		}
	}
}

func TestEvaluateRuleExpr(t *testing.T) {
	get := subjectFrom(loadJSON(t, "testdata/custom-rules.json")["subjects"].(map[string]any)["get"])

	t.Run("short-circuits", func(t *testing.T) {
		b := &RuleBudget{Steps: 1}
		if !EvaluateRuleExpr(mustCompile(t, `request.method == "GET" || request.path.matches("x")`), get, b).Matched || b.Steps != 1 {
			t.Error("||")
		}
		if EvaluateRuleExpr(mustCompile(t, `request.method == "PUT" && request.path.matches("x")`), get, b).Matched || b.Steps != 1 {
			t.Error("&&")
		}
	})

	t.Run("returns the input that matched", func(t *testing.T) {
		r := EvaluateRuleExpr(mustCompile(t, `input.key == "query.sort"`), get, nil)
		if !r.Matched || r.Input == nil || *r.Input != (Input{Value: "name desc", Key: "query.sort", Source: SourceRequest}) {
			t.Errorf("%+v", r)
		}
	})

	t.Run("fails open on a sparse subject", func(t *testing.T) {
		e := mustCompile(t, `request.headers["a"] == "b" && input.value == "x"`)
		for _, s := range []*RuleSubject{{}, {Request: &RuleRequest{}}, {Inputs: []Input{}}} {
			if EvaluateRuleExpr(e, s, nil).Matched {
				t.Errorf("%+v", s)
			}
		}
		if EvaluateRuleExpr(nil, get, nil).Matched || EvaluateRuleExpr(e, nil, nil).Matched {
			t.Error("nil")
		}
	})

	t.Run("stops at the budget", func(t *testing.T) {
		e := mustCompile(t, `input.value.matches("a{100}x")`)
		big := &RuleSubject{App: strPtr("a")}
		for i := 0; i < 256; i++ {
			big.Inputs = append(big.Inputs, Input{Value: strings.Repeat("a", 4096), Key: "query.k", Source: SourceRequest})
		}
		b := &RuleBudget{Steps: 10_000}
		if r := EvaluateRuleExpr(e, big, b); r.Matched || !r.Exhausted || b.Steps >= 0 {
			t.Errorf("%+v %d", r, b.Steps)
		}
	})

	t.Run("matches in linear time", func(t *testing.T) {
		t0 := time.Now()
		if EvaluateRuleExpr(mustCompile(t, `app.name.matches("^(?:a|a)*b$")`), &RuleSubject{App: strPtr(strings.Repeat("a", 4000))}, nil).Matched {
			t.Error("(a|a)*b")
		}
		if EvaluateRuleExpr(mustCompile(t, `app.name.matches(".*.*.*.*.*.*x")`), &RuleSubject{App: strPtr(strings.Repeat("a", 4096))}, nil).Matched {
			t.Error(".*x")
		}
		if d := time.Since(t0); d > 2*time.Second {
			t.Errorf("took %v", d)
		}
	})

	t.Run("reads only the first 4096 code points", func(t *testing.T) {
		e := mustCompile(t, `app.name.matches("x")`)
		if EvaluateRuleExpr(e, &RuleSubject{App: strPtr(strings.Repeat("é", 4096) + "x")}, nil).Matched {
			t.Error("past the cap")
		}
		if !EvaluateRuleExpr(e, &RuleSubject{App: strPtr(strings.Repeat("é", 4095) + "x")}, nil).Matched {
			t.Error("at the cap")
		}
	})
}

func TestRegexSubset(t *testing.T) {
	for _, p := range []string{"a", "^a$", "[a-z0-9_]+", "(?:x|y){1,3}", `\d{3}-\d{4}`, ".*", "a|", "(?:)", `[\s\S]`} {
		if !IsSafeRegex(p) {
			t.Errorf("refused %q", p)
		}
	}
	for _, p := range []string{"(a+)+", "(a*)*", "(a|b+)*", "a{0,1000}", `\1`, "(?=x)", "(?!x)", "(?<=x)", "(?P<n>x)", `\Z`, `\A`, `\cA`, "a{1,2}{3}", `[a-\d]`, "x{", `\`} {
		if IsSafeRegex(p) {
			t.Errorf("accepted %q", p)
		}
	}
}

func TestRuleCIDR(t *testing.T) {
	b, ok := parseIPBytes("1.2.3.4")
	if !ok || b != [16]byte{10: 255, 11: 255, 12: 1, 13: 2, 14: 3, 15: 4} {
		t.Error(b)
	}
	if b, ok := parseIPBytes("::1"); !ok || b != [16]byte{15: 1} {
		t.Error(b)
	}
	if b, ok := parseIPBytes("1:2:3:4:5:6:1.2.3.4"); !ok || b != [16]byte{0, 1, 0, 2, 0, 3, 0, 4, 0, 5, 0, 6, 1, 2, 3, 4} {
		t.Error(b)
	}
	for _, bad := range []string{"1.2.3", "1.2.3.256", "01.2.3.4", ":1", "1:::2", "1:2:3:4:5:6:7:8:9", "12345::", "g::", "1.2.3.4::", ""} {
		if _, ok := parseIPBytes(bad); ok {
			t.Errorf("parsed %q", bad)
		}
	}
	for s, prefix := range map[string]int{"10.0.0.0/8": 104, "::/0": 0, "1.2.3.4": 128} {
		if n, ok := parseCidr(s); !ok || n.prefix != prefix {
			t.Errorf("%s: %d", s, n.prefix)
		}
	}
}
