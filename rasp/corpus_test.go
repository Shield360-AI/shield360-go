package rasp

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The shared RASP corpus (sdk/rasp/testdata, README "Fixtures"): every benign
// case must fire nothing (false positives per section, must be 0), every
// entry of attack-examples.json must be detected as it says, and the
// embedded data files must stay byte-identical to the contract's copies.
//
// The fixtures are read from testdata/shared, copies of sdk/rasp kept by
// sdk/go/scripts/sync-shared-testdata.sh (CI runs it with --check), so the
// module also tests on its own in the public mirror.

var raspDir = filepath.Join("testdata", "shared")

var sections = []string{"sql", "nosql", "command", "path", "ssrf", "code", "xml", "deser", "xss", "template", "requests"}

func loadJSON(t *testing.T, rel string) map[string]any {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(raspDir, rel))
	if err != nil {
		t.Fatalf("read %s: %v", rel, err)
	}
	var v map[string]any
	if err := json.Unmarshal(data, &v); err != nil {
		t.Fatalf("parse %s: %v", rel, err)
	}
	return v
}

func str(c map[string]any, k string) string { s, _ := c[k].(string); return s }

func strList(v any) []string {
	var out []string
	for _, x := range asList(v) {
		if s, ok := x.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

func asList(v any) []any { l, _ := v.([]any); return l }

// normalise runs a case's inputs through the SDK's normalizer: request
// inputs get their percent-decoded forms, model output is fragmented.
func normalise(raw any) []Input {
	var out []Input
	for _, x := range asList(raw) {
		m, _ := x.(map[string]any)
		if str(m, "source") == string(SourceModelOutput) {
			addModelOutput(&out, str(m, "value"), str(m, "key"))
		} else {
			addInput(&out, str(m, "value"), str(m, "key"), SourceRequest)
		}
	}
	return out
}

// nodeVersions are the Node versions request cases also run under: one
// inside each runtimeVersions range of the built-in rules.
func nodeVersions() []string {
	out := []string{"24.22.0"}
	for _, r := range BuiltInRules {
		for _, rg := range r.RuntimeVersions["node"] {
			out = append(out, rg[0])
		}
	}
	return out
}

// runCase runs one case of a section; nil means nothing fired.
func runCase(section string, c map[string]any) *Finding {
	inputs := normalise(c["inputs"])
	switch section {
	case "sql":
		return DetectSQL(str(c, "query"), inputs, SQLDialect(str(c, "dialect")))
	case "nosql":
		var ins []Input
		flatten(&ins, c["body"], "body", 0)
		flatten(&ins, c["query"], "query", 0)
		trees := []any{c["body"], c["query"]}
		if f := DetectNoSQL(c["filter"], trees, ins); f != nil {
			return f
		}
		if c["update"] != nil {
			return DetectNoSQL(c["update"], trees, ins)
		}
		return nil
	case "command":
		if cmd, ok := c["command"].(string); ok {
			if f := DetectCommand(cmd, inputs); f != nil {
				return f
			}
			return DetectShellSpawn(Spawn{Command: cmd, InRequest: true})
		}
		argv := strList(c["argv"])
		if f := DetectArgv(argv, inputs); f != nil {
			return f
		}
		if script, ok := ShellScriptOf(argv); ok {
			if f := DetectCommand(script, inputs); f != nil {
				return f
			}
		}
		argv0 := ""
		if len(argv) > 0 {
			argv0 = argv[0]
		}
		return DetectShellSpawn(Spawn{Argv0: argv0, InRequest: true})
	case "path":
		return DetectPath(str(c, "path"), FileOp(str(c, "op")), inputs, strList(c["fileRoots"]), true)
	case "ssrf":
		return DetectSSRF(str(c, "url"), inputs, strList(c["resolved"]))
	case "code":
		return DetectCode(str(c, "code"), inputs)
	case "xml":
		re, _ := c["resolvesExternal"].(bool)
		return DetectXML(str(c, "xml"), inputs, re)
	case "deser":
		data := str(c, "data")
		if str(c, "dataEncoding") == "base64" {
			b, _ := base64.StdEncoding.DecodeString(data)
			data = string(b)
		}
		return DetectDeserialization(DeserFormat(str(c, "format")), data, inputs)
	case "template":
		// Only the source reaches the detector; data is never template source.
		return DetectTemplate(str(c, "template"), inputs, str(c, "engine"))
	case "xss":
		return DetectXSS(str(c, "contentType"), str(c, "body"), inputs)
	case "requests":
		headers := map[string]string{}
		if h, ok := c["headers"].(map[string]any); ok {
			for k, v := range h {
				switch x := v.(type) {
				case string:
					headers[k] = x
				case []any:
					headers[k] = strings.Join(strList(x), ", ")
				}
			}
		}
		req := &VpRequest{Method: str(c, "method"), Path: str(c, "path"), Query: str(c, "query"), Headers: headers, Cookie: str(c, "cookie"), Body: str(c, "body")}
		if f := MatchVirtualPatches(req, BuiltInRules, PhaseAll, Runtime, RuntimeVersion()); f != nil {
			return f
		}
		// The same matcher under Node, so the request cases prove it on the
		// rules that only apply there.
		for _, v := range nodeVersions() {
			if f := MatchVirtualPatches(req, BuiltInRules, PhaseAll, "node", v); f != nil {
				return f
			}
		}
		return nil
	}
	return nil
}

func TestBenignCorpus(t *testing.T) {
	benign := loadJSON(t, "testdata/benign.json")
	if v, _ := benign["version"].(float64); v != 1 {
		t.Fatalf("benign.json version = %v, want 1", benign["version"])
	}
	rates := map[string]string{}
	defer func() {
		var lines []string
		for _, s := range sections {
			if r, ok := rates[s]; ok {
				lines = append(lines, fmt.Sprintf("  %s: %s", s, r))
			}
		}
		t.Logf("RASP false-positive rates (Go):\n%s", strings.Join(lines, "\n"))
	}()
	for _, section := range sections {
		cases := asList(benign[section])
		if len(cases) == 0 {
			t.Errorf("section %s is empty", section)
			continue
		}
		t.Run(section, func(t *testing.T) {
			var fired []string
			for _, x := range cases {
				c, _ := x.(map[string]any)
				if f := runCase(section, c); f != nil {
					fired = append(fired, fmt.Sprintf("%s: %s", str(c, "name"), f.Rule))
				}
			}
			rates[section] = fmt.Sprintf("%d/%d (%.2f%%)", len(fired), len(cases), 100*float64(len(fired))/float64(len(cases)))
			if len(fired) > 0 {
				t.Errorf("%d false positives:\n%s", len(fired), strings.Join(fired, "\n"))
			}
		})
	}
}

func TestAttackExamples(t *testing.T) {
	var cases []any
	for _, file := range []string{"testdata/attack-examples.json", "testdata/template-attack-examples.json"} {
		list, ok := loadJSON(t, file)["cases"].([]any)
		if !ok {
			t.Fatalf("%s has no cases list", file)
		}
		cases = append(cases, list...)
	}
	detected := 0
	for i, x := range cases {
		c, _ := x.(map[string]any)
		name := str(c, "name")
		if name == "" {
			name = fmt.Sprintf("%s %d", str(c, "check"), i)
		}
		t.Run(name, func(t *testing.T) {
			expect, _ := c["expect"].(map[string]any)
			f := runCase(str(c, "check"), c)
			if f == nil {
				t.Fatalf("not detected; want %v", expect)
			}
			if string(f.Attack) != str(expect, "attack") {
				t.Errorf("attack = %s, want %s", f.Attack, str(expect, "attack"))
			}
			if rule := str(expect, "rule"); rule != "" && f.Rule != rule {
				t.Errorf("rule = %s, want %s", f.Rule, rule)
			}
			if !t.Failed() {
				detected++
			}
		})
	}
	t.Logf("RASP attack examples detected (Go): %d/%d", detected, len(cases))
}

func TestEmbeddedDataIsByteIdentical(t *testing.T) {
	for _, tc := range []struct{ embedded, contract string }{
		{"data/default-rules.json", "rules/default-rules.json"},
		{"data/dnslog-domains.json", "testdata/dnslog-domains.json"},
	} {
		got, err := os.ReadFile(tc.embedded)
		if err != nil {
			t.Fatal(err)
		}
		want, err := os.ReadFile(filepath.Join(raspDir, tc.contract))
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, want) {
			t.Errorf("%s is not byte-identical to sdk/rasp/%s (via %s)", tc.embedded, tc.contract, raspDir)
		}
	}
	if !bytes.Equal(defaultRulesJSON, mustRead(t, "data/default-rules.json")) || !bytes.Equal(dnslogJSON, mustRead(t, "data/dnslog-domains.json")) {
		t.Error("the embedded bytes differ from the files in data/")
	}
	if len(BuiltInRules) == 0 || BuiltInRulesVersion == "" || len(dnslogSuffixes) == 0 || len(dnslogHosts) == 0 {
		t.Error("embedded data did not parse")
	}
}

func mustRead(t *testing.T, p string) []byte {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// requestFor builds a request that satisfies a rule's clauses from the rule
// itself.
func requestFor(rule VirtualPatchRule) *VpRequest {
	req := &VpRequest{Method: "GET", Path: "/", Headers: map[string]string{}}
	for _, c := range rule.Match {
		value := "x"
		if len(c.Values) > 0 {
			value = c.Values[0]
		} else if c.Value != "" {
			value = c.Value
		}
		switch {
		case c.Target == "method":
			req.Method = value
		case strings.HasPrefix(c.Target, "header:"):
			if c.Op == "present" {
				req.Headers[c.Target[7:]] = "x"
			} else {
				req.Headers[c.Target[7:]] = value
			}
		case c.Target == "body" || c.Target == "request":
			req.Body += value
		case c.Target == "query":
			req.Query += value
		case c.Target == "cookie":
			req.Cookie += value
		case c.Target == "path":
			req.Path = value
		}
	}
	return req
}

// TestSQLLexerConformance runs testdata/sql-lexer.json: the tokens the SQL
// lexer returns, kind and text, for each dialect-specific case.
func TestSQLLexerConformance(t *testing.T) {
	fixture := loadJSON(t, "testdata/sql-lexer.json")
	cases := asList(fixture["cases"])
	if len(cases) == 0 {
		t.Fatal("sql-lexer.json has no cases")
	}
	for _, x := range cases {
		c, _ := x.(map[string]any)
		t.Run(str(c, "name"), func(t *testing.T) {
			var want, got []string
			for _, tok := range asList(c["tokens"]) {
				p := strList(tok)
				want = append(want, p[0]+" "+p[1])
			}
			for _, tok := range SQLTokens(str(c, "query"), SQLDialect(str(c, "dialect"))) {
				got = append(got, tok.Kind+" "+tok.Text)
			}
			if strings.Join(got, "\n") != strings.Join(want, "\n") {
				t.Errorf("tokens:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
			}
		})
	}
}
