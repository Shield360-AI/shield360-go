package rasp

import (
	"bytes"
	"context"
	"encoding/json"
	htmltemplate "html/template"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	texttemplate "text/template"
)

// templateTableJSON mirrors one engine of sdk/rasp/rules/template-engines.json.
type templateTableJSON struct {
	Pairs        [][]string `json:"pairs"`
	Literal      [][]string `json:"literal"`
	Tags         [][]string `json:"tags"`
	Directives   []string   `json:"directives"`
	LineComment  []string   `json:"lineComment"`
	LineCode     []string   `json:"lineCode"`
	Attrs        []string   `json:"attrs"`
	Escape       string     `json:"escape"`
	SpaceLiteral bool       `json:"spaceLiteral"`
	Pug          bool       `json:"pug"`
}

func toTableJSON(s TemplateSyntax) templateTableJSON {
	out := templateTableJSON{
		Pairs: [][]string{}, Literal: [][]string{}, Tags: [][]string{},
		Directives: append([]string{}, s.Directives...), LineComment: append([]string{}, s.LineComment...),
		LineCode: append([]string{}, s.LineCode...), Attrs: append([]string{}, s.Attrs...),
		Escape: s.Escape, SpaceLiteral: s.SpaceLiteral, Pug: s.Pug,
	}
	for _, p := range s.Pairs {
		out.Pairs = append(out.Pairs, []string{p.Open, p.Close, p.Mode})
	}
	for _, d := range s.Literal {
		out.Literal = append(out.Literal, []string{d.Open, d.Close})
	}
	for _, d := range s.Tags {
		out.Tags = append(out.Tags, []string{d.Open, d.Close})
	}
	return out
}

// TestTemplateEngineTableMatchesContract: the embedded table equals the
// contract's engines, in order, including list order.
func TestTemplateEngineTableMatchesContract(t *testing.T) {
	data, err := os.ReadFile(filepath.Join(raspDir, "rules", "template-engines.json"))
	if err != nil {
		t.Fatal(err)
	}
	var file struct {
		Engines json.RawMessage `json:"engines"`
	}
	if err := json.Unmarshal(data, &file); err != nil {
		t.Fatal(err)
	}
	// Engine order from the object's keys.
	dec := json.NewDecoder(bytes.NewReader(file.Engines))
	if _, err := dec.Token(); err != nil {
		t.Fatal(err)
	}
	var names []string
	want := map[string]templateTableJSON{}
	for dec.More() {
		tok, err := dec.Token()
		if err != nil {
			t.Fatal(err)
		}
		name := tok.(string)
		var e templateTableJSON
		if err := dec.Decode(&e); err != nil {
			t.Fatal(err)
		}
		names = append(names, name)
		want[name] = e
	}
	var got []string
	for _, e := range TemplateEngines {
		got = append(got, e.Name)
		if !reflect.DeepEqual(toTableJSON(e.Syntax), want[e.Name]) {
			t.Errorf("engine %s:\n got %+v\nwant %+v", e.Name, toTableJSON(e.Syntax), want[e.Name])
		}
	}
	if !reflect.DeepEqual(got, names) {
		t.Errorf("engines %v, want %v", got, names)
	}
}

func tmplInput(v string) []Input { return []Input{{Value: v, Key: "query.q", Source: SourceRequest}} }

func tmplRule(source, value, engine string) string {
	if f := DetectTemplate(source, tmplInput(value), engine); f != nil {
		if f.Attack != CodeInjection {
			return "wrong attack " + string(f.Attack)
		}
		return f.Rule
	}
	return ""
}

func TestDetectTemplate(t *testing.T) {
	const rule = "code.template_injection"
	hits := []struct{ source, value, engine string }{
		// structure, overlap, minimum length
		{"Hello {{ 7 * 7 }}", "{{ 7 * 7 }}", "handlebars"},
		{"<%= 7 * 7 %>", "7 * 7", "ejs"},
		{"p\n  - 7 + 7", "- 7 + 7", "pug"},
		// pug attributes
		{`a(href=url + "x") Link`, `url + "x"`, "pug"},
		{`a(class="c" href=url)= label + 1`, "label + 1", "pug"},
		// dotted paths
		{"Hello {{ user.name }}", "user.name }}", "nunjucks"},
		// doubled escape leaves the opener live
		{`Show \\{{name}} live`, "{{name}}", "handlebars"},
		// shared engine table
		{"<#if x>${a}</#if>", "x>${a}", "freemarker"},
		{"<#assign x = 7 * 7>", "7 * 7", "freemarker"},
		{"#set($x = 7 * 7)", "7 * 7", "velocity"},
		{"Hi\n% if a + b:\nx", "a + b", "mako"},
		{`<%def name="x()">y</%def>`, `name="x()"`, "mako"},
		{`<p th:text="a + b">x</p>`, "a + b", "thymeleaf"},
		{"@if($a + $b) y @endif", "$a + $b", "blade"},
		{`{{ printf "%d" 7 }}`, `printf "%d"`, "gotemplate"},
		{"Hi {$a + $b}", "$a + $b", "smarty"},
		{"{% raw %}x{% endraw %}{{ a }}", "{% endraw %}{{ a }}", "jinja2"},
		// review fixes: literal whitespace control, no comments in regions, spaced attrs
		{"{% raw %}x{%endraw%}{{ 7 * 7 }}", "{{ 7 * 7 }}", "jinja2"},
		{"{% raw %}x{%- endraw -%}{{ 7 * 7 }}", "{{ 7 * 7 }}", "nunjucks"},
		{"{{ 10 // a + b }}", "a + b", "jinja2"},
		{`<p th:text = "a + b">x</p>`, "a + b", "thymeleaf"},
	}
	for _, c := range hits {
		if got := tmplRule(c.source, c.value, c.engine); got != rule {
			t.Errorf("%s %q with %q: got %q, want %s", c.engine, c.source, c.value, got, rule)
		}
	}
	misses := []struct{ source, value, engine string }{
		{"Hello {{name}}", "name", "handlebars"},
		{`<%= "ordinary prose" %>`, "ordinary prose", "ejs"},
		{"Hello 7 + 7", "7 + 7", "ejs"},
		{"{{name}}", "absent", "ejs"},
		{"{{x}}", "x", "ejs"},
		// pug attributes
		{"a(href=url) Link", "url", "pug"},
		{`a(title="O'Brien here") Link`, "O'Brien here", "pug"},
		{"p Hello (see the notes) today", "see the notes", "pug"},
		// dotted paths
		{"Hello {{user.name}}", "user.name", "handlebars"},
		{"Hello <%= user.name %>", "user.name", "ejs"},
		// quoted closes
		{`{{shout "a }} b"}} done`, "a }} b", "handlebars"},
		{`{{ "a }} b" | upper }} done`, "a }} b", "nunjucks"},
		{`p #{"a } b"} done`, "a } b", "pug"},
		// escapes and comments
		{`Show \{{name}} literally`, "{{name}}", "handlebars"},
		{"Hi {# note {{ a + b }} #}", "{{ a + b }}", "nunjucks"},
		// unknown engine
		{"{{ a }}", "{{ a }}", "unknown"},
		// go template comments and data-like prose
		{"Hi {{/* a + b */}} there", "a + b", "gotemplate"},
		{"Hello ordinary prose", "ordinary prose", "gotemplate"},
		// review fixes
		{"{%- raw -%}{{ a + b }}{% endraw %}", "{{ a + b }}", "jinja2"},
		{"<p>${a + b}</p>", "${a + b}", "thymeleaf"},
	}
	for _, c := range misses {
		if got := tmplRule(c.source, c.value, c.engine); got != "" {
			t.Errorf("%s %q with %q: got %q, want no finding", c.engine, c.source, c.value, got)
		}
	}
}

func TestTemplateTokensShape(t *testing.T) {
	toks := TemplateTokens("@include(a.b) {{ user.name }}", "blade")
	var kinds, texts []string
	for _, tk := range toks {
		kinds = append(kinds, tk.Kind)
		texts = append(texts, tk.Text)
	}
	wantKinds := []string{"delimiter", "word", "delimiter", "word", "delimiter", "delimiter", "word", "delimiter"}
	wantTexts := []string{"", "include", "", "a.b", "", "", "user.name", ""}
	if !reflect.DeepEqual(kinds, wantKinds) || !reflect.DeepEqual(texts, wantTexts) {
		t.Fatalf("tokens %v %v", kinds, texts)
	}
	if TemplateTokens("{{ a }}", "unknown") != nil {
		t.Fatal("unknown engine has tokens")
	}
}

func TestTemplateHelpersContract(t *testing.T) {
	const input = `{{ printf "%d" 7 }}`
	runSinkContract(t, sinkCase{
		name:   "rasp.ParseTextTemplate",
		attack: CodeInjection,
		inputs: AddInput(nil, input, "query.q"),
		call: func(t *testing.T, ctx context.Context) (bool, error) {
			tpl, err := ParseTextTemplate(ctx, texttemplate.New("x"), "Hello "+input)
			if err != nil {
				return false, err
			}
			var b bytes.Buffer
			return tpl.Execute(&b, nil) == nil && b.String() == "Hello 7", nil
		},
	})
	runSinkContract(t, sinkCase{
		name:   "rasp.ParseHTMLTemplate",
		attack: CodeInjection,
		inputs: AddInput(nil, input, "query.q"),
		call: func(t *testing.T, ctx context.Context) (bool, error) {
			tpl, err := ParseHTMLTemplate(ctx, htmltemplate.New("x"), "Hello "+input)
			if err != nil {
				return false, err
			}
			var b bytes.Buffer
			return tpl.Execute(&b, nil) == nil && b.String() == "Hello 7", nil
		},
	})
	runSinkContract(t, sinkCase{
		name:   "rasp.CheckTemplate",
		attack: CodeInjection,
		inputs: AddInput(nil, "{{ 7 * 7 }}", "query.q"),
		call: func(t *testing.T, ctx context.Context) (bool, error) {
			if err := CheckTemplate(ctx, "jinja2.from_string", "jinja2", "Hello {{ 7 * 7 }}"); err != nil {
				return false, err
			}
			return true, nil
		},
	})
}

func TestTemplateHelperRules(t *testing.T) {
	log := setupEngine(t, engineSettings{mode: ModeBlock})
	n := countChecks(t)
	// Input as data only: the fixed source passes and renders the data.
	ctx := requestCtx(AddInput(nil, "{{ 7 * 7 }}", "query.q"), nil)
	tpl, err := ParseTextTemplate(ctx, texttemplate.New("x"), "Hello {{.}}")
	if err != nil {
		t.Fatal(err)
	}
	var b bytes.Buffer
	if err := tpl.Execute(&b, "{{ 7 * 7 }}"); err != nil || b.String() != "Hello {{ 7 * 7 }}" {
		t.Fatalf("render %q %v", b.String(), err)
	}
	// Ordinary prose in the source passes; an unknown engine is not checked.
	pctx := requestCtx(AddInput(nil, "ordinary prose", "query.q"), nil)
	if _, err := ParseHTMLTemplate(pctx, htmltemplate.New("x"), "Hello ordinary prose"); err != nil {
		t.Fatal(err)
	}
	if err := CheckTemplate(ctx, "", "unknown", "Hello {{ 7 * 7 }}"); err != nil {
		t.Fatal(err)
	}
	// One check per call.
	if got := n.Load(); got != 3 {
		t.Fatalf("%d checks, want 3", got)
	}
	// Events name the sink; the default is <engine>.parse.
	if b := AsBlocked(CheckTemplate(ctx, "", "jinja2", "Hello {{ 7 * 7 }}")); b == nil || b.Rule != "code.template_injection" {
		t.Fatalf("got %v", b)
	}
	if b := AsBlocked(func() error { _, err := ParseTextTemplate(ctx, texttemplate.New("x"), "{{ 7 * 7 }}"); return err }()); b == nil {
		t.Fatal("want block")
	}
	ev := log.all()
	if len(ev) != 2 || ev[0].Attrs["shield360.rasp.sink"] != "jinja2.parse" || ev[1].Attrs["shield360.rasp.sink"] != "text/template.Parse" {
		t.Fatalf("events %v", ev)
	}
}

func TestTemplateModeOffSkipsDetector(t *testing.T) {
	setupEngine(t, engineSettings{mode: ModeBlock, attacks: map[AttackType]Mode{CodeInjection: ModeOff}})
	n := countChecks(t)
	ctx := requestCtx(AddInput(nil, "{{ 7 * 7 }}", "query.q"), nil)
	if err := CheckTemplate(ctx, "", "gotemplate", "{{ 7 * 7 }}"); err != nil || n.Load() != 0 {
		t.Fatalf("err=%v checks=%d", err, n.Load())
	}
}
