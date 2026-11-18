package rasp

import (
	"context"
	htmltemplate "html/template"
	"regexp"
	"strings"
	texttemplate "text/template"
)

// Template source (README "Template source", code.template_injection):
// request input that becomes part of a template's source, not its data, in
// a parse or compile call. Go has no runtime patching, so the sinks are the
// checked helpers below: ParseTextTemplate and ParseHTMLTemplate for the
// standard library's (*Template).Parse (engine "gotemplate"), and
// CheckTemplate for any engine of the shared table. Data passed to Execute
// is never template source and is not checked.

// Template close modes: where a pair's region ends.
const (
	closeFirst   = "first"   // the first close, quoted or not
	closeQuoted  = "quoted"  // the first close outside "/' strings
	closeBracket = "bracket" // the bracket closing depth zero
)

// TemplatePair is an expression or code region: open, close and close mode.
type TemplatePair struct{ Open, Close, Mode string }

// TemplateDelims is an [open, close] pair of a literal block or tag.
type TemplateDelims struct{ Open, Close string }

// TemplateSyntax is one engine's syntax (README "Engine table"). Order
// inside each list matters: the first match wins.
type TemplateSyntax struct {
	Pairs        []TemplatePair
	Literal      []TemplateDelims
	Tags         []TemplateDelims
	Directives   []string
	LineComment  []string
	LineCode     []string
	Attrs        []string
	Escape       string
	SpaceLiteral bool
	Pug          bool
}

// TemplateEngineEntry names one engine of the table.
type TemplateEngineEntry struct {
	Name   string
	Syntax TemplateSyntax
}

var jinjaPairs = []TemplatePair{{"{{", "}}", closeQuoted}, {"{%", "%}", closeQuoted}}

// TemplateEngines is the contract table sdk/rasp/rules/template-engines.json,
// in its order (a test compares the two).
var TemplateEngines = []TemplateEngineEntry{
	{"handlebars", TemplateSyntax{
		Pairs:   []TemplatePair{{"{{{", "}}}", closeQuoted}, {"{{", "}}", closeQuoted}},
		Literal: []TemplateDelims{{"{{!--", "--}}"}, {"{{!", "}}"}},
		Escape:  `\`,
	}},
	{"ejs", TemplateSyntax{
		Pairs:   []TemplatePair{{"<%", "%>", closeFirst}},
		Literal: []TemplateDelims{{"<%#", "%>"}},
	}},
	{"lodash", TemplateSyntax{
		Pairs:   []TemplatePair{{"<%", "%>", closeFirst}, {"${", "}", closeFirst}},
		Literal: []TemplateDelims{{"<%#", "%>"}},
	}},
	{"pug", TemplateSyntax{
		Pairs: []TemplatePair{{"#{", "}", closeBracket}, {"!{", "}", closeBracket}},
		Pug:   true,
	}},
	{"nunjucks", TemplateSyntax{Pairs: jinjaPairs, Literal: []TemplateDelims{{"{#", "#}"}, {"{% raw %}", "{% endraw %}"}}}},
	{"jinja2", TemplateSyntax{Pairs: jinjaPairs, Literal: []TemplateDelims{{"{#", "#}"}, {"{% raw %}", "{% endraw %}"}}}},
	{"minijinja", TemplateSyntax{Pairs: jinjaPairs, Literal: []TemplateDelims{{"{#", "#}"}, {"{% raw %}", "{% endraw %}"}}}},
	{"tera", TemplateSyntax{Pairs: jinjaPairs, Literal: []TemplateDelims{{"{#", "#}"}, {"{% raw %}", "{% endraw %}"}}}},
	{"twig", TemplateSyntax{Pairs: jinjaPairs, Literal: []TemplateDelims{{"{#", "#}"}, {"{% verbatim %}", "{% endverbatim %}"}}}},
	{"pebble", TemplateSyntax{Pairs: jinjaPairs, Literal: []TemplateDelims{{"{#", "#}"}, {"{% verbatim %}", "{% endverbatim %}"}}}},
	{"django", TemplateSyntax{
		Pairs:   []TemplatePair{{"{{", "}}", closeFirst}, {"{%", "%}", closeFirst}},
		Literal: []TemplateDelims{{"{#", "#}"}, {"{% comment %}", "{% endcomment %}"}, {"{% verbatim %}", "{% endverbatim %}"}},
	}},
	{"liquid", TemplateSyntax{Pairs: jinjaPairs, Literal: []TemplateDelims{{"{% comment %}", "{% endcomment %}"}, {"{% raw %}", "{% endraw %}"}}}},
	{"scriban", TemplateSyntax{
		Pairs:   []TemplatePair{{"{{", "}}", closeQuoted}},
		Literal: []TemplateDelims{{"{%{", "}%}"}},
	}},
	{"gotemplate", TemplateSyntax{
		Pairs:   []TemplatePair{{"{{", "}}", closeQuoted}},
		Literal: []TemplateDelims{{"{{/*", "*/"}, {"{{- /*", "*/"}},
	}},
	{"mako", TemplateSyntax{
		Pairs:       []TemplatePair{{"${", "}", closeBracket}, {"<%", "%>", closeFirst}},
		Literal:     []TemplateDelims{{"<%doc>", "</%doc>"}, {"<%text>", "</%text>"}},
		Tags:        []TemplateDelims{{"<%", ">"}, {"</%", ">"}},
		LineComment: []string{"##"},
		LineCode:    []string{"%"},
	}},
	{"freemarker", TemplateSyntax{
		Pairs:   []TemplatePair{{"${", "}", closeBracket}, {"#{", "}", closeBracket}},
		Literal: []TemplateDelims{{"<#--", "-->"}, {"<#noparse>", "</#noparse>"}},
		Tags:    []TemplateDelims{{"<#", ">"}, {"</#", ">"}, {"<@", ">"}, {"</@", ">"}},
	}},
	{"velocity", TemplateSyntax{
		Pairs:      []TemplatePair{{"$!{", "}", closeBracket}, {"${", "}", closeBracket}},
		Literal:    []TemplateDelims{{"#*", "*#"}, {"##", "\n"}, {"#[[", "]]#"}},
		Directives: []string{"$!", "$", "#"},
		Escape:     `\`,
	}},
	{"thymeleaf", TemplateSyntax{
		Pairs:   []TemplatePair{{"[[", "]]", closeQuoted}, {"[(", ")]", closeQuoted}},
		Literal: []TemplateDelims{{"<!--/*", "*/-->"}},
		Attrs:   []string{"th:", "data-th-"},
	}},
	{"smarty", TemplateSyntax{
		Pairs:        []TemplatePair{{"{", "}", closeQuoted}},
		Literal:      []TemplateDelims{{"{*", "*}"}, {"{literal}", "{/literal}"}},
		SpaceLiteral: true,
	}},
	{"blade", TemplateSyntax{
		Pairs:      []TemplatePair{{"{!!", "!!}", closeFirst}, {"{{", "}}", closeFirst}, {"@php", "@endphp", closeFirst}},
		Literal:    []TemplateDelims{{"{{--", "--}}"}, {"@verbatim", "@endverbatim"}},
		Directives: []string{"@"},
		Escape:     "@",
	}},
}

var templateEngineIndex = func() map[string]*TemplateSyntax {
	m := make(map[string]*TemplateSyntax, len(TemplateEngines))
	for i := range TemplateEngines {
		m[TemplateEngines[i].Name] = &TemplateEngines[i].Syntax
	}
	return m
}()

// Pug line patterns. Go's \w and \s are ASCII.
var (
	pugMarker = regexp.MustCompile(`^\s*(?:-\s*|(?:[\w.#-]+\s*)?!?=\s*)`)
	pugTag    = regexp.MustCompile(`^\s*\+?[\w.#:-]+`)
	pugRest   = regexp.MustCompile(`^!?=\s*`)
)

func isTmplWord(c byte) bool { return isIDStartByte(c) || isDigitByte(c) }
func isTmplAttrChar(c byte) bool {
	return isTmplWord(c) || c == ':' || c == '-'
}

// skipQuoted is the index just past a quoted run starting at i (s[i] is the
// quote).
func skipQuoted(s string, i int) int {
	q := s[i]
	k := i + 1
	for k < len(s) && s[k] != q {
		if s[k] == '\\' {
			k += 2
		} else {
			k++
		}
	}
	return min(len(s), k+1)
}

// quotedClose is the first close outside quoted strings, or -1.
func quotedClose(s string, from int, close string) int {
	for i := from; i < len(s); {
		if c := s[i]; c == '"' || c == '\'' {
			i = skipQuoted(s, i)
			continue
		}
		if strings.HasPrefix(s[i:], close) {
			return i
		}
		i++
	}
	return -1
}

// bracketClose is the bracket closing depth zero, skipping quoted strings
// and nested brackets, or -1.
func bracketClose(s string, from int) int {
	depth := 0
	for i := from; i < len(s); {
		c := s[i]
		if c == '"' || c == '\'' || c == '`' {
			i = skipQuoted(s, i)
			continue
		}
		switch c {
		case '(', '[', '{':
			depth++
		case ')', ']', '}':
			if depth == 0 {
				return i
			}
			depth--
		}
		i++
	}
	return -1
}

// indexFrom is strings.Index from an offset, or -1.
func indexFrom(s, sub string, from int) int {
	if from > len(s) {
		return -1
	}
	if k := strings.Index(s[from:], sub); k >= 0 {
		return from + k
	}
	return -1
}

// literalAt is the end of literal-block pattern matched at i, or -1; a
// space in pattern matches any run of whitespace, '-', '+' and '~'.
func literalAt(s string, i int, pattern string) int {
	k := i
	for p := 0; p < len(pattern); p++ {
		c := pattern[p]
		switch {
		case c == ' ':
			for k < len(s) && (isSpaceByte(s[k]) || s[k] == '-' || s[k] == '+' || s[k] == '~') {
				k++
			}
		case k < len(s) && s[k] == c:
			k++
		default:
			return -1
		}
	}
	return k
}

// regionCode is the code tokens of a region body. Template expressions have
// no // or /* comments: both are operators.
func regionCode(body string) []Token {
	var out []Token
	for pos := 0; pos < len(body); {
		resume := -1
		for _, t := range CodeTokens(body[pos:]) {
			st := pos + t.S
			if t.Kind == "comment" {
				out = append(out, Token{S: st, E: st + 1, Kind: "op", Text: "/"}, Token{S: st + 1, E: st + 2, Kind: "op", Text: body[st+1 : st+2]})
				resume = st + 2
				break
			}
			t.S, t.E = st, pos+t.E
			out = append(out, t)
		}
		if resume < 0 {
			break
		}
		pos = resume
	}
	return out
}

// mergePaths joins a dotted property path (user.name) into one word token.
func mergePaths(tokens []Token) []Token {
	out := make([]Token, 0, len(tokens))
	for i := 0; i < len(tokens); i++ {
		t := tokens[i]
		for t.Kind == "word" && i+2 < len(tokens) && tokens[i+1].Text == "." && tokens[i+1].S == t.E &&
			tokens[i+2].Kind == "word" && tokens[i+2].S == tokens[i+1].E {
			t = Token{S: t.S, E: tokens[i+2].E, Kind: t.Kind, Text: t.Text + "." + tokens[i+2].Text}
			i += 2
		}
		out = append(out, t)
	}
	return out
}

// TemplateTokens are the boundary delimiters ("delimiter") plus the code
// tokens of each expression region of source; literal text yields nothing.
// An engine missing from the table yields nil. Offsets are bytes.
func TemplateTokens(source, engine string) []Token {
	syn := templateEngineIndex[engine]
	if syn == nil {
		return nil
	}
	s := *syn
	var tokens []Token
	region := func(start, open, end, close int) {
		tokens = append(tokens, Token{S: start, E: start + open, Kind: "delimiter"})
		base := start + open
		for _, t := range mergePaths(regionCode(source[base:end])) {
			t.S += base
			t.E += base
			tokens = append(tokens, t)
		}
		if close > 0 {
			tokens = append(tokens, Token{S: end, E: end + close, Kind: "delimiter"})
		}
	}
	lineEndAt := func(i int) int {
		if e := indexFrom(source, "\n", i); e >= 0 {
			return e
		}
		return len(source)
	}
	hasAt := func(p string, i int) bool { return i >= 0 && i <= len(source) && strings.HasPrefix(source[i:], p) }
	n := len(source)
scan:
	for i := 0; i < n; {
		lineStart := i == 0 || source[i-1] == '\n'
		if s.Pug && lineStart {
			lineEnd := lineEndAt(i)
			line := source[i:lineEnd]
			// Pug's line code and buffered expressions; tag/text lines stay literal.
			if m := pugMarker.FindStringIndex(line); m != nil {
				region(i, m[1], lineEnd, 0)
				i = lineEnd
				continue
			}
			// Tag or mixin attributes are JavaScript: a(href=url), +card(item).
			if loc := pugTag.FindStringIndex(line); loc != nil && byteAt(source, i+loc[1]) == '(' {
				open := i + loc[1]
				if cl := bracketClose(source, open+1); cl >= 0 {
					region(open, 1, cl, 1)
					i = cl + 1
					restEnd := lineEndAt(i)
					if rl := pugRest.FindStringIndex(source[i:restEnd]); rl != nil {
						region(i, rl[1], restEnd, 0)
						i = restEnd
					}
					continue
				}
			}
		}
		if lineStart && (len(s.LineComment) > 0 || len(s.LineCode) > 0) {
			j := i
			for j < n && (source[j] == ' ' || source[j] == '\t') {
				j++
			}
			lineEnd := lineEndAt(i)
			for _, p := range s.LineComment {
				if hasAt(p, j) {
					i = lineEnd
					continue scan
				}
			}
			for _, p := range s.LineCode {
				if hasAt(p, j) && !hasAt(p, j+len(p)) {
					region(i, j+len(p)-i, lineEnd, 0)
					i = lineEnd
					continue scan
				}
			}
		}
		// First match wins: literal blocks, tags, attributes, pairs, directives.
		var literal, tag *TemplateDelims
		var pair *TemplatePair
		attr, directive := "", ""
		quote := -1
		for k := range s.Literal {
			if literalAt(source, i, s.Literal[k].Open) >= 0 {
				literal = &s.Literal[k]
				break
			}
		}
		if literal == nil {
			for k := range s.Tags {
				if p := s.Tags[k].Open; hasAt(p, i) && isIDStartByte(byteAt(source, i+len(p))) {
					tag = &s.Tags[k]
					break
				}
			}
		}
		if literal == nil && tag == nil && (i == 0 || isSpaceByte(source[i-1])) {
			for _, p := range s.Attrs {
				if !hasAt(p, i) {
					continue
				}
				k := i + len(p)
				for k < n && isTmplAttrChar(source[k]) {
					k++
				}
				if k == i+len(p) {
					continue
				}
				for k < n && isSpaceByte(source[k]) {
					k++
				}
				if byteAt(source, k) != '=' {
					continue
				}
				k++
				for k < n && isSpaceByte(source[k]) {
					k++
				}
				if c := byteAt(source, k); c == '"' || c == '\'' {
					attr, quote = p, k
					break
				}
			}
		}
		if literal == nil && tag == nil && attr == "" {
			for k := range s.Pairs {
				if hasAt(s.Pairs[k].Open, i) {
					pair = &s.Pairs[k]
					break
				}
			}
		}
		if literal == nil && tag == nil && attr == "" && pair == nil {
			for _, p := range s.Directives {
				if hasAt(p, i) && isIDStartByte(byteAt(source, i+len(p))) && !(i > 0 && isTmplWord(source[i-1])) {
					directive = p
					break
				}
			}
		}
		var opener string
		switch {
		case literal != nil:
		case tag != nil:
			opener = tag.Open
		case attr != "":
			opener = attr
		case pair != nil:
			opener = pair.Open
		case directive != "":
			opener = directive
		default:
			i++
			continue
		}
		from := i + len(opener)
		if literal != nil {
			from = literalAt(source, i, literal.Open)
		}
		// An escaped opener (\{{, @{{) is literal; a doubled escape (\\{{) leaves it live.
		if s.Escape != "" && i > 0 && source[i-1] == s.Escape[0] && !(i > 1 && source[i-2] == s.Escape[0]) {
			i = from
			continue
		}
		switch {
		case literal != nil:
			i = n
			for j := from; j < n; j++ {
				if e := literalAt(source, j, literal.Close); e >= 0 {
					i = e
					break
				}
			}
		case tag != nil:
			e := quotedClose(source, from, tag.Close)
			if e < 0 {
				i = from
				continue
			}
			region(i, len(tag.Open), e, len(tag.Close))
			i = e + len(tag.Close)
		case attr != "":
			e := indexFrom(source, source[quote:quote+1], quote+1)
			if e < 0 {
				i = from
				continue
			}
			region(quote, 1, e, 1)
			i = e + 1
		case directive != "":
			tokens = append(tokens, Token{S: i, E: from, Kind: "delimiter"})
			k := from
			for k < n && (isTmplWord(source[k]) || source[k] == '.') {
				k++
			}
			for k > from && source[k-1] == '.' {
				k--
			}
			tokens = append(tokens, Token{S: from, E: k, Kind: "word", Text: source[from:k]})
			i = k
			if byteAt(source, k) == '(' {
				if cl := bracketClose(source, k+1); cl >= 0 {
					region(k, 1, cl, 1)
					i = cl + 1
				}
			}
		default:
			if s.SpaceLiteral && from < n && isSpaceByte(source[from]) {
				i = from
				continue
			}
			// Closing delimiters inside quotes end an expression only where the engine ignores quotes.
			var e int
			switch pair.Mode {
			case closeBracket:
				e = bracketClose(source, from)
			case closeQuoted:
				e = quotedClose(source, from, pair.Close)
			default:
				e = indexFrom(source, pair.Close, from)
			}
			if e < 0 {
				i = from
				continue
			}
			region(i, len(pair.Open), e, len(pair.Close))
			i = e + len(pair.Close)
		}
	}
	return tokens
}

// DetectTemplate runs code.template_injection on a template source: an
// input of length >= 3 that overlaps a template boundary or spans at least
// two expression tokens. An engine missing from the table is not checked.
func DetectTemplate(source string, inputs []Input, engine string) *Finding {
	if source == "" || templateEngineIndex[engine] == nil {
		return nil
	}
	var tokens []Token
	lexed := false
	for i := range inputs {
		v := inputs[i].Value
		if charLen(v) < 3 {
			continue
		}
		for _, idx := range Occurrences(source, v, 8) {
			if !lexed {
				tokens, lexed = TemplateTokens(source, engine), true
			}
			span := Overlapping(tokens, idx, len(v))
			if len(span) >= 2 {
				return found(CodeInjection, "code.template_injection", &inputs[i])
			}
			for _, t := range span {
				if t.Kind == "delimiter" {
					return found(CodeInjection, "code.template_injection", &inputs[i])
				}
			}
		}
	}
	return nil
}

// CheckTemplate checks template source about to be parsed or compiled by
// engine, a name from TemplateEngines (code.template_injection). Pass only
// the source, never the data. sink names the call site in events (default
// "<engine>.parse"). It returns only the block error.
func CheckTemplate(ctx context.Context, sink, engine, source string) error {
	if !Active() || source == "" || ModeFor(CodeInjection) == ModeOff {
		return nil
	}
	inputs := inputsOf(ctx)
	if len(inputs) == 0 {
		return nil
	}
	return checkSink(ctx, sinkName(sink, sinkName(engine+".parse", "template.parse")), func(*iastSlot) *Finding {
		return DetectTemplate(source, inputs, engine)
	})
}

// ParseTextTemplate is t.Parse(text) for text/template with RASP checks:
// in block mode a tainted source returns the block error and t is not
// changed.
func ParseTextTemplate(ctx context.Context, t *texttemplate.Template, text string) (*texttemplate.Template, error) {
	if err := CheckTemplate(ctx, "text/template.Parse", "gotemplate", text); err != nil {
		return nil, err
	}
	return t.Parse(text)
}

// ParseHTMLTemplate is t.Parse(text) for html/template with RASP checks:
// in block mode a tainted source returns the block error and t is not
// changed.
func ParseHTMLTemplate(ctx context.Context, t *htmltemplate.Template, text string) (*htmltemplate.Template, error) {
	if err := CheckTemplate(ctx, "html/template.Parse", "gotemplate", text); err != nil {
		return nil, err
	}
	return t.Parse(text)
}
