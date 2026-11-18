package rasp

import (
	"regexp"
	"strings"
	"unicode"
)

// Passive IAST rules (README "Passive IAST"). Pure: each takes what a
// detector already computed (the sink text, its tokens, the inputs) and says
// whether a request input reaches the sink verbatim in a place the app did
// not parameterize, even though the value is harmless and the attack check
// found nothing. The detectors call them through an iastSlot only when
// passive IAST is armed for the current check, so the rules never run, and
// never lex, when it is off.

// VulnRules are the passive IAST rules of the contract.
var VulnRules = []string{
	"vuln.sql_concat",
	"vuln.cmd_shell",
	"vuln.cmd_arg",
	"vuln.path_from_input",
	"vuln.ssrf_host",
	"vuln.code_eval",
	"vuln.include_from_input",
	"vuln.deser_input",
	"vuln.xml_external",
}

// vuln is a vulnerability a rule found: the rule, the input and where in the
// sink argument the input sits.
type vuln struct {
	rule     string
	input    Input
	position string
}

// IAST thresholds (README "Thresholds").
const (
	iastMinLength       = 3
	iastMinWordLength   = 8
	iastMinNumberLength = 4
)

var (
	boringWords   = wordSet("true false null none nil undefined yes no on off asc desc")
	lettersOnly   = regexp.MustCompile(`^[A-Za-z]+$`)
	numberLike    = regexp.MustCompile(`^[0-9.+-]+$`)
	letterOrDigit = func(r rune) bool { return unicode.IsLetter(r) || unicode.IsNumber(r) }
)

// iastQualifies reports whether an input value is specific enough that
// finding it verbatim in a sink means it came from the request, not a
// coincidence with a literal the app wrote itself.
func iastQualifies(v string) bool {
	n := charLen(v)
	if n < iastMinLength {
		return false
	}
	if boringWords[strings.ToLower(v)] {
		return false
	}
	if lettersOnly.MatchString(v) && n < iastMinWordLength {
		return false
	}
	if numberLike.MatchString(v) && n < iastMinNumberLength {
		return false
	}
	first := []rune(v)[0]
	same := true
	for _, r := range v {
		if r != first {
			same = false
			break
		}
	}
	if same {
		return false
	}
	// Only spaces and punctuation.
	return strings.IndexFunc(v, letterOrDigit) >= 0
}

func iastCandidates(inputs []Input) []*Input {
	var out []*Input
	for i := range inputs {
		if inputs[i].Source == SourceRequest && iastQualifies(inputs[i].Value) {
			out = append(out, &inputs[i])
		}
	}
	return out
}

func newVuln(rule string, in *Input, position string) *vuln {
	return &vuln{rule: rule, input: *in, position: position}
}

// vulnSQL is vuln.sql_concat: an input sits in the query inside a string
// literal, as a whole number literal, as a whole identifier (not a keyword),
// or as a run of whole tokens the attack check let through (a sort list).
// Never inside a comment, never when the input is the whole query.
func vulnSQL(query string, inputs []Input, tokens func() []Token) *vuln {
	trimmed := jsTrim(query)
	for _, inp := range iastCandidates(inputs) {
		v := inp.Value
		if v == query || jsTrim(v) == trimmed {
			continue
		}
		for _, idx := range Occurrences(query, v, 8) {
			over := Overlapping(tokens(), idx, len(v))
			if len(over) == 0 || anyComment(over) {
				continue
			}
			end := idx + len(v)
			if len(over) == 1 {
				t := over[0]
				if t.Kind == "string" && idx > t.S && end <= t.E {
					return newVuln("vuln.sql_concat", inp, "string")
				}
				whole := t.S == idx && t.E == end
				if whole && t.Kind == "number" {
					return newVuln("vuln.sql_concat", inp, "number")
				}
				if whole && t.Kind == "name" {
					return newVuln("vuln.sql_concat", inp, "identifier")
				}
				if whole && t.Kind == "word" && !antiDetect[strings.ToLower(t.Text)] {
					return newVuln("vuln.sql_concat", inp, "identifier")
				}
				continue
			}
			if over[0].S == idx && over[len(over)-1].E == end {
				return newVuln("vuln.sql_concat", inp, "tokens")
			}
		}
	}
	return nil
}

func anyComment(ts []Token) bool {
	for _, t := range ts {
		if isCommentToken(t) {
			return true
		}
	}
	return false
}

// vulnShell is vuln.cmd_shell: an input sits inside one word of a
// shell-interpreted command.
func vulnShell(command string, inputs []Input, tokens []Token) *vuln {
	trimmed := jsTrim(command)
	for _, inp := range iastCandidates(inputs) {
		v := inp.Value
		if jsTrim(v) == trimmed {
			continue
		}
		for _, idx := range Occurrences(command, v, 8) {
			over := Overlapping(tokens, idx, len(v))
			if len(over) == 1 && over[0].Kind == "word" {
				return newVuln("vuln.cmd_shell", inp, "word")
			}
		}
	}
	return nil
}

// vulnArgv is vuln.cmd_arg: an argument (not the executable) of an argv
// spawn without a shell contains an input. The caller skips sh -c spawns.
func vulnArgv(argv []string, inputs []Input) *vuln {
	for _, inp := range iastCandidates(inputs) {
		for k := 1; k < len(argv); k++ {
			if strings.Contains(argv[k], inp.Value) {
				return newVuln("vuln.cmd_arg", inp, "argument")
			}
		}
	}
	return nil
}

// vulnPath is vuln.path_from_input: an input (normalized like the path)
// forms whole path segments: it starts at a segment start and ends at a
// segment end, or right before a `.` in it.
func vulnPath(np string, inputs []Input) *vuln {
	for _, inp := range iastCandidates(inputs) {
		ni := NormPath(inp.Value)
		if ni == "" || ni == "/" {
			continue
		}
		for _, idx := range Occurrences(np, ni, 8) {
			end := idx + len(ni)
			startOk := idx == 0 || np[idx-1] == '/' || strings.HasPrefix(ni, "/")
			endOk := end == len(np) || np[end] == '/' || np[end] == '.' || strings.HasSuffix(ni, "/")
			if startOk && endOk {
				return newVuln("vuln.path_from_input", inp, "segment")
			}
		}
	}
	return nil
}

var urlScheme = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9+.-]*://`)

// authorityOf returns the host[:port] of a URL as written (lower-cased) and
// the offset just past the host itself (after any userinfo).
func authorityOf(u, host string) (authority string, hostEnd int, ok bool) {
	m := urlScheme.FindString(u)
	if m == "" {
		return "", 0, false
	}
	rest := u[len(m):]
	auth := rest
	if end := strings.IndexAny(rest, "/?#\\"); end >= 0 {
		auth = rest[:end]
	}
	at := strings.LastIndexByte(auth, '@')
	hostStart := len(m) + at + 1
	bracket := 0
	if byteAt(u, hostStart) == '[' {
		bracket = 2
	}
	return strings.ToLower(auth[at+1:]), hostStart + len(host) + bracket, true
}

// vulnSSRF is vuln.ssrf_host: the URL's host is an input (equal to the
// host, host:port or [host]), or an input is a prefix of the URL reaching
// past the destination host (a base URL or whole URL from the request).
func vulnSSRF(u, host string, inputs []Input) *vuln {
	authority := ""
	var hostEnd int
	if host != "" {
		a, end, ok := authorityOf(u, host)
		authority = a
		if ok {
			hostEnd = end
		} else {
			hostEnd = len(u) + 1
		}
	} else {
		hostEnd = strings.IndexByte(u, ':') + 1
	}
	for _, inp := range iastCandidates(inputs) {
		v := strings.ToLower(inp.Value)
		if host != "" && (v == host || v == authority || v == "["+host+"]") {
			return newVuln("vuln.ssrf_host", inp, "host")
		}
		if strings.HasPrefix(u, inp.Value) && len(inp.Value) >= hostEnd && (host != "" || len(inp.Value) > hostEnd) {
			return newVuln("vuln.ssrf_host", inp, "url")
		}
	}
	return nil
}

// vulnCode is vuln.code_eval: an input sits inside a string literal of
// evaluated code, or is a whole identifier or number in it.
func vulnCode(code string, inputs []Input, tokens func() []Token) *vuln {
	for _, inp := range iastCandidates(inputs) {
		v := inp.Value
		if v == code {
			continue
		}
		for _, idx := range Occurrences(code, v, 8) {
			over := Overlapping(tokens(), idx, len(v))
			if len(over) != 1 {
				continue
			}
			t := over[0]
			end := idx + len(v)
			if t.Kind == "string" && idx > t.S && end <= t.E {
				return newVuln("vuln.code_eval", inp, "string")
			}
			if t.S == idx && t.E == end && (t.Kind == "word" || t.Kind == "number") {
				pos := "number"
				if t.Kind == "word" {
					pos = "identifier"
				}
				return newVuln("vuln.code_eval", inp, pos)
			}
		}
	}
	return nil
}

// vulnInclude is vuln.include_from_input: a module specifier contains an
// input (the attack check covers equal and path-like inputs). Go has no
// include sink; the rule is kept for the shared corpus.
func vulnInclude(specifier string, inputs []Input) *vuln {
	for _, inp := range iastCandidates(inputs) {
		if inp.Value != specifier && strings.Contains(specifier, inp.Value) {
			return newVuln("vuln.include_from_input", inp, "specifier")
		}
	}
	return nil
}

// vulnData is vuln.deser_input / vuln.xml_external: the data handed to an
// unsafe deserializer, or to an XML parser that resolves external entities,
// is tainted, at least 3 characters long, by an input that qualifies.
func vulnData(rule, data string, inp *Input) *vuln {
	if inp == nil || inp.Source != SourceRequest || charLen(data) < iastMinLength || !iastQualifies(inp.Value) {
		return nil
	}
	return newVuln(rule, inp, "data")
}

func requestOnly(inputs []Input) []Input {
	var out []Input
	for _, in := range inputs {
		if in.Source == SourceRequest {
			out = append(out, in)
		}
	}
	return out
}

// iastSlot is where one check's detectors note a vulnerability (README
// "Passive IAST"): Check arms one for a sampled check while passive IAST is
// on and hands it to the detectors; a nil slot (the usual case) costs one
// comparison per detector call. It belongs to one check on one goroutine.
type iastSlot struct {
	vuln *vuln
}

// note runs a rule when the slot is armed and keeps the first result. A rule
// that panics is ignored: passive IAST never breaks a check.
func (s *iastSlot) note(rule func() *vuln) {
	if s == nil || s.vuln != nil {
		return
	}
	defer func() { _ = recover() }()
	s.vuln = rule()
}
