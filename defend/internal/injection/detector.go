// Package injection finds prompt injection in text an AI agent is about to
// read: a developer's prompt (direct injection), and tool results, files,
// fetched pages and tool descriptions (indirect injection and tool
// poisoning), plus the URL beacons attackers use to get data back out.
//
// It is deterministic and local: a versioned rule set (rules.json, shared
// byte for byte with the platform's TypeScript detector) of patterns and a
// few structural checks (invisible Unicode, encoded blobs). It reports a
// score, the rules that matched and where — never the text itself beyond a
// short masked snippet.
//
// Heuristics can be evaded; this is a tripwire that catches the common and
// the published, not a proof of safety.
package injection

import (
	"crypto/hmac"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	"regexp"
	"sort"
	"strings"
	"unicode/utf8"
)

//go:embed rules.json
var rulesJSON []byte

// Source is what kind of content is being scanned. Some rules only make sense
// for some sources (a tool description, tool arguments), and some weigh less
// in others (chat-template tokens in a source file are usually just code).
type Source string

const (
	SourcePrompt          Source = "prompt"
	SourceToolResult      Source = "tool_result"
	SourceToolDescription Source = "tool_description"
	SourceToolArgs        Source = "tool_args"
	SourceContext         Source = "context"
	SourceDocument        Source = "document"
	SourceFile            Source = "file"
)

// Rule is one entry of rules.json.
type Rule struct {
	ID          string             `json:"id"`
	Category    string             `json:"category"`
	Kind        string             `json:"kind,omitempty"`
	Description string             `json:"description"`
	Weight      float64            `json:"weight"`
	Weights     map[string]float64 `json:"weights,omitempty"`
	Sources     []string           `json:"sources,omitempty"`
	// Any: literal substrings (folded, see fold) one of which a text must
	// contain for Patterns to be tried. A speed-up only.
	Any      []string `json:"any,omitempty"`
	Patterns []string `json:"patterns,omitempty"`
	Within   []string `json:"within,omitempty"`
	Decoded  bool     `json:"decoded,omitempty"`
	Min      int      `json:"min,omitempty"`

	patterns []*regexp.Regexp
	within   []*regexp.Regexp
}

// RuleSet is rules.json.
type RuleSet struct {
	Version      string  `json:"version"`
	Threshold    float64 `json:"threshold"`
	MaxScanChars int     `json:"maxScanChars"`
	SnippetChars int     `json:"snippetChars"`
	MaxSpans     int     `json:"maxSpans"`
	Rules        []*Rule `json:"rules"`
}

// Span is a match's position, in Unicode code points from the start of the
// scanned text (the same numbers the TypeScript detector reports).
type Span [2]int

// Match is one rule that fired.
type Match struct {
	Rule     string  `json:"rule"`
	Category string  `json:"category"`
	Weight   float64 `json:"weight"`
	Spans    []Span  `json:"spans"`
	// Snippet: a short, masked view of the first match, for a reviewer.
	Snippet string `json:"snippet"`
	// Fingerprint: keyed hash of the matched text, so the same payload can be
	// recognised across events without storing it. Empty without a key.
	Fingerprint string `json:"fingerprint,omitempty"`
}

// Result is what a scan found.
type Result struct {
	Version    string   `json:"version"`
	Score      float64  `json:"score"`
	Threshold  float64  `json:"threshold"`
	Detected   bool     `json:"detected"`
	Categories []string `json:"categories"`
	Matches    []Match  `json:"matches"`
}

// RuleIDs lists the rules that matched, sorted.
func (r Result) RuleIDs() []string {
	ids := make([]string, 0, len(r.Matches))
	for _, m := range r.Matches {
		ids = append(ids, m.Rule)
	}
	return ids
}

// Options for one scan.
type Options struct {
	Source Source
	// FingerprintKey keys match fingerprints (the organisation's guard key).
	FingerprintKey string
}

var defaultRules = mustLoad(rulesJSON)

// Rules returns the embedded rule set.
func Rules() *RuleSet { return defaultRules }

// RulesJSON returns the embedded rules file, byte for byte.
func RulesJSON() []byte { return rulesJSON }

func mustLoad(raw []byte) *RuleSet {
	rs, err := Load(raw)
	if err != nil {
		panic(err)
	}
	return rs
}

// Load parses and compiles a rules file.
func Load(raw []byte) (*RuleSet, error) {
	var rs RuleSet
	if err := json.Unmarshal(raw, &rs); err != nil {
		return nil, err
	}
	for _, r := range rs.Rules {
		for i, lit := range r.Any {
			r.Any[i] = fold(lit)
		}
		for _, p := range r.Patterns {
			re, err := regexp.Compile("(?i)" + p)
			if err != nil {
				return nil, fmt.Errorf("rule %s: %w", r.ID, err)
			}
			r.patterns = append(r.patterns, re)
		}
		for _, p := range r.Within {
			re, err := regexp.Compile("(?i)" + p)
			if err != nil {
				return nil, fmt.Errorf("rule %s: %w", r.ID, err)
			}
			r.within = append(r.within, re)
		}
	}
	return &rs, nil
}

// Scan checks text with the embedded rules.
func Scan(text string, opts Options) Result { return defaultRules.Scan(text, opts) }

func (r *Rule) appliesTo(source Source) bool {
	if len(r.Sources) == 0 {
		return true
	}
	for _, s := range r.Sources {
		if s == string(source) {
			return true
		}
	}
	return false
}

func (r *Rule) weightFor(source Source) float64 {
	if w, ok := r.Weights[string(source)]; ok {
		return w
	}
	return r.Weight
}

// ---------------------------------------------------------------------------
// Characters.

// jsWhitespace is every code point JavaScript's \s matches. Each becomes a
// plain space (or \n) before matching, so \s means the same in both engines.
func isJSWhitespace(r rune) bool {
	switch r {
	case '\t', '\n', '\v', '\f', '\r', ' ', 0x00A0, 0x1680, 0x2028, 0x2029, 0x202F, 0x205F, 0x3000, 0xFEFF:
		return true
	}
	return r >= 0x2000 && r <= 0x200A
}

func normaliseRune(r rune) rune {
	switch {
	case r == '\n' || r == '\r' || r == 0x2028 || r == 0x2029:
		return '\n'
	case isJSWhitespace(r):
		return ' '
	}
	return r
}

func isTag(r rune) bool { return r >= 0xE0000 && r <= 0xE007F }

func isBidi(r rune) bool { return (r >= 0x202A && r <= 0x202E) || (r >= 0x2066 && r <= 0x2069) }

// isZeroWidth: characters with no width that carry no meaning in ordinary
// text. U+200C/U+200D (joiners) are left out: emoji and several scripts need them.
func isZeroWidth(r rune) bool {
	switch r {
	case 0x200B, 0x2060, 0x2061, 0x2062, 0x2063, 0x2064, 0x180E, 0xFEFF:
		return true
	}
	return false
}

// isInvisible: removed to build the cleaned view.
func isInvisible(r rune) bool {
	return isZeroWidth(r) || r == 0x200C || r == 0x200D || isTag(r) || isBidi(r) || r == 0x00AD || r == 0x200E || r == 0x200F
}

func isASCIILetter(r rune) bool { return (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') }

// ---------------------------------------------------------------------------
// Views of the text. Each maps its code points back to the original's, so a
// match anywhere is reported where it is in what was scanned.

type view struct {
	text   string
	folded string
	runes  []rune
	// origin[i]: the original code point view rune i came from.
	origin []int
	// runeAt[b]: the rune index of byte b of text.
	runeAt []int
}

func newView(runes []rune, origin []int) *view {
	v := &view{runes: runes, origin: origin, text: string(runes)}
	v.runeAt = make([]int, len(v.text)+1)
	i := 0
	for b := 0; b < len(v.text); {
		_, size := utf8.DecodeRuneInString(v.text[b:])
		for k := 0; k < size; k++ {
			v.runeAt[b+k] = i
		}
		b += size
		i++
	}
	v.runeAt[len(v.text)] = i
	v.folded = fold(v.text)
	return v
}

// fold lowers ASCII letters and maps the two non-ASCII letters that
// case-insensitive matching folds onto ASCII (ſ to s, the Kelvin sign to k),
// so a prefilter can never skip text a pattern would match.
func fold(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		switch {
		case r >= 'A' && r <= 'Z':
			r += 'a' - 'A'
		case r == 0x017F:
			r = 's'
		case r == 0x212A:
			r = 'k'
		}
		b.WriteRune(r)
	}
	return b.String()
}

// mayMatch: the rule's prefilter lets its patterns be tried on this view.
func (r *Rule) mayMatch(v *view) bool {
	if len(r.Any) == 0 {
		return true
	}
	for _, lit := range r.Any {
		if strings.Contains(v.folded, lit) {
			return true
		}
	}
	return false
}

// span maps a byte range of the view to a code-point span of the original.
func (v *view) span(start, end int) Span {
	rs, re := v.runeAt[start], v.runeAt[end]
	if len(v.origin) == 0 {
		return Span{rs, re}
	}
	os := v.origin[rs]
	oe := os + 1
	if re > rs {
		oe = v.origin[re-1] + 1
	}
	return Span{os, oe}
}

// ---------------------------------------------------------------------------
// Scanning.

type hit struct {
	rule  *Rule
	spans []Span
	// text is the matched text, for the fingerprint.
	text string
	// snippet, when set, replaces the masked text (structural rules).
	snippet string
}

type collector struct {
	rs     *RuleSet
	source Source
	hits   map[string]*hit
}

func (c *collector) add(rule *Rule, span Span, text, snippet string) {
	h, ok := c.hits[rule.ID]
	if !ok {
		h = &hit{rule: rule, text: text, snippet: snippet}
		c.hits[rule.ID] = h
	}
	if len(h.spans) < c.rs.MaxSpans {
		h.spans = append(h.spans, span)
	}
}

// regexHits runs the pattern rules over one view. only limits it to rules
// marked decoded (for text recovered from an encoding).
func (c *collector) regexMatches(v *view, decodedOnly bool) map[string][]Span {
	found := map[string][]Span{}
	for _, rule := range c.rs.Rules {
		if rule.Kind != "" || !rule.appliesTo(c.source) || (decodedOnly && !rule.Decoded) || !rule.mayMatch(v) {
			continue
		}
		for _, re := range rule.patterns {
			for _, loc := range re.FindAllStringIndex(v.text, 20) {
				if loc[1] == loc[0] {
					continue
				}
				matched := v.text[loc[0]:loc[1]]
				ok := true
				for _, w := range rule.within {
					if !w.MatchString(matched) {
						ok = false
						break
					}
				}
				if ok {
					found[rule.ID] = append(found[rule.ID], v.span(loc[0], loc[1]))
				}
			}
		}
	}
	return found
}

func (rs *RuleSet) rule(id string) *Rule {
	for _, r := range rs.Rules {
		if r.ID == id {
			return r
		}
	}
	return nil
}

func (rs *RuleSet) ruleOfKind(kind string) []*Rule {
	var out []*Rule
	for _, r := range rs.Rules {
		if r.Kind == kind {
			out = append(out, r)
		}
	}
	return out
}

// Scan checks text against the rule set.
func (rs *RuleSet) Scan(text string, opts Options) Result {
	source := opts.Source
	if source == "" {
		source = SourcePrompt
	}
	original := []rune(text)
	if rs.MaxScanChars > 0 && len(original) > rs.MaxScanChars {
		original = original[:rs.MaxScanChars]
	}
	c := &collector{rs: rs, source: source, hits: map[string]*hit{}}
	textOf := func(s Span) string { return string(original[s[0]:s[1]]) }

	// 1. The text as written, whitespace made uniform (one code point each).
	norm := make([]rune, len(original))
	for i, r := range original {
		norm[i] = normaliseRune(r)
	}
	base := newView(norm, nil)
	direct := c.regexMatches(base, false)
	for _, id := range sortedKeys(direct) {
		rule := rs.rule(id)
		for _, s := range direct[id] {
			c.add(rule, s, textOf(s), "")
		}
	}

	// 2. The cleaned view: invisible characters removed, fullwidth letters
	// narrowed. What only matches here was hidden on purpose.
	var cleaned []rune
	var origin []int
	changed := false
	for i, r := range original {
		if isInvisible(r) {
			changed = true
			continue
		}
		if r >= 0xFF01 && r <= 0xFF5E {
			r -= 0xFEE0
			changed = true
		}
		cleaned = append(cleaned, normaliseRune(r))
		origin = append(origin, i)
	}
	if changed {
		hidden := c.regexMatches(newView(cleaned, origin), false)
		for _, id := range sortedKeys(hidden) {
			if _, seen := direct[id]; seen {
				continue
			}
			spans := hidden[id]
			rule := rs.rule(id)
			for _, s := range spans {
				c.add(rule, s, textOf(s), "")
			}
			for _, split := range rs.ruleOfKind("invisible_split") {
				if split.appliesTo(source) {
					c.add(split, spans[0], textOf(spans[0]), "")
				}
			}
		}
	}

	// 3. Invisible characters.
	c.invisible(original)

	// 4. Encoded blobs that decode to an injection.
	c.encoded(base, original)

	// 5. Respelled text: look-alike letters, leetspeak and ROT13.
	c.respelled(norm, direct, textOf)

	return c.result(original, opts.FingerprintKey)
}

// respelled checks views of the text in which each code point is replaced by
// at most one other, so spans stay where they are: look-alike letters from
// other scripts (Cyrillic, Greek, mathematical and circled letters) read as
// ASCII, leetspeak digits read as letters, and ROT13 undone. A rule that only
// matches in such a view was disguised on purpose; the rule of that kind is
// reported with it. Rules already found as written are not reported twice.
func (c *collector) respelled(norm []rune, direct map[string][]Span, textOf func(Span) string) {
	for _, rule := range c.rs.Rules {
		if !rule.appliesTo(c.source) {
			continue
		}
		var mapped []rune
		snippet := ""
		switch rule.Kind {
		case "homoglyph":
			mapped = respellHomoglyphs(norm)
		case "leetspeak":
			mapped = respellLeet(norm)
		case "rot13":
			if !rule.mayMatch(newView(norm, nil)) {
				continue
			}
			mapped = rot13(norm)
			snippet = "⟨ROT13 text⟩"
		default:
			continue
		}
		if mapped == nil {
			continue
		}
		// Only the instruction rules (those also read in decoded text).
		found := c.regexMatches(newView(mapped, nil), true)
		first := Span{-1, -1}
		for _, id := range sortedKeys(found) {
			if _, seen := direct[id]; seen {
				continue
			}
			if _, seen := c.hits[id]; seen && snippet == "" {
				continue
			}
			for _, s := range found[id] {
				c.add(c.rs.rule(id), s, textOf(s), snippet)
				if first[0] < 0 || s[0] < first[0] {
					first = s
				}
			}
		}
		if first[0] >= 0 {
			c.add(rule, first, textOf(first), snippet)
		}
	}
}

// homoglyphs: letters of other scripts that read as an ASCII letter. Only
// mapped inside a word that also has an ASCII letter, so ordinary Russian or
// Greek text is left alone.
var homoglyphs = map[rune]rune{
	0x0430: 'a', 0x0435: 'e', 0x043E: 'o', 0x0440: 'p', 0x0441: 'c', 0x0443: 'y', 0x0445: 'x',
	0x0456: 'i', 0x0458: 'j', 0x0455: 's', 0x0501: 'd', 0x0261: 'g', 0x04BB: 'h', 0x051B: 'q', 0x051D: 'w',
	0x0410: 'A', 0x0412: 'B', 0x0415: 'E', 0x041A: 'K', 0x041C: 'M', 0x041D: 'H', 0x041E: 'O', 0x0420: 'P',
	0x0421: 'C', 0x0422: 'T', 0x0425: 'X', 0x0406: 'I', 0x0408: 'J', 0x0405: 'S',
	0x03BF: 'o', 0x03B1: 'a', 0x03BD: 'v', 0x03B9: 'i', 0x03BA: 'k', 0x03C1: 'p', 0x03C5: 'u',
	0x039F: 'O', 0x0391: 'A', 0x0392: 'B', 0x0395: 'E', 0x0397: 'H', 0x0399: 'I', 0x039A: 'K', 0x039C: 'M',
	0x039D: 'N', 0x03A1: 'P', 0x03A4: 'T', 0x03A7: 'X', 0x03A5: 'Y', 0x0396: 'Z',
}

// styledLetter reads a mathematical alphanumeric or circled letter as ASCII.
func styledLetter(r rune) (rune, bool) {
	switch {
	case r >= 0x1D400 && r <= 0x1D6A3:
		i := (r - 0x1D400) % 52
		if i < 26 {
			return 'A' + i, true
		}
		return 'a' + i - 26, true
	case r >= 0x24B6 && r <= 0x24CF:
		return 'A' + r - 0x24B6, true
	case r >= 0x24D0 && r <= 0x24E9:
		return 'a' + r - 0x24D0, true
	}
	return 0, false
}

func respellHomoglyphs(norm []rune) []rune {
	out := make([]rune, len(norm))
	copy(out, norm)
	changed := false
	for i := 0; i < len(norm); {
		_, look := homoglyphs[norm[i]]
		if !isASCIILetter(norm[i]) && !look {
			if r, ok := styledLetter(norm[i]); ok {
				out[i] = r
				changed = true
			}
			i++
			continue
		}
		j, ascii := i, false
		for j < len(norm) {
			_, look := homoglyphs[norm[j]]
			if !isASCIILetter(norm[j]) && !look {
				break
			}
			ascii = ascii || isASCIILetter(norm[j])
			j++
		}
		if ascii {
			for k := i; k < j; k++ {
				if r, ok := homoglyphs[norm[k]]; ok {
					out[k] = r
					changed = true
				}
			}
		}
		i = j
	}
	if !changed {
		return nil
	}
	return out
}

var leet = map[rune]rune{'0': 'o', '1': 'i', '3': 'e', '4': 'a', '5': 's', '7': 't', '@': 'a', '$': 's'}

// respellLeet reads leetspeak digits as letters inside a word that has both.
func respellLeet(norm []rune) []rune {
	out := make([]rune, len(norm))
	copy(out, norm)
	changed := false
	isWord := func(r rune) bool { _, l := leet[r]; return isASCIILetter(r) || (r >= '0' && r <= '9') || l }
	for i := 0; i < len(norm); {
		if !isWord(norm[i]) {
			i++
			continue
		}
		j, letters, digits := i, 0, 0
		for j < len(norm) && isWord(norm[j]) {
			if isASCIILetter(norm[j]) {
				letters++
			} else if _, l := leet[norm[j]]; l {
				digits++
			}
			j++
		}
		if letters > 0 && digits > 0 {
			for k := i; k < j; k++ {
				if r, ok := leet[norm[k]]; ok {
					out[k] = r
					changed = true
				}
			}
		}
		i = j
	}
	if !changed {
		return nil
	}
	return out
}

func rot13(norm []rune) []rune {
	out := make([]rune, len(norm))
	for i, r := range norm {
		switch {
		case r >= 'a' && r <= 'z':
			r = 'a' + (r-'a'+13)%26
		case r >= 'A' && r <= 'Z':
			r = 'A' + (r-'A'+13)%26
		}
		out[i] = r
	}
	return out
}

func sortedKeys(m map[string][]Span) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// invisible counts tag characters (outside flag emoji), zero-width
// characters and bidi controls, and reads what tag characters spell.
func (c *collector) invisible(original []rune) {
	norm := original
	var tagSpans, zwSpans, bidiSpans []Span
	var smuggled []rune
	var smuggledOrigin []int
	for i := 0; i < len(norm); i++ {
		r := norm[i]
		switch {
		case isTag(r):
			j := i
			for j < len(norm) && isTag(norm[j]) {
				j++
			}
			// A subdivision flag: U+1F3F4, tag letters, U+E007F.
			flag := i > 0 && norm[i-1] == 0x1F3F4 && norm[j-1] == 0xE007F && j-i <= 8
			if !flag {
				tagSpans = append(tagSpans, Span{i, j})
				for k := i; k < j; k++ {
					if norm[k] >= 0xE0020 && norm[k] <= 0xE007E {
						smuggled = append(smuggled, norm[k]-0xE0000)
						smuggledOrigin = append(smuggledOrigin, k)
					}
				}
				smuggled = append(smuggled, ' ')
				smuggledOrigin = append(smuggledOrigin, j-1)
			}
			i = j - 1
		case isZeroWidth(r) && !(r == 0xFEFF && i == 0):
			zwSpans = append(zwSpans, Span{i, i + 1})
		case (r == 0x200C || r == 0x200D) && i > 0 && i+1 < len(norm) && isASCIILetter(norm[i-1]) && isASCIILetter(norm[i+1]):
			zwSpans = append(zwSpans, Span{i, i + 1})
		case isBidi(r):
			bidiSpans = append(bidiSpans, Span{i, i + 1})
		}
	}
	count := func(spans []Span) int {
		n := 0
		for _, s := range spans {
			n += s[1] - s[0]
		}
		return n
	}
	concat := func(spans []Span) string {
		var b strings.Builder
		for _, s := range spans {
			b.WriteString(string(original[s[0]:s[1]]))
		}
		return b.String()
	}
	for _, rule := range c.rs.Rules {
		if !rule.appliesTo(c.source) {
			continue
		}
		var spans []Span
		var what string
		switch rule.Kind {
		case "tag":
			spans, what = tagSpans, "hidden tag characters"
		case "zero_width":
			spans, what = zwSpans, "zero-width characters"
		case "bidi":
			spans, what = bidiSpans, "bidirectional control characters"
		default:
			continue
		}
		n := count(spans)
		if n == 0 || n < max(rule.Min, 1) {
			continue
		}
		snippet := fmt.Sprintf("⟨%d %s⟩", n, what)
		for _, s := range spans {
			c.add(rule, s, concat(spans), snippet)
		}
	}
	// What the tag characters spell is checked like anything else.
	if len(smuggled) > 0 {
		spelled := c.regexMatches(newView(smuggled, smuggledOrigin), true)
		for _, id := range sortedKeys(spelled) {
			rule := c.rs.rule(id)
			for _, s := range spelled[id] {
				c.add(rule, s, string(original[s[0]:s[1]]), "⟨instruction in hidden tag characters⟩")
			}
		}
	}
}

var (
	base64Blob = regexp.MustCompile(`[A-Za-z0-9+/_-]{16,}={0,2}`)
	hexBlob    = regexp.MustCompile(`(?:[0-9A-Fa-f]{2}){8,}`)
)

const maxBlobs = 20

// encoded decodes base64 and hex blobs and checks what they say.
func (c *collector) encoded(base *view, original []rune) {
	for _, rule := range c.rs.Rules {
		if (rule.Kind != "base64" && rule.Kind != "hex") || !rule.appliesTo(c.source) {
			continue
		}
		re, decode, label := base64Blob, decodeBase64, "base64"
		if rule.Kind == "hex" {
			re, decode, label = hexBlob, decodeHex, "hex"
		}
		seen := 0
		for _, loc := range re.FindAllStringIndex(base.text, -1) {
			blob := base.text[loc[0]:loc[1]]
			if utf8.RuneCountInString(blob) < rule.Min {
				continue
			}
			if seen >= maxBlobs {
				break
			}
			seen++
			plain, ok := decode(blob)
			if !ok {
				continue
			}
			decodedRunes := []rune(plain)
			for i, r := range decodedRunes {
				decodedRunes[i] = normaliseRune(r)
			}
			inner := c.regexMatches(newView(decodedRunes, nil), true)
			if len(inner) == 0 {
				continue
			}
			span := base.span(loc[0], loc[1])
			snippet := fmt.Sprintf("⟨%s blob, %d characters⟩", label, span[1]-span[0])
			for _, id := range sortedKeys(inner) {
				c.add(c.rs.rule(id), span, plain, snippet)
			}
			c.add(rule, span, plain, snippet)
		}
	}
}

func printable(b []byte) bool {
	if len(b) < 12 {
		return false
	}
	ok := 0
	for _, ch := range b {
		if (ch >= 0x20 && ch <= 0x7E) || ch == '\n' || ch == '\r' || ch == '\t' {
			ok++
		}
	}
	return ok*10 >= len(b)*9
}

// decodeBase64 reads standard or URL-safe base64, padded or not, and only
// accepts text that is almost all printable ASCII.
func decodeBase64(s string) (string, bool) {
	s = strings.TrimRight(s, "=")
	if len(s)%4 == 1 {
		return "", false
	}
	var out []byte
	var acc, bits uint
	for i := 0; i < len(s); i++ {
		ch := s[i]
		var v uint
		switch {
		case ch >= 'A' && ch <= 'Z':
			v = uint(ch - 'A')
		case ch >= 'a' && ch <= 'z':
			v = uint(ch-'a') + 26
		case ch >= '0' && ch <= '9':
			v = uint(ch-'0') + 52
		case ch == '+' || ch == '-':
			v = 62
		case ch == '/' || ch == '_':
			v = 63
		default:
			return "", false
		}
		acc = acc<<6 | v
		bits += 6
		if bits >= 8 {
			bits -= 8
			out = append(out, byte(acc>>bits))
			acc &= (1 << bits) - 1
		}
	}
	if !printable(out) || !utf8.Valid(out) {
		return "", false
	}
	return string(out), true
}

func decodeHex(s string) (string, bool) {
	out, err := hex.DecodeString(s)
	if err != nil || !printable(out) || !utf8.Valid(out) {
		return "", false
	}
	return string(out), true
}

func (c *collector) result(original []rune, key string) Result {
	ids := make([]string, 0, len(c.hits))
	for id := range c.hits {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	res := Result{Version: c.rs.Version, Threshold: c.rs.Threshold, Matches: []Match{}, Categories: []string{}}
	keep := 1.0
	cats := map[string]bool{}
	for _, id := range ids {
		h := c.hits[id]
		w := h.rule.weightFor(c.source)
		if w <= 0 {
			continue
		}
		sort.Slice(h.spans, func(i, j int) bool {
			if h.spans[i][0] != h.spans[j][0] {
				return h.spans[i][0] < h.spans[j][0]
			}
			return h.spans[i][1] < h.spans[j][1]
		})
		keep *= 1 - w
		cats[h.rule.Category] = true
		snippet := h.snippet
		if snippet == "" {
			snippet = MaskSnippet(original, h.spans[0][0], h.spans[0][1], c.rs.SnippetChars)
		}
		res.Matches = append(res.Matches, Match{
			Rule:        id,
			Category:    h.rule.Category,
			Weight:      w,
			Spans:       h.spans,
			Snippet:     snippet,
			Fingerprint: Fingerprint(key, id, h.text),
		})
	}
	for cat := range cats {
		res.Categories = append(res.Categories, cat)
	}
	sort.Strings(res.Categories)
	res.Score = math.Round((1-keep)*1000) / 1000
	res.Detected = len(res.Matches) > 0 && res.Score >= c.rs.Threshold
	return res
}

// ---------------------------------------------------------------------------
// What a reviewer sees.

var (
	tokenRun = regexp.MustCompile(`[A-Za-z0-9+/=_-]{16,}`)
	digitRun = regexp.MustCompile(`[0-9]{6,}`)
	spaceRun = regexp.MustCompile(` {2,}`)
)

// MaskSnippet shows the start of a match: at most n code points, invisible
// characters named rather than hidden, whitespace collapsed, and anything
// shaped like a key, token or long number replaced whole, so a snippet never
// carries any character of a secret.
func MaskSnippet(original []rune, start, end, n int) string {
	if start < 0 {
		start = 0
	}
	if end > len(original) {
		end = len(original)
	}
	cut := end
	if n > 0 && cut-start > n {
		cut = start + n
	}
	var b strings.Builder
	for _, r := range original[start:cut] {
		switch {
		case isInvisible(r):
			fmt.Fprintf(&b, "⟨U+%04X⟩", r)
		case r < 0x20 || (r >= 0x7F && r <= 0x9F) || isJSWhitespace(r):
			b.WriteRune(' ')
		default:
			b.WriteRune(r)
		}
	}
	s := spaceRun.ReplaceAllString(b.String(), " ")
	s = tokenRun.ReplaceAllString(s, "[redacted]")
	s = digitRun.ReplaceAllString(s, "•••")
	s = strings.TrimSpace(s)
	if cut < end {
		s += "…"
	}
	if r := []rune(s); len(r) > 160 {
		s = string(r[:160]) + "…"
	}
	return s
}

// Fingerprint is a keyed hash of what a rule matched, whitespace and ASCII
// case folded, so the same payload is recognisable across events. Without a
// key there is no fingerprint.
func Fingerprint(key, rule, text string) string {
	if key == "" {
		return ""
	}
	runes := []rune(text)
	if len(runes) > 500 {
		runes = runes[:500]
	}
	var b strings.Builder
	space := false
	for _, r := range runes {
		if isJSWhitespace(r) {
			space = true
			continue
		}
		if space && b.Len() > 0 {
			b.WriteByte(' ')
		}
		space = false
		if r >= 'A' && r <= 'Z' {
			r += 'a' - 'A'
		}
		b.WriteRune(r)
	}
	mac := hmac.New(sha256.New, []byte(key))
	mac.Write([]byte(rule + "\x00" + b.String()))
	return hex.EncodeToString(mac.Sum(nil))[:16]
}
