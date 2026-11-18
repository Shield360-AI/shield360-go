// Package masking is the masking contract every Shield360 SDK shares
// (sdk/rasp/README.md, "Masking"), checked by sdk/rasp/testdata/masking.json:
// credential pairs, bearer credentials and opaque tokens are masked;
// readable identifiers (class names, package and file paths) survive; an
// attribute named like a credential is masked whole. It is used by RASP
// snippets and application logs.
package masking

import (
	"regexp"
	"strings"
	"unicode/utf8"
)

// Mask replaces what is hidden.
const Mask = "***"

// Lookahead is how many characters past the cut masking reads, so a
// credential crossing the cut is never left half visible.
const Lookahead = 1024

const key = `(?:pass(?:word|wd|phrase)?|pwd|secret|token|api[_-]?key|access[_-]?key|private[_-]?key` +
	`|client[_-]?secret|auth(?:orization)?|bearer|cookie|session(?:[_-]?id)?|credentials?)`

var (
	pair = regexp.MustCompile(`(?i)(` + key + `["']?[ \t]*[=:][ \t]*)` +
		`("(?:[^"\\]|\\.)*"?|'(?:[^'\\]|\\.)*'?` +
		`|(?:(?:bearer|basic|digest|negotiate|token)[ \t]+)?[^ \t\r\n\f\x0B&;,'"]+)`)
	bearer   = regexp.MustCompile(`(?i)(bearer[ \t]+)[A-Za-z0-9._~+/=-]+`)
	run      = regexp.MustCompile(`[A-Za-z0-9_\-+/=.]{20,}`)
	readable = regexp.MustCompile(`^[A-Za-z]+[0-9]{0,4}$`)
)

var sensitiveWords = map[string]bool{
	"password": true, "passwd": true, "passphrase": true, "pwd": true, "secret": true, "token": true,
	"apikey": true, "authorization": true, "cookie": true, "credential": true, "credentials": true,
	"bearer": true, "otp": true, "signature": true, "privatekey": true, "sessionid": true, "jwt": true,
	"accesskey": true, "secretkey": true,
}

var sensitivePairs = map[[2]string]bool{
	{"api", "key"}: true, {"private", "key"}: true, {"access", "key"}: true,
	{"secret", "key"}: true, {"session", "id"}: true,
}

func isVowel(c byte) bool { return strings.IndexByte("aeiouyAEIOUY", c) >= 0 }
func isUpper(c byte) bool { return c >= 'A' && c <= 'Z' }
func isLower(c byte) bool { return c >= 'a' && c <= 'z' }
func isDigit(c byte) bool { return c >= '0' && c <= '9' }

func readablePiece(p string) bool {
	if !readable.MatchString(p) {
		return false
	}
	letters, vowels, upperRun, longest, transitions := 0, 0, 0, 0, 0
	var prev byte
	for i := 0; i < len(p); i++ {
		c := p[i]
		if isDigit(c) {
			continue
		}
		letters++
		if isVowel(c) {
			vowels++
		}
		if isUpper(c) {
			upperRun++
			if upperRun > longest {
				longest = upperRun
			}
			if isLower(prev) {
				transitions++
			}
		} else {
			upperRun = 0
		}
		prev = c
	}
	if vowels*5 < letters {
		return false
	}
	return longest <= 6 && transitions*3 <= letters
}

// IsOpaque reports whether a run of 20+ token characters reads as a secret
// rather than an identifier.
func IsOpaque(r string) bool {
	if strings.Contains(r, "+") || strings.HasSuffix(r, "=") {
		return true
	}
	pieces := strings.FieldsFunc(r, func(c rune) bool {
		return c == '.' || c == '/' || c == '-' || c == '_' || c == '='
	})
	for _, p := range pieces {
		if len(p) >= 8 && !readablePiece(p) {
			return true
		}
	}
	return false
}

// Credentials applies the contract's credential rules to s: credential pairs
// (quotes kept), then bearer credentials. Nothing is cut.
func Credentials(s string) string {
	s = replaceSubmatch(pair, s, func(prefix, value string) string {
		switch {
		case strings.HasPrefix(value, `"`):
			return prefix + `"` + Mask + `"`
		case strings.HasPrefix(value, "'"):
			return prefix + "'" + Mask + "'"
		}
		return prefix + Mask
	})
	return bearer.ReplaceAllString(s, "${1}"+Mask)
}

// Secrets masks credentials and opaque tokens in s; nothing is cut.
func Secrets(s string) string {
	return run.ReplaceAllStringFunc(Credentials(s), func(r string) string {
		if IsOpaque(r) {
			return Mask
		}
		return r
	})
}

// longToken is the strict long-token rule targets keep: hosts and
// directories are short labels, so any long token run in one is masked.
var longToken = regexp.MustCompile(`[A-Za-z0-9_\-+/]{20,}={0,2}`)

// MaxTarget is the longest target sent; a longer one is left out, never cut.
const MaxTarget = 256

// Target masks an allow-list target (sdk/rasp/README.md, "Masking",
// "Allow-list targets"): the credential rules on the whole target, every
// '/'-separated segment holding '@' replaced by "***", then the strict
// long-token rule piece by piece (split at '/' and '.', separators kept).
// Nothing is cut: ok is false when the result is empty, holds a control
// character or is longer than 256 characters.
func Target(raw string) (string, bool) {
	s := Credentials(raw)
	segs := strings.Split(s, "/")
	for i, seg := range segs {
		if strings.Contains(seg, "@") {
			segs[i] = Mask
		}
	}
	s = strings.Join(segs, "/")
	var b strings.Builder
	start := 0
	for i := 0; i <= len(s); i++ {
		if i == len(s) || s[i] == '/' || s[i] == '.' {
			b.WriteString(longToken.ReplaceAllString(s[start:i], Mask))
			if i < len(s) {
				b.WriteByte(s[i])
			}
			start = i + 1
		}
	}
	s = b.String()
	if s == "" || utf8.RuneCountInString(s) > MaxTarget {
		return "", false
	}
	for _, r := range s {
		if r < 0x20 || r == 0x7f {
			return "", false
		}
	}
	return s, true
}

func replaceSubmatch(re *regexp.Regexp, s string, f func(prefix, value string) string) string {
	matches := re.FindAllStringSubmatchIndex(s, -1)
	if matches == nil {
		return s
	}
	var b strings.Builder
	last := 0
	for _, m := range matches {
		b.WriteString(s[last:m[0]])
		b.WriteString(f(s[m[2]:m[3]], s[m[4]:m[5]]))
		last = m[1]
	}
	b.WriteString(s[last:])
	return b.String()
}

// Cut keeps at most n characters (runes) of s.
func Cut(s string, n int) string {
	if n < 0 {
		n = 0
	}
	if utf8.RuneCountInString(s) <= n {
		return s
	}
	i := 0
	for pos := range s {
		if i == n {
			return s[:pos]
		}
		i++
	}
	return s
}

// Text is at most limit characters of s, masked before it is cut.
func Text(s string, limit int) string {
	s = strings.ToValidUTF8(s, "�")
	return Cut(Secrets(Cut(s, limit+Lookahead)), limit)
}

func words(key string) []string {
	var out []string
	chunks := strings.FieldsFunc(key, func(c rune) bool {
		return !(c < 128 && (isUpper(byte(c)) || isLower(byte(c)) || isDigit(byte(c))))
	})
	for _, chunk := range chunks {
		start := 0
		for i := 1; i < len(chunk); i++ {
			a, b := chunk[i-1], chunk[i]
			var next byte
			if i+1 < len(chunk) {
				next = chunk[i+1]
			}
			lowerToUpper := (isLower(a) || isDigit(a)) && isUpper(b)
			acronymEnd := isUpper(a) && isUpper(b) && isLower(next)
			if lowerToUpper || acronymEnd {
				out = append(out, strings.ToLower(chunk[start:i]))
				start = i
			}
		}
		out = append(out, strings.ToLower(chunk[start:]))
	}
	return out
}

// IsSensitiveKey reports whether an attribute name names a credential
// (password, x-api-key, sessionId).
func IsSensitiveKey(key string) bool {
	w := words(key)
	for i, word := range w {
		if sensitiveWords[word] {
			return true
		}
		if i+1 < len(w) && sensitivePairs[[2]string{word, w[i+1]}] {
			return true
		}
	}
	return false
}

// Value masks an attribute value: nil stays nil; any value under a sensitive
// name becomes "***"; strings are masked and cut to limit; slices and maps
// are masked item by item (map entries under their own names).
func Value(key string, v any, limit int) any {
	if v == nil {
		return nil
	}
	if IsSensitiveKey(key) {
		return Mask
	}
	switch x := v.(type) {
	case string:
		return Text(x, limit)
	case []string:
		out := make([]any, len(x))
		for i, s := range x {
			out[i] = Value(key, s, limit)
		}
		return out
	case []any:
		out := make([]any, len(x))
		for i, s := range x {
			out[i] = Value(key, s, limit)
		}
		return out
	case map[string]any:
		out := make(map[string]any, len(x))
		for k, s := range x {
			out[k] = Value(k, s, limit)
		}
		return out
	case map[string]string:
		out := make(map[string]any, len(x))
		for k, s := range x {
			out[k] = Value(k, s, limit)
		}
		return out
	}
	return v
}
