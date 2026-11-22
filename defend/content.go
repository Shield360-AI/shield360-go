package defend

import (
	"regexp"
	"strings"

	"github.com/ThinkfleetAI/shield360-go/defend/internal/injection"
)

// Prompt injection and sensitive data in the text the app passes to Defend
// (Call.Content), as the TypeScript, Python, PHP and Rust SDKs check it.
//
// Prompt injection is the shared detector itself: internal/injection is a
// byte-identical copy of cli/internal/coding/injection/detector.go with its
// rules (rules.json); tests say so and hold it to the golden corpus. Only
// the score is used: Defend reports reason codes, never text.
//
// Sensitive data: the high-precision PII and secret shapes of the AI
// security pack's output check. Deterministic and local; never panics.

// MaxContentChars is how much content (characters, all items) is checked.
const MaxContentChars = 20_000

// InjectionScore is the shared detector's score for text from source
// (prompt, tool_result, ...), and the rules that matched.
func InjectionScore(text, source string) (float64, []string) {
	r := injection.Scan(text, injection.Options{Source: injection.Source(source)})
	return r.Score, r.RuleIDs()
}

// InjectionThreshold is the score at which text is prompt injection.
func InjectionThreshold() float64 { return injection.Rules().Threshold }

type shape struct {
	re    *regexp.Regexp
	check func(string) bool
}

var shapes = func() []shape {
	defs := []struct {
		p     string
		check func(string) bool
	}{
		{`(\bsk-(?:proj-)?[A-Za-z0-9_-]{20,})`, nil},
		{`(\bsk-ant-[A-Za-z0-9_-]{20,})`, nil},
		{`(?:^|[^A-Za-z0-9/+=])((?:AKIA|ASIA)[0-9A-Z]{16})(?:[^A-Za-z0-9/+=]|$)`, nil},
		{`(\bAIza[0-9A-Za-z_-]{35})`, nil},
		{`(\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,})`, nil},
		{`(\bgithub_pat_[A-Za-z0-9_]{22,})`, nil},
		{`(\b(?:sk|rk)_live_[A-Za-z0-9]{24,})`, nil},
		{`(\bxox[bpoas]-[A-Za-z0-9-]{10,})`, nil},
		{`(-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----)`, nil},
		{`(\b(?:mongodb(?:\+srv)?|postgres(?:ql)?|mysql|redis|amqps?)://[^\s:@/]+:[^\s@/]+@[^\s]+)`, nil},
		{`(\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,})`, nil},
		{`(\b[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}\b)`, nil},
		{`(?:^|[^0-9-])([0-9]{3}-[0-9]{2}-[0-9]{4})(?:[^0-9-]|$)`, issuableSSN},
		{`(?:^|[^0-9])((?:4[0-9]{3}|5[1-5][0-9]{2}|3[47][0-9]{2}|6(?:011|5[0-9]{2}))(?:[ -]?[0-9]{4}){2}[ -]?[0-9]{3,4})(?:[^0-9]|$)`, luhn},
		{`(?:^|[^0-9])((?:\+1[ .-]?)?\(?[2-9][0-9]{2}\)?[ .-][0-9]{3}[ .-][0-9]{4})(?:[^0-9]|$)`, nil},
	}
	out := make([]shape, 0, len(defs))
	for _, d := range defs {
		out = append(out, shape{regexp.MustCompile(d.p), d.check})
	}
	return out
}()

func luhn(v string) bool {
	var d []int
	for _, c := range v {
		if c >= '0' && c <= '9' {
			d = append(d, int(c-'0'))
		}
	}
	if len(d) < 13 || len(d) > 19 {
		return false
	}
	sum := 0
	for i := 0; i < len(d); i++ {
		n := d[len(d)-1-i]
		if i%2 == 1 {
			n *= 2
			if n > 9 {
				n -= 9
			}
		}
		sum += n
	}
	return sum%10 == 0
}

func issuableSSN(v string) bool {
	p := strings.SplitN(v, "-", 3)
	for len(p) < 3 {
		p = append(p, "")
	}
	return p[0] != "000" && p[0] != "666" && !strings.HasPrefix(p[0], "9") && p[1] != "00" && p[2] != "0000"
}

// Sensitive says whether text holds a secret or PII shape.
func Sensitive(text string) bool {
	t := cut(text, 200_000)
	for _, s := range shapes {
		at := 0
		for at <= len(t) {
			loc := s.re.FindStringSubmatchIndex(t[at:])
			if loc == nil || loc[2] < 0 {
				break
			}
			start, end := at+loc[2], at+loc[3]
			// A search from the middle may not treat that point as the
			// start of the text (as a search with context would not).
			if at > 0 && loc[2] == 0 && loc[0] == 0 {
				at++
				continue
			}
			if s.check == nil || s.check(t[start:end]) {
				return true
			}
			if end > at {
				at = end
			} else {
				at++
			}
		}
	}
	return false
}

// CheckContent checks the content for prompt injection and, unless off,
// sensitive data.
func CheckContent(content []string, mode SensitiveData) (out ContentFindings) {
	left := MaxContentChars
	for _, raw := range content {
		if left <= 0 {
			break
		}
		if raw == "" {
			continue
		}
		r := []rune(raw)
		if len(r) > left {
			r = r[:left]
		}
		left -= len(r)
		text := string(r)
		if !out.PromptInjection {
			out.PromptInjection = safely(func() bool {
				score, _ := InjectionScore(text, "prompt")
				return score >= InjectionThreshold()
			})
		}
		if mode != SensitiveOff && !out.SensitiveData {
			out.SensitiveData = safely(func() bool { return Sensitive(text) })
		}
	}
	return out
}

func safely(f func() bool) (ok bool) {
	defer func() {
		if recover() != nil {
			ok = false
		}
	}()
	return f()
}
