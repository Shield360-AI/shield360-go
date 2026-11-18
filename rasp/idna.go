package rasp

import (
	"net/url"
	"strings"
	"unicode/utf8"
)

// Internationalized host names. url.URL.String percent-encodes a non-ASCII
// host and net/http dials its IDNA ASCII (punycode) form, while an input
// holds whichever form the user sent. The HTTP sink matches all three.
// toASCIIHost lower-cases and punycode-encodes each label (RFC 3492); it
// does not apply the rest of UTS 46 mapping, so exotic names (full-width
// letters, compatibility forms) may differ from net/http's form.

// urlForms returns u as text with its host percent-encoded (u.String()),
// in Unicode, and in IDNA ASCII, without duplicates.
func urlForms(u *url.URL) []string {
	escaped := u.String()
	host := u.Hostname()
	if isASCII(host) {
		return []string{escaped}
	}
	escHost := strings.TrimPrefix((&url.URL{Host: host}).String(), "//")
	forms := []string{escaped}
	for _, h := range []string{host, toASCIIHost(host)} {
		f := strings.Replace(escaped, escHost, h, 1)
		if f != escaped && f != forms[len(forms)-1] {
			forms = append(forms, f)
		}
	}
	return forms
}

func isASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] >= utf8.RuneSelf {
			return false
		}
	}
	return true
}

// toASCIIHost is the host's IDNA ASCII form (see above). IDNA dots
// (U+3002, U+FF0E, U+FF61) separate labels.
func toASCIIHost(host string) string {
	if isASCII(host) {
		return strings.ToLower(host)
	}
	host = strings.NewReplacer("。", ".", "．", ".", "｡", ".").Replace(strings.ToLower(host))
	labels := strings.Split(host, ".")
	for i, l := range labels {
		if !isASCII(l) {
			if p, ok := punycode(l); ok {
				labels[i] = "xn--" + p
			}
		}
	}
	return strings.Join(labels, ".")
}

const (
	pcBase        = 36
	pcTMin        = 1
	pcTMax        = 26
	pcSkew        = 38
	pcDamp        = 700
	pcInitialBias = 72
	pcInitialN    = 128
)

func pcAdapt(delta, points int, first bool) int {
	if first {
		delta /= pcDamp
	} else {
		delta /= 2
	}
	delta += delta / points
	k := 0
	for delta > ((pcBase-pcTMin)*pcTMax)/2 {
		delta /= pcBase - pcTMin
		k += pcBase
	}
	return k + (pcBase-pcTMin+1)*delta/(delta+pcSkew)
}

func pcDigit(d int) byte {
	if d < 26 {
		return byte('a' + d)
	}
	return byte('0' + d - 26)
}

// punycode encodes one label (RFC 3492, section 6.3).
func punycode(label string) (string, bool) {
	runes := []rune(label)
	out := make([]byte, 0, len(label)+8)
	for _, r := range runes {
		if r < utf8.RuneSelf {
			out = append(out, byte(r))
		}
	}
	b := len(out)
	h := b
	if b > 0 {
		out = append(out, '-')
	}
	n, delta, bias := pcInitialN, 0, pcInitialBias
	const maxInt = int(^uint32(0) >> 1)
	for h < len(runes) {
		m := maxInt
		for _, r := range runes {
			if int(r) >= n && int(r) < m {
				m = int(r)
			}
		}
		if (m - n) > (maxInt-delta)/(h+1) {
			return "", false
		}
		delta += (m - n) * (h + 1)
		n = m
		for _, r := range runes {
			if int(r) < n {
				delta++
			}
			if int(r) != n {
				continue
			}
			q := delta
			for k := pcBase; ; k += pcBase {
				t := k - bias
				if t < pcTMin {
					t = pcTMin
				} else if t > pcTMax {
					t = pcTMax
				}
				if q < t {
					break
				}
				out = append(out, pcDigit(t+(q-t)%(pcBase-t)))
				q = (q - t) / (pcBase - t)
			}
			out = append(out, pcDigit(q))
			bias = pcAdapt(delta, h+1, h == b)
			delta = 0
			h++
		}
		delta++
		n++
	}
	return string(out), true
}
