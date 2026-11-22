package defend

import (
	"net/http"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/Shield360-AI/shield360-go/clienttype"
	"github.com/Shield360-AI/shield360-go/rasp"
)

// What Defend reads from a request. Header values stay in memory for the one
// decision; nothing here is logged or sent. Port of defend/request.ts.

// Content limits: at most MaxContentItems strings of MaxContentItem
// characters each.
const (
	MaxContentItems = 16
	MaxContentItem  = 8192
	maxHeader       = 4096
)

// Request is the request Defend decides on.
type Request struct {
	Method string
	// Target is the request target (path and query, or an absolute URL).
	Target string
	// Headers are the request headers (any case; several values joined
	// with ", ").
	Headers map[string]string
	// RemoteAddr is the connection's peer address (a port is ignored).
	RemoteAddr string
}

// RequestOf reads an *http.Request.
func RequestOf(r *http.Request) Request {
	h := make(map[string]string, len(r.Header))
	for k, v := range r.Header {
		h[k] = strings.Join(v, ", ")
	}
	if r.Host != "" && h["Host"] == "" {
		h["Host"] = r.Host
	}
	target := r.RequestURI
	if target == "" && r.URL != nil {
		target = r.URL.RequestURI()
	}
	return Request{Method: r.Method, Target: target, Headers: h, RemoteAddr: r.RemoteAddr}
}

// Call is what the caller adds for one decision.
type Call struct {
	// Content is text to check for prompt injection and sensitive data
	// (the user's prompt, a tool argument).
	Content []string
	// IP, Country and ASN override what is read from the request.
	IP      string
	Country string
	ASN     uint32
}

// FactsOptions say how the client address and its location are read.
type FactsOptions struct {
	// TrustProxy is how many proxies in front append to X-Forwarded-For (0:
	// the header is not read).
	TrustProxy int
	// CountryHeader and ASNHeader name headers a trusted proxy sets (for
	// example CF-IPCountry).
	CountryHeader string
	ASNHeader     string
}

// Facts are what Defend read from a request.
type Facts struct {
	Method string
	// Path is percent-decoded; RawPath is as sent (Edge signs it).
	Path, RawPath string
	Query         string
	HasQuery      bool
	IP            string
	Country       string
	ASN           uint32
	// Headers have lower-case names.
	Headers map[string]string
	Content []string
	Edge    *clienttype.EdgeSignal
}

func cut(s string, max int) string {
	if len(s) <= max {
		return s
	}
	n := max
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return s[:n]
}

func stripTarget(target string) string {
	p := target
	if p == "" {
		p = "/"
	}
	if i := strings.Index(p, "://"); i >= 0 {
		scheme := p[:i]
		ok := scheme != "" && (scheme[0] >= 'a' && scheme[0] <= 'z' || scheme[0] >= 'A' && scheme[0] <= 'Z')
		for j := 0; ok && j < len(scheme); j++ {
			c := scheme[j]
			ok = c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '+' || c == '.' || c == '-'
		}
		if ok {
			rest := p[i+3:]
			if j := strings.IndexAny(rest, "/?#"); j >= 0 && rest[j] == '/' {
				p = rest[j:]
			} else {
				p = "/"
			}
		}
	}
	if q := strings.IndexAny(p, "?#"); q >= 0 {
		return p[:q]
	}
	return p
}

func unhex(c byte) (byte, bool) {
	switch {
	case c >= '0' && c <= '9':
		return c - '0', true
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10, true
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10, true
	}
	return 0, false
}

// PathOf is the target's path, percent-decoded (as sent when it does not
// decode to UTF-8).
func PathOf(target string) string {
	p := stripTarget(target)
	if !strings.HasPrefix(p, "/") {
		p = "/" + p
	}
	out := make([]byte, 0, len(p))
	for i := 0; i < len(p); i++ {
		if p[i] == '%' {
			if i+2 < len(p) {
				h, ok1 := unhex(p[i+1])
				l, ok2 := unhex(p[i+2])
				if ok1 && ok2 {
					out = append(out, h<<4|l)
					i += 2
					continue
				}
			}
			return p
		}
		out = append(out, p[i])
	}
	if !utf8.Valid(out) {
		return p
	}
	return string(out)
}

// RawPathOf is the target's path as sent.
func RawPathOf(target string) string { return stripTarget(target) }

// UsableIP reads an address ([v6], ::ffff:v4 and a v4 port-less form); ""
// when it is not one.
func UsableIP(v string) string {
	s := strings.TrimSpace(v)
	if strings.HasPrefix(s, "[") {
		if e := strings.IndexByte(s, ']'); e >= 0 {
			s = s[1:e]
		}
	}
	if strings.HasPrefix(s, "::ffff:") && strings.Contains(s, ".") {
		s = s[7:]
	}
	if rasp.ValidIP(s) {
		return s
	}
	return ""
}

func remoteIP(addr string) string {
	if ip := UsableIP(addr); ip != "" {
		return ip
	}
	// host:port or [v6]:port
	if i := strings.LastIndexByte(addr, ':'); i > 0 {
		return UsableIP(addr[:i])
	}
	return ""
}

// ForwardedIP is the address hops entries from the right of an
// X-Forwarded-For value.
func ForwardedIP(header string, hops int) string {
	if header == "" || hops < 1 {
		return ""
	}
	var parts []string
	for _, p := range strings.Split(header, ",") {
		if p = strings.TrimSpace(p); p != "" {
			parts = append(parts, p)
		}
	}
	i := len(parts) - hops
	if i < 0 {
		return ""
	}
	return UsableIP(parts[i])
}

// FactsOf reads the facts of a request.
func FactsOf(req Request, call Call, o FactsOptions) Facts {
	headers := make(map[string]string, len(req.Headers))
	for k, v := range req.Headers {
		headers[strings.ToLower(k)] = cut(v, maxHeader)
	}
	method := "GET"
	if req.Method != "" {
		method = cut(strings.ToUpper(req.Method), 16)
	}
	target := req.Target
	if target == "" {
		target = "/"
	}
	ip := UsableIP(call.IP)
	if ip == "" {
		ip = ForwardedIP(headers["x-forwarded-for"], o.TrustProxy)
	}
	if ip == "" {
		ip = remoteIP(req.RemoteAddr)
	}
	f := Facts{Method: method, Path: PathOf(target), RawPath: RawPathOf(target), IP: ip, Headers: headers}
	if i := strings.IndexByte(target, '?'); i >= 0 {
		f.Query, f.HasQuery = cut(target[i+1:], 2048), true
	}
	header := func(name string) string {
		if name == "" {
			return ""
		}
		return headers[strings.ToLower(name)]
	}
	country := call.Country
	if country == "" {
		country = header(o.CountryHeader)
	}
	if t := strings.TrimSpace(country); len(t) == 2 && allBytes(t, func(c byte) bool { return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' }) {
		f.Country = strings.ToUpper(t)
	}
	f.ASN = call.ASN
	if f.ASN == 0 {
		t := strings.TrimSpace(header(o.ASNHeader))
		digits := t
		if len(t) > 2 && strings.EqualFold(t[:2], "as") {
			digits = t[2:]
		}
		if len(digits) >= 1 && len(digits) <= 10 && allBytes(digits, func(c byte) bool { return c >= '0' && c <= '9' }) {
			if n, err := strconv.ParseUint(digits, 10, 64); err == nil && n <= 4_294_967_295 {
				f.ASN = uint32(n)
			}
		}
	}
	for _, c := range call.Content {
		if c == "" {
			continue
		}
		if len(f.Content) >= MaxContentItems {
			break
		}
		if r := []rune(c); len(r) > MaxContentItem {
			c = string(r[:MaxContentItem])
		}
		f.Content = append(f.Content, c)
	}
	return f
}

// CarriesAgentProof says whether the request carries a Shield360 agent
// passport or a Web Bot Auth signature.
func CarriesAgentProof(headers map[string]string) bool {
	return headers["shield360-agent"] != "" || (headers["signature"] != "" && headers["signature-input"] != "")
}
