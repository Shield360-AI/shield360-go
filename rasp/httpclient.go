package rasp

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/url"
)

// Outbound HTTP sink (README "SSRF"). NewTransport wraps a RoundTripper so
// every request (each redirect hop included) is checked before it is sent:
// outbound.not_allowed against allow.outboundHosts (inside or outside a
// request; the Shield360 and OTLP hosts are always allowed), then the ssrf
// rules against the inputs in the request's context. An internationalized
// host is matched in its percent-encoded, Unicode and IDNA ASCII forms.
//
// DNS rebinding: a request whose host name comes from an input and that
// goes direct is sent through a clone of the base *http.Transport whose
// DialContext resolves the name, checks every address, and connects to
// exactly those addresses (TLS still uses the URL's server name). A custom
// TLS dialer (DialTLSContext, DialTLS) keeps doing its own connecting: its
// name is resolved and checked first, and the address it actually connected
// to is checked before any byte of the request is sent. The clone does not
// keep connections alive, so a tainted request never reuses a connection
// dialed for another. A tainted request through a proxy (Proxy, HTTP_PROXY)
// has the target resolved locally and checked before it is sent: best
// effort, since the proxy resolves the name itself.
// Requests whose host is an IP literal, or not tainted, use the base as is.

const httpSink = "http.Transport"

type ipResolver interface {
	LookupIPAddr(ctx context.Context, host string) ([]net.IPAddr, error)
}

type raspTransport struct {
	base http.RoundTripper
	// fresh is a no-keep-alive, no-proxy clone of base (when base is an
	// *http.Transport) that checks the address it dials.
	fresh *http.Transport
	// proxy is base's proxy function, when known.
	proxy    func(*http.Request) (*url.URL, error)
	resolver ipResolver
}

// NewTransport returns base (http.DefaultTransport when nil) with RASP
// checks. Keep it the innermost RoundTripper, directly around the
// *http.Transport, so the dial check applies; around any other RoundTripper
// the checks before sending run, and a tainted host name is resolved and
// checked before sending, but the address actually dialed is not seen.
// Wrapping a wrapped transport returns it unchanged.
func NewTransport(base http.RoundTripper) http.RoundTripper {
	if base == nil {
		base = http.DefaultTransport
	}
	if t, ok := base.(*raspTransport); ok {
		return t
	}
	t := &raspTransport{base: base, resolver: net.DefaultResolver}
	if ht, ok := base.(*http.Transport); ok {
		t.proxy = ht.Proxy
		fresh := ht.Clone()
		fresh.DisableKeepAlives = true
		t.guardDials(fresh)
		t.fresh = fresh
	}
	return t
}

// WrapClient returns a copy of c (a new client when nil) whose transport
// has RASP checks.
func WrapClient(c *http.Client) *http.Client {
	var cp http.Client
	if c != nil {
		cp = *c
	}
	cp.Transport = NewTransport(cp.Transport)
	return &cp
}

// CloseIdleConnections closes the idle connections of the base transport.
func (t *raspTransport) CloseIdleConnections() {
	if c, ok := t.base.(interface{ CloseIdleConnections() }); ok {
		c.CloseIdleConnections()
	}
	if t.fresh != nil {
		t.fresh.CloseIdleConnections()
	}
}

func closeRequestBody(req *http.Request) {
	if req.Body != nil {
		_ = req.Body.Close()
	}
}

// RoundTrip checks the request and sends it.
func (t *raspTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if !Active() || req == nil || req.URL == nil {
		return t.base.RoundTrip(req)
	}
	ctx := req.Context()
	inputs := inputsOf(ctx)
	var (
		pre    *Finding
		target *dialTarget
	)
	_, err := checkSinkDecision(ctx, httpSink, func(slot *iastSlot) *Finding {
		forms := urlForms(req.URL)
		var outbound, ssrf *Finding
		// Allowed when any form of the host is on the list.
		for _, u := range forms {
			if outbound = DetectOutbound(u, AllowLists().OutboundHosts, AlwaysAllowedHosts()); outbound == nil {
				break
			}
		}
		if len(inputs) == 0 {
			pre = outbound
			return pre
		}
		for _, u := range forms {
			if ssrf = detectSSRFWith(u, inputs, nil, slot); ssrf != nil {
				break
			}
		}
		// The strongest decision wins: an outbound finding in monitor never
		// hides an SSRF finding that blocks.
		pre = Strongest(outbound, ssrf)
		if pre != nil && pre.Attack == SSRF {
			return pre
		}
		// No SSRF finding yet (an outbound finding in monitor lets the call
		// on): a tainted name still gets the address check below.
		for _, u := range forms {
			if _, h, ok := RawURL(u); ok && h != "" && !IsIPLiteral(h) && taintOf(u, h, inputs) != nil {
				target = &dialTarget{url: u, host: toASCIIHost(req.URL.Hostname()), inputs: inputs}
				break
			}
		}
		return pre
	})
	if err != nil {
		closeRequestBody(req)
		return nil, err
	}
	// Reported already (one event per request), or nothing to rebind.
	if target == nil || (pre != nil && pre.Attack == SSRF) {
		return t.base.RoundTrip(req)
	}
	if t.fresh == nil || t.proxied(req) {
		// The connection is not ours to see: check the target's addresses
		// from a lookup of our own before sending.
		if err := t.checkLookup(ctx, target); err != nil {
			closeRequestBody(req)
			return nil, err
		}
		return t.base.RoundTrip(req)
	}
	resp, err := t.fresh.RoundTrip(req.WithContext(context.WithValue(ctx, dialKey{}, target)))
	if b := AsBlocked(err); b != nil {
		return nil, b
	}
	return resp, err
}

// proxied reports whether base sends req through a proxy.
func (t *raspTransport) proxied(req *http.Request) (on bool) {
	if t.proxy == nil {
		return false
	}
	defer func() {
		if recover() != nil {
			on = false
		}
	}()
	u, err := t.proxy(req)
	return err == nil && u != nil
}

// lookup resolves host; ok is false when it cannot (fail open).
func (t *raspTransport) lookup(ctx context.Context, host, network string) ([]net.IPAddr, []string, bool) {
	ips, err := t.resolver.LookupIPAddr(ctx, host)
	ips = filterNetwork(ips, network)
	if err != nil || len(ips) == 0 {
		return nil, nil, false
	}
	addrs := make([]string, len(ips))
	for i, ip := range ips {
		addrs[i] = ip.IP.String()
	}
	return ips, addrs, true
}

func (t *raspTransport) checkLookup(ctx context.Context, target *dialTarget) error {
	_, addrs, ok := t.lookup(ctx, target.host, "tcp")
	if !ok {
		return nil
	}
	return checkSink(ctx, httpSink, func(*iastSlot) *Finding { return DetectSSRF(target.url, target.inputs, addrs) })
}

type dialKey struct{}

// dialTarget is what the dial check needs about the request that dials.
type dialTarget struct {
	url    string // the form of the URL the input taints
	host   string // the host, IDNA ASCII
	inputs []Input
}

type dialFunc func(ctx context.Context, network, addr string) (net.Conn, error)

// guardDials makes every dial path of the clone check its addresses. The
// clone carries only requests that go direct, so it has no proxy.
func (t *raspTransport) guardDials(ht *http.Transport) {
	ht.Proxy = nil
	dial := ht.DialContext
	if dial == nil {
		//lint:ignore SA1019 the transport's own fallback order
		if legacy := ht.Dial; legacy != nil {
			dial = func(_ context.Context, network, addr string) (net.Conn, error) { return legacy(network, addr) }
		} else {
			var d net.Dialer
			dial = d.DialContext
		}
	}
	ht.DialContext = t.pinnedDial(dial)
	tlsDial := ht.DialTLSContext
	//lint:ignore SA1019 the transport's own fallback order
	if legacy := ht.DialTLS; tlsDial == nil && legacy != nil {
		tlsDial = func(_ context.Context, network, addr string) (net.Conn, error) { return legacy(network, addr) }
	}
	//lint:ignore SA1019 replaced by the checked DialTLSContext
	ht.DialTLS = nil
	if tlsDial != nil {
		ht.DialTLSContext = t.verifiedDial(tlsDial)
	}
}

// pinnedDial resolves a tainted request's host, checks every address, and
// connects to exactly those addresses.
func (t *raspTransport) pinnedDial(dial dialFunc) dialFunc {
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		target, _ := ctx.Value(dialKey{}).(*dialTarget)
		if target == nil || !Active() {
			return dial(ctx, network, addr)
		}
		host, port, err := net.SplitHostPort(addr)
		if err != nil {
			return dial(ctx, network, addr)
		}
		ips, addrs, ok := t.lookup(ctx, host, network)
		if !ok {
			// A dialer that resolves elsewhere (SOCKS): fail open.
			return dial(ctx, network, addr)
		}
		if err := checkSink(ctx, httpSink, func(*iastSlot) *Finding { return DetectSSRF(target.url, target.inputs, addrs) }); err != nil {
			return nil, err
		}
		var errs []error
		for _, ip := range ips {
			c, err := dial(ctx, network, net.JoinHostPort(ip.String(), port))
			if err == nil {
				return c, nil
			}
			errs = append(errs, err)
			if ctx.Err() != nil {
				break
			}
		}
		if len(errs) == 1 {
			return nil, errs[0]
		}
		return nil, errors.Join(errs...)
	}
}

// verifiedDial wraps a custom TLS dialer, which takes the server name from
// addr and connects itself: the name's addresses are checked first, then
// the address it actually connected to, before the request is written.
func (t *raspTransport) verifiedDial(dial dialFunc) dialFunc {
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		target, _ := ctx.Value(dialKey{}).(*dialTarget)
		if target == nil || !Active() {
			return dial(ctx, network, addr)
		}
		host, _, err := net.SplitHostPort(addr)
		if err != nil {
			return dial(ctx, network, addr)
		}
		checked := map[string]bool{}
		reported := false
		if _, addrs, ok := t.lookup(ctx, host, network); ok {
			d, err := checkSinkDecision(ctx, httpSink, func(*iastSlot) *Finding { return DetectSSRF(target.url, target.inputs, addrs) })
			if err != nil {
				return nil, err
			}
			reported = d != DecisionNone
			for _, a := range addrs {
				checked[a] = true
			}
		}
		c, err := dial(ctx, network, addr)
		if err != nil || c == nil {
			return c, err
		}
		if ip := remoteIP(c); ip != "" && !checked[ip] && !reported {
			if err := checkSink(ctx, httpSink, func(*iastSlot) *Finding { return DetectSSRF(target.url, target.inputs, []string{ip}) }); err != nil {
				_ = c.Close()
				return nil, err
			}
		}
		return c, nil
	}
}

// remoteIP is the peer address of a connection, or "" when it is not an IP.
func remoteIP(c net.Conn) (ip string) {
	defer func() {
		if recover() != nil {
			ip = ""
		}
	}()
	a := c.RemoteAddr()
	if a == nil {
		return ""
	}
	if tcp, ok := a.(*net.TCPAddr); ok {
		return tcp.IP.String()
	}
	if h, _, err := net.SplitHostPort(a.String()); err == nil && net.ParseIP(h) != nil {
		return net.ParseIP(h).String()
	}
	return ""
}

func filterNetwork(ips []net.IPAddr, network string) []net.IPAddr {
	if network != "tcp4" && network != "tcp6" {
		return ips
	}
	out := ips[:0:0]
	for _, ip := range ips {
		if (ip.IP.To4() != nil) == (network == "tcp4") {
			out = append(out, ip)
		}
	}
	return out
}
