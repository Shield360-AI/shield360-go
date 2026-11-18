package rasp

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
)

// hitServer counts the requests it serves.
func hitServer(t *testing.T) (*httptest.Server, *atomic.Int32) {
	t.Helper()
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		_, _ = io.WriteString(w, "ok")
	}))
	t.Cleanup(srv.Close)
	return srv, &hits
}

// fakeResolver answers from a fixed table and counts lookups.
type fakeResolver struct {
	mu      sync.Mutex
	table   map[string][]string
	lookups int
}

func (f *fakeResolver) LookupIPAddr(_ context.Context, host string) ([]net.IPAddr, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.lookups++
	var out []net.IPAddr
	for _, a := range f.table[host] {
		out = append(out, net.IPAddr{IP: net.ParseIP(a)})
	}
	if len(out) == 0 {
		return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
	}
	return out, nil
}

// raspTransportWith is NewTransport with a fake resolver, over an
// *http.Transport whose dialer resolves names from the same table (so the
// unchecked paths reach the test server too).
func raspTransportWith(r *fakeResolver) http.RoundTripper {
	var d net.Dialer
	base := &http.Transport{DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
		if h, p, err := net.SplitHostPort(addr); err == nil && len(r.table[h]) > 0 {
			addr = net.JoinHostPort(r.table[h][0], p)
		}
		return d.DialContext(ctx, network, addr)
	}}
	t := NewTransport(base).(*raspTransport)
	t.resolver = r
	return t
}

// outerRT is another RoundTripper of the same kind (tracing, retries).
type outerRT struct{ next http.RoundTripper }

func (o outerRT) RoundTrip(r *http.Request) (*http.Response, error) { return o.next.RoundTrip(r) }

func get(ctx context.Context, rt http.RoundTripper, u string, hits *atomic.Int32) (bool, error) {
	before := hits.Load()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return false, err
	}
	resp, err := (&http.Client{Transport: rt}).Do(req)
	if err == nil {
		_, _ = io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
	}
	return hits.Load() > before, err
}

func TestHTTPTransportContract(t *testing.T) {
	srv, hits := hitServer(t)
	host := strings.TrimPrefix(srv.URL, "http://")
	runSinkContract(t, sinkCase{
		name:   "rasp.NewTransport (IP literal)",
		attack: SSRF,
		inputs: AddInput(nil, host, "query.target"),
		call: func(t *testing.T, ctx context.Context) (bool, error) {
			return get(ctx, NewTransport(nil), srv.URL+"/", hits)
		},
		composed: map[string]sinkCall{
			"another RoundTripper on top": func(t *testing.T, ctx context.Context) (bool, error) {
				return get(ctx, outerRT{NewTransport(&http.Transport{})}, srv.URL+"/", hits)
			},
			"another RoundTripper underneath": func(t *testing.T, ctx context.Context) (bool, error) {
				return get(ctx, NewTransport(outerRT{&http.Transport{}}), srv.URL+"/", hits)
			},
		},
	})

	// DNS rebinding: the name passes the check before sending; the address
	// the connection is about to use is private.
	_, port, _ := net.SplitHostPort(host)
	rebind := "http://rebind.test:" + port + "/"
	res := &fakeResolver{table: map[string][]string{"rebind.test": {"127.0.0.1"}}}
	runSinkContract(t, sinkCase{
		name:   "rasp.NewTransport (address dialed)",
		attack: SSRF,
		inputs: AddInput(nil, rebind, "query.url"),
		call: func(t *testing.T, ctx context.Context) (bool, error) {
			return get(ctx, raspTransportWith(res), rebind, hits)
		},
		composed: map[string]sinkCall{
			"another RoundTripper on top": func(t *testing.T, ctx context.Context) (bool, error) {
				return get(ctx, outerRT{raspTransportWith(res)}, rebind, hits)
			},
		},
	})
}

func TestHTTPTransportRules(t *testing.T) {
	srv, hits := hitServer(t)
	_, port, _ := net.SplitHostPort(strings.TrimPrefix(srv.URL, "http://"))

	t.Run("the rebinding block error survives the client", func(t *testing.T) {
		setupEngine(t, engineSettings{mode: ModeBlock})
		res := &fakeResolver{table: map[string][]string{"rebind.test": {"127.0.0.1", "10.1.2.3"}}}
		u := "http://rebind.test:" + port + "/"
		_, err := get(requestCtx(AddInput(nil, u, "query.url"), nil), raspTransportWith(res), u, hits)
		var ue *url.Error
		if !errors.As(err, &ue) || AsBlocked(err) == nil || AsBlocked(err).Rule != "ssrf.internal" {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("untainted names use the pooled transport, unresolved", func(t *testing.T) {
		log := setupEngine(t, engineSettings{mode: ModeBlock})
		res := &fakeResolver{table: map[string][]string{"rebind.test": {"127.0.0.1"}}}
		rt := raspTransportWith(res)
		// The request's input does not name the host.
		ctx := requestCtx(AddInput(nil, "something else", "query.q"), nil)
		if ran, err := get(ctx, rt, srv.URL+"/", hits); err != nil || !ran {
			t.Fatalf("ran=%v err=%v", ran, err)
		}
		if res.lookups != 0 || len(log.all()) != 0 {
			t.Fatalf("lookups %d, events %v", res.lookups, log.all())
		}
	})
	t.Run("a tainted public address passes", func(t *testing.T) {
		log := setupEngine(t, engineSettings{mode: ModeBlock})
		// Resolves to a public address; the dial is refused by the fake
		// dialer, which proves it dialed exactly the checked address.
		res := &fakeResolver{table: map[string][]string{"public.test": {"93.184.215.14"}}}
		inner := &http.Transport{DialContext: func(_ context.Context, _, addr string) (net.Conn, error) {
			if addr != "93.184.215.14:"+port {
				t.Errorf("dialed %s", addr)
			}
			return nil, errors.New("no network in tests")
		}}
		rt := NewTransport(inner).(*raspTransport)
		rt.resolver = res
		u := "http://public.test:" + port + "/"
		_, err := get(requestCtx(AddInput(nil, u, "query.url"), nil), rt, u, hits)
		if err == nil || AsBlocked(err) != nil {
			t.Fatalf("got %v", err)
		}
		if len(log.all()) != 0 {
			t.Fatalf("events %v", log.all())
		}
	})
	t.Run("outbound allow-list, inside or outside a request", func(t *testing.T) {
		s := engineSettings{mode: ModeBlock, allow: Allow{OutboundHosts: []string{"*.example.com"}}}
		log := setupEngine(t, s)
		ran, err := get(context.Background(), NewTransport(nil), srv.URL+"/", hits)
		if b := AsBlocked(err); b == nil || b.Rule != "outbound.not_allowed" || ran {
			t.Fatalf("ran=%v err=%v", ran, err)
		}
		if len(log.all()) != 1 {
			t.Fatalf("events %v", log.all())
		}
		// The Shield360 and OTLP hosts are always allowed.
		s.alwaysAllowed = []string{"127.0.0.1"}
		setupEngine(t, s)
		if ran, err := get(context.Background(), NewTransport(nil), srv.URL+"/", hits); err != nil || !ran {
			t.Fatalf("always allowed: ran=%v err=%v", ran, err)
		}
	})
	t.Run("a blocked request closes its body", func(t *testing.T) {
		setupEngine(t, engineSettings{mode: ModeBlock})
		body := &closeTracker{Reader: strings.NewReader("x")}
		req, _ := http.NewRequestWithContext(requestCtx(AddInput(nil, "127.0.0.1", "query.h"), nil), http.MethodPost, srv.URL+"/", body)
		if _, err := NewTransport(nil).RoundTrip(req); AsBlocked(err) == nil {
			t.Fatalf("got %v", err)
		}
		if !body.closed {
			t.Fatal("body not closed")
		}
	})
	t.Run("WrapClient and idempotence", func(t *testing.T) {
		c := WrapClient(nil)
		if _, ok := c.Transport.(*raspTransport); !ok {
			t.Fatal("not wrapped")
		}
		if NewTransport(c.Transport) != c.Transport {
			t.Fatal("wrapped twice")
		}
		orig := &http.Client{Timeout: 5}
		if w := WrapClient(orig); w == orig || w.Timeout != 5 || orig.Transport != nil {
			t.Fatal("WrapClient must copy")
		}
		c.CloseIdleConnections()
	})
	t.Run("network filter", func(t *testing.T) {
		ips := []net.IPAddr{{IP: net.ParseIP("10.0.0.1")}, {IP: net.ParseIP("::1")}}
		if got := filterNetwork(ips, "tcp4"); len(got) != 1 || got[0].IP.To4() == nil {
			t.Fatalf("tcp4 %v", got)
		}
		if got := filterNetwork(ips, "tcp6"); len(got) != 1 || got[0].IP.To4() != nil {
			t.Fatalf("tcp6 %v", got)
		}
		if got := filterNetwork(ips, "tcp"); len(got) != 2 {
			t.Fatalf("tcp %v", got)
		}
	})
}

type closeTracker struct {
	io.Reader
	closed bool
}

func (c *closeTracker) Close() error { c.closed = true; return nil }

// A tainted request through a proxy: the target is resolved locally and
// checked before sending (the proxy's address says nothing about it).
func TestHTTPTransportProxiedTarget(t *testing.T) {
	proxy, hits := hitServer(t)
	proxyURL, _ := url.Parse(proxy.URL)
	res := &fakeResolver{table: map[string][]string{"rebind.test": {"127.0.0.1"}}}
	mk := func() http.RoundTripper {
		rt := NewTransport(&http.Transport{Proxy: http.ProxyURL(proxyURL)}).(*raspTransport)
		rt.resolver = res
		return rt
	}
	const u = "http://rebind.test:8080/"
	ctx := func() context.Context { return requestCtx(AddInput(nil, u, "query.url"), nil) }

	setupEngine(t, engineSettings{mode: ModeBlock})
	ran, err := get(ctx(), mk(), u, hits)
	if b := AsBlocked(err); b == nil || b.Rule != "ssrf.internal" || ran {
		t.Fatalf("block: ran=%v err=%v", ran, err)
	}
	log := setupEngine(t, engineSettings{mode: ModeMonitor})
	if ran, err := get(ctx(), mk(), u, hits); err != nil || !ran {
		t.Fatalf("monitor: ran=%v err=%v", ran, err)
	}
	if len(eventsOf(log, SSRF)) != 1 {
		t.Fatalf("events %v", log.all())
	}
	// Untainted requests through the proxy are not resolved.
	res.lookups = 0
	if ran, err := get(requestCtx(AddInput(nil, "other", "query.q"), nil), mk(), u, hits); err != nil || !ran || res.lookups != 0 {
		t.Fatalf("untainted: ran=%v err=%v lookups=%d", ran, err, res.lookups)
	}
}

// Internationalized hosts: the input in Unicode or punycode taints the
// request, and the IDNA ASCII name net/http dials is the one checked.
func TestHTTPTransportInternationalizedHost(t *testing.T) {
	srv, hits := hitServer(t)
	_, port, _ := net.SplitHostPort(strings.TrimPrefix(srv.URL, "http://"))
	res := &fakeResolver{table: map[string][]string{"xn--bcher-kva.test": {"127.0.0.1"}}}
	u := "http://bücher.test:" + port + "/"
	for name, input := range map[string]string{
		"unicode input":  u,
		"punycode input": "xn--bcher-kva.test",
		"escaped input":  "b%C3%BCcher.test",
	} {
		t.Run(name, func(t *testing.T) {
			setupEngine(t, engineSettings{mode: ModeBlock})
			ran, err := get(requestCtx(AddInput(nil, input, "query.url"), nil), raspTransportWith(res), u, hits)
			if b := AsBlocked(err); b == nil || b.Rule != "ssrf.internal" || ran {
				t.Fatalf("ran=%v err=%v", ran, err)
			}
		})
	}
	t.Run("allow-list in either form", func(t *testing.T) {
		for _, allowed := range []string{"bücher.test", "xn--bcher-kva.test"} {
			setupEngine(t, engineSettings{mode: ModeBlock, allow: Allow{OutboundHosts: []string{allowed}}})
			if ran, err := get(context.Background(), raspTransportWith(res), u, hits); err != nil || !ran {
				t.Fatalf("%s: ran=%v err=%v", allowed, ran, err)
			}
		}
	})
}

// A custom TLS dialer connects itself: the address it actually connected
// to is checked before the request is written, for DialTLSContext and the
// legacy DialTLS alike.
func TestHTTPTransportCustomTLSDialer(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits.Add(1) }))
	t.Cleanup(srv.Close)
	_, port, _ := net.SplitHostPort(strings.TrimPrefix(srv.URL, "https://"))
	// The name passes the check (a public address); the dialer resolves it
	// its own way and lands on loopback.
	res := &fakeResolver{table: map[string][]string{"public.test": {"93.184.215.14"}}}
	dialTLS := func(ctx context.Context, network, addr string) (net.Conn, error) {
		host, _, _ := net.SplitHostPort(addr)
		var d net.Dialer
		c, err := d.DialContext(ctx, network, "127.0.0.1:"+port)
		if err != nil {
			return nil, err
		}
		tc := tls.Client(c, &tls.Config{ServerName: host, InsecureSkipVerify: true}) // test server
		if err := tc.HandshakeContext(ctx); err != nil {
			c.Close()
			return nil, err
		}
		return tc, nil
	}
	u := "https://public.test:" + port + "/"
	bases := map[string]func() *http.Transport{
		"DialTLSContext": func() *http.Transport { return &http.Transport{DialTLSContext: dialTLS} },
		"DialTLS": func() *http.Transport {
			return &http.Transport{DialTLS: func(network, addr string) (net.Conn, error) {
				return dialTLS(context.Background(), network, addr)
			}}
		},
	}
	for name, mk := range bases {
		t.Run(name, func(t *testing.T) {
			ctx := func() context.Context { return requestCtx(AddInput(nil, u, "query.url"), nil) }
			rt := func() http.RoundTripper {
				r := NewTransport(mk()).(*raspTransport)
				r.resolver = res
				return r
			}
			setupEngine(t, engineSettings{mode: ModeBlock})
			ran, err := get(ctx(), rt(), u, &hits)
			if b := AsBlocked(err); b == nil || b.Rule != "ssrf.internal" || ran {
				t.Fatalf("block: ran=%v err=%v", ran, err)
			}
			log := setupEngine(t, engineSettings{mode: ModeMonitor})
			if ran, err := get(ctx(), rt(), u, &hits); err != nil || !ran {
				t.Fatalf("monitor: ran=%v err=%v", ran, err)
			}
			if len(eventsOf(log, SSRF)) != 1 {
				t.Fatalf("events %v", log.all())
			}
		})
	}
}

func TestIDNAForms(t *testing.T) {
	// Reference values from golang.org/x/net/idna Lookup.ToASCII.
	for in, want := range map[string]string{
		"bücher.test": "xn--bcher-kva.test", "münchen.de": "xn--mnchen-3ya.de",
		"ドメイン名例.jp": "xn--eckwd4c7cu47r2wf.jp", "faß.de": "xn--fa-hia.de",
		"BÜCHER.test": "xn--bcher-kva.test", "日本語。jp": "xn--wgv71a119e.jp",
		"Example.COM": "example.com",
	} {
		if got := toASCIIHost(in); got != want {
			t.Errorf("toASCIIHost(%q) = %q, want %q", in, got, want)
		}
	}
	pu, _ := url.Parse("http://user@bücher.test:8080/p?q=1")
	got := urlForms(pu)
	want := []string{"http://user@b%C3%BCcher.test:8080/p?q=1", "http://user@bücher.test:8080/p?q=1", "http://user@xn--bcher-kva.test:8080/p?q=1"}
	if strings.Join(got, " ") != strings.Join(want, " ") {
		t.Fatalf("urlForms = %q", got)
	}
	au, _ := url.Parse("http://example.com/")
	if len(urlForms(au)) != 1 {
		t.Fatal("ASCII hosts have one form")
	}
}
