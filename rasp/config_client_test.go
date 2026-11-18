package rasp

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

// Signed config client: verified only against a pinned key; the response's
// own keys are never trusted unless AllowUnpinnedConfig (trust on first use);
// JWKS rotation; expiry; ETag; cache re-verification; the kill switch.

type pair struct {
	kid  string
	x    string
	priv ed25519.PrivateKey
}

func keyPair(t *testing.T, kid string) pair {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return pair{kid: kid, x: base64.RawURLEncoding.EncodeToString(pub), priv: priv}
}

func b64(v any) string {
	b, _ := json.Marshal(v)
	return base64.RawURLEncoding.EncodeToString(b)
}

const nowS = 1_800_000_000

var now0 = time.Unix(nowS, 0)

func claims(over map[string]any) map[string]any {
	c := map[string]any{
		"v": 1, "app": "orders-api", "iat": nowS, "exp": nowS + 3600, "version": "abc123",
		"killSwitch": false, "snippets": false, "mode": "monitor", "attacks": map[string]any{},
		"allow": map[string]any{"commands": []string{}, "outboundHosts": []string{}, "fileRoots": []string{}}, "rules": nil,
	}
	for k, v := range over {
		c[k] = v
	}
	return c
}

func jws(k pair, c map[string]any, header map[string]any) string {
	h := map[string]any{"alg": "EdDSA", "typ": JWSType, "kid": k.kid}
	for key, v := range header {
		h[key] = v
	}
	head, body := b64(h), b64(c)
	sig := ed25519.Sign(k.priv, []byte(head+"."+body))
	return head + "." + body + "." + base64.RawURLEncoding.EncodeToString(sig)
}

func jwk(k pair) map[string]any {
	return map[string]any{"kty": "OKP", "crv": "Ed25519", "x": k.x, "kid": k.kid}
}

func jsonText(v any) string { b, _ := json.Marshal(v); return string(b) }

func verifyReason(token string, keys []PinnedKey, app string, at time.Time) string {
	_, _, reason := VerifyConfigJWS(token, keys, app, at)
	return reason
}

func TestVerifyConfigJWS(t *testing.T) {
	k1, k2 := keyPair(t, "k1"), keyPair(t, "k2")
	pinned := ParsePublicKeys(jsonText(jwk(k1)))

	t.Run("accepts a config signed by the pinned key", func(t *testing.T) {
		c, kid, reason := VerifyConfigJWS(jws(k1, claims(nil), nil), pinned, "orders-api", now0)
		if reason != "" || c.Version != "abc123" || kid != "k1" {
			t.Fatalf("reason=%s claims=%+v", reason, c)
		}
	})
	t.Run("refuses another key, whatever kid it names", func(t *testing.T) {
		if r := verifyReason(jws(k2, claims(nil), nil), pinned, "orders-api", now0); r != "signature" {
			t.Errorf("reason %s", r)
		}
		forged := k2
		forged.kid = "k1"
		if r := verifyReason(jws(forged, claims(nil), nil), pinned, "orders-api", now0); r != "signature" {
			t.Errorf("reason %s", r)
		}
	})
	t.Run("refuses a wrong typ, alg, app, version, or an expired config (60 s skew)", func(t *testing.T) {
		cases := []struct {
			token, want string
		}{
			{jws(k1, claims(nil), map[string]any{"typ": "JWT"}), "typ"},
			{jws(k1, claims(nil), map[string]any{"alg": "none"}), "alg"},
			{jws(k1, claims(map[string]any{"app": "other"}), nil), "app"},
			{jws(k1, claims(map[string]any{"v": 2}), nil), "version"},
			{jws(k1, claims(map[string]any{"version": ""}), nil), "version"},
			{jws(k1, claims(map[string]any{"exp": nowS - 61}), nil), "expired"},
			{jws(k1, claims(map[string]any{"exp": nowS - 30}), nil), ""},
		}
		for _, c := range cases {
			if r := verifyReason(c.token, pinned, "orders-api", now0); r != c.want {
				t.Errorf("reason %q, want %q", r, c.want)
			}
		}
	})
	t.Run("refuses a tampered payload", func(t *testing.T) {
		parts := strings.Split(jws(k1, claims(nil), nil), ".")
		tampered := parts[0] + "." + b64(claims(map[string]any{"killSwitch": true})) + "." + parts[2]
		if r := verifyReason(tampered, pinned, "orders-api", now0); r != "signature" {
			t.Errorf("reason %s", r)
		}
	})
	t.Run("JWKS rotation: either pinned kid verifies; an unpinned kid does not", func(t *testing.T) {
		k3 := keyPair(t, "k3")
		jwks := ParsePublicKeys(jsonText(map[string]any{"keys": []any{jwk(k1), jwk(k2)}}))
		if len(jwks) != 2 {
			t.Fatalf("parsed %d keys", len(jwks))
		}
		for _, k := range []pair{k1, k2} {
			if r := verifyReason(jws(k, claims(nil), nil), jwks, "orders-api", now0); r != "" {
				t.Errorf("%s: %s", k.kid, r)
			}
		}
		if r := verifyReason(jws(k3, claims(nil), nil), jwks, "orders-api", now0); r == "" {
			t.Error("k3 verified")
		}
	})
	t.Run("parses the pinned key as a JWK, a JWKS, or the bare base64url x; refuses anything else", func(t *testing.T) {
		if len(ParsePublicKeys(k1.x)) != 1 {
			t.Error("bare x")
		}
		if ks := ParsePublicKeys(jsonText(jwk(k1))); len(ks) != 1 || ks[0].Kid != "k1" {
			t.Error("JWK")
		}
		if ks := ParsePublicKeys(jsonText([]any{jwk(k1)})); len(ks) != 1 || ks[0].X != k1.x {
			t.Error("JSON array")
		}
		pem := "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEA\n-----END PUBLIC KEY-----"
		for _, bad := range []string{pem, "not-a-key", jsonText(map[string]any{"kty": "RSA", "crv": "x", "x": k1.x}), "{broken"} {
			if len(ParsePublicKeys(bad)) != 0 {
				t.Errorf("accepted %q", bad)
			}
		}
		// A bare key (no kid) verifies whatever kid the header names; so does a JWKS when the header's kid is not listed.
		if r := verifyReason(jws(k1, claims(nil), nil), ParsePublicKeys(k1.x), "orders-api", now0); r != "" {
			t.Errorf("bare key: %s", r)
		}
		unlisted := k1
		unlisted.kid = "unlisted"
		if r := verifyReason(jws(unlisted, claims(nil), nil), ParsePublicKeys(jsonText(map[string]any{"keys": []any{jwk(k2), jwk(k1)}})), "orders-api", now0); r != "" {
			t.Errorf("unlisted kid: %s", r)
		}
	})
	t.Run("reads the claims the engine uses", func(t *testing.T) {
		c, _, _ := VerifyConfigJWS(jws(k1, claims(map[string]any{
			"killSwitch": true, "snippets": true, "mode": "block", "attacks": map[string]any{"sql_injection": "block"},
			"allow": map[string]any{"commands": []any{"git", 3}}, "rules": []any{map[string]any{"id": "vp.a", "match": []any{}}, "bad"},
			"sinks": []any{map[string]any{"id": "sink.x"}},
		}), nil), pinned, "orders-api", now0)
		if c == nil || !c.KillSwitch || !c.Snippets || c.Mode != ModeBlock || c.Attacks[SQLInjection] != ModeBlock ||
			c.Allow == nil || len(c.Allow.Commands) != 1 || c.Allow.OutboundHosts != nil || len(c.Rules) != 1 || len(c.Sinks) != 1 {
			t.Errorf("claims %+v", c)
		}
		if c.ReportTargets {
			t.Error("reportTargets absent must be false")
		}
		c, _, _ = VerifyConfigJWS(jws(k1, claims(map[string]any{"reportTargets": true}), nil), pinned, "orders-api", now0)
		if c == nil || !c.ReportTargets || !toRemote(c).ReportTargets {
			t.Errorf("reportTargets %+v", c)
		}
	})
}

type served struct {
	status int
	config string
	keys   []any
	etag   string
}

type fakeServer struct {
	*httptest.Server
	mu    sync.Mutex
	serve func() served
	calls []*http.Request
}

func newFakeServer(t *testing.T, serve func() served) *fakeServer {
	f := &fakeServer{serve: serve}
	f.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		f.calls = append(f.calls, r.Clone(context.Background()))
		s := f.serve()
		f.mu.Unlock()
		if s.etag != "" {
			w.Header().Set("ETag", s.etag)
		}
		status := s.status
		if status == 0 {
			status = 200
		}
		w.WriteHeader(status)
		if status != http.StatusNotModified {
			keys := s.keys
			if keys == nil {
				keys = []any{}
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"config": s.config, "keys": keys})
		}
	}))
	t.Cleanup(f.Close)
	return f
}

func (f *fakeServer) requests() []*http.Request {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]*http.Request(nil), f.calls...)
}

type clientRig struct {
	c        *ConfigClient
	srv      *fakeServer
	applied  []*Claims
	warnings []string
	now      time.Time
	mu       sync.Mutex
}

func newClientRig(t *testing.T, dir string, pinned []PinnedKey, serve func() served, edit func(*ConfigClientOptions)) *clientRig {
	rig := &clientRig{now: now0}
	rig.srv = newFakeServer(t, serve)
	o := ConfigClientOptions{
		URL: rig.srv.URL + "/", APIKey: "test-api-key", App: "orders-api", Pinned: pinned, CacheDir: dir,
		OnConfig:  func(c *Claims) { rig.mu.Lock(); rig.applied = append(rig.applied, c); rig.mu.Unlock() },
		OnWarning: func(w string) { rig.mu.Lock(); rig.warnings = append(rig.warnings, w); rig.mu.Unlock() },
		Now:       func() time.Time { rig.mu.Lock(); defer rig.mu.Unlock(); return rig.now },
	}
	if edit != nil {
		edit(&o)
	}
	rig.c = NewConfigClient(o)
	return rig
}

func TestConfigClient(t *testing.T) {
	k1, k2 := keyPair(t, "k1"), keyPair(t, "k2")
	pinned := ParsePublicKeys(jsonText(jwk(k1)))
	ctx := context.Background()

	t.Run("pinned: fetches with the API key and applies a verified config", func(t *testing.T) {
		rig := newClientRig(t, t.TempDir(), pinned, func() served { return served{config: jws(k1, claims(nil), nil), keys: []any{jwk(k1)}, etag: `"e1"`} }, nil)
		if r := rig.c.Poll(ctx); r != PollUpdated {
			t.Fatalf("poll %s", r)
		}
		req := rig.srv.requests()[0]
		if req.URL.RequestURI() != "/api/rasp/config?app=orders-api" || req.Header.Get("Authorization") != "Bearer test-api-key" {
			t.Errorf("request %s %v", req.URL, req.Header)
		}
		if rig.applied[0].Version != "abc123" {
			t.Error("not applied")
		}
	})

	t.Run("pinned: the response's own key is not trusted", func(t *testing.T) {
		rig := newClientRig(t, t.TempDir(), pinned, func() served { return served{config: jws(k2, claims(nil), nil), keys: []any{jwk(k2)}} }, nil)
		if r := rig.c.Poll(ctx); r != PollRejected {
			t.Fatalf("poll %s", r)
		}
		if len(rig.applied) != 0 || len(rig.warnings) != 1 || rig.warnings[0] != "signature" {
			t.Errorf("applied %v warnings %v", rig.applied, rig.warnings)
		}
	})

	t.Run("unpinned: refused without fetching; nothing applied", func(t *testing.T) {
		rig := newClientRig(t, t.TempDir(), nil, func() served { return served{config: jws(k1, claims(nil), nil), keys: []any{jwk(k1)}} }, nil)
		if r := rig.c.Poll(ctx); r != PollRejected {
			t.Fatalf("poll %s", r)
		}
		if len(rig.srv.requests()) != 0 || len(rig.applied) != 0 || len(rig.warnings) != 1 || rig.warnings[0] != "unpinned" {
			t.Errorf("calls %d applied %v warnings %v", len(rig.srv.requests()), rig.applied, rig.warnings)
		}
	})

	t.Run("AllowUnpinned: trusts the first key, then refuses a different one", func(t *testing.T) {
		key := k1
		rig := newClientRig(t, t.TempDir(), nil, func() served { return served{config: jws(key, claims(nil), nil), keys: []any{jwk(key)}} },
			func(o *ConfigClientOptions) { o.AllowUnpinned = true })
		if r := rig.c.Poll(ctx); r != PollUpdated {
			t.Fatalf("poll %s", r)
		}
		if !contains(rig.warnings, "trust_on_first_use") {
			t.Errorf("warnings %v", rig.warnings)
		}
		rig.srv.mu.Lock()
		key = k2
		rig.srv.mu.Unlock()
		if r := rig.c.Poll(ctx); r != PollRejected {
			t.Errorf("second key: %s", r)
		}
	})

	t.Run("ETag: sends If-None-Match and keeps the config on 304", func(t *testing.T) {
		status := 200
		rig := newClientRig(t, t.TempDir(), pinned, func() served { return served{status: status, config: jws(k1, claims(nil), nil), etag: `"e1"`} }, nil)
		rig.c.Poll(ctx)
		rig.srv.mu.Lock()
		status = 304
		rig.srv.mu.Unlock()
		if r := rig.c.Poll(ctx); r != PollUnchanged {
			t.Fatalf("poll %s", r)
		}
		if got := rig.srv.requests()[1].Header.Get("If-None-Match"); got != `"e1"` {
			t.Errorf("If-None-Match %q", got)
		}
		if rig.c.Current().Version != "abc123" {
			t.Error("config dropped")
		}
	})

	t.Run("expiry: an expired config is refused; the one in force is dropped once it expires", func(t *testing.T) {
		stale := newClientRig(t, t.TempDir(), pinned, func() served { return served{config: jws(k1, claims(map[string]any{"exp": nowS - 3600}), nil)} }, nil)
		if r := stale.c.Poll(ctx); r != PollRejected {
			t.Errorf("stale: %s", r)
		}
		up := true
		rig := newClientRig(t, t.TempDir(), pinned, func() served {
			if up {
				return served{config: jws(k1, claims(map[string]any{"exp": nowS + 120}), nil)}
			}
			return served{status: 503}
		}, nil)
		rig.c.Poll(ctx)
		rig.srv.mu.Lock()
		up = false
		rig.srv.mu.Unlock()
		rig.mu.Lock()
		rig.now = rig.now.Add(10 * time.Minute)
		rig.mu.Unlock()
		if r := rig.c.Poll(ctx); r != PollFailed {
			t.Errorf("poll %s", r)
		}
		if rig.applied[len(rig.applied)-1] != nil || rig.c.Current() != nil {
			t.Error("expired config still in force")
		}
	})

	t.Run("failures back off to 5 minutes; success polls about every minute", func(t *testing.T) {
		rig := newClientRig(t, t.TempDir(), pinned, func() served { return served{} }, func(o *ConfigClientOptions) { o.Random = func() float64 { return 1 } })
		if rig.c.NextDelay(PollFailed) != Backoff || rig.c.NextDelay(PollRejected) != Backoff || rig.c.NextDelay(PollUpdated) != 70*time.Second {
			t.Error("delays")
		}
	})

	t.Run("cache: the last verified config is re-verified on load; a tampered cache is refused", func(t *testing.T) {
		dir := t.TempDir()
		rig := newClientRig(t, dir, pinned, func() served { return served{config: jws(k1, claims(map[string]any{"version": "cached"}), nil)} }, nil)
		rig.c.Poll(ctx)
		fresh := newClientRig(t, dir, pinned, func() served { return served{status: 503} }, nil)
		if !fresh.c.LoadCache() || fresh.c.Current().Version != "cached" {
			t.Fatal("cache not loaded")
		}
		if info, err := os.Stat(fresh.c.CacheFile()); err != nil || info.Mode().Perm() != 0o600 {
			t.Errorf("cache file mode: %v %v", info, err)
		}
		forged := jsonText(map[string]any{"config": jws(k2, claims(map[string]any{"version": "forged"}), nil), "tofu": []any{jwk(k2)}})
		if err := os.WriteFile(fresh.c.CacheFile(), []byte(forged), 0o600); err != nil {
			t.Fatal(err)
		}
		other := newClientRig(t, dir, pinned, func() served { return served{status: 503} }, nil)
		if other.c.LoadCache() || other.c.Current() != nil {
			t.Error("forged cache accepted")
		}
	})

	t.Run("never panics on a network error or a malformed body", func(t *testing.T) {
		boom := NewConfigClient(ConfigClientOptions{URL: "http://127.0.0.1:1", APIKey: "k", App: "orders-api", Pinned: pinned, CacheDir: t.TempDir()})
		if r := boom.Poll(ctx); r != PollFailed {
			t.Errorf("offline: %s", r)
		}
		rig := newClientRig(t, t.TempDir(), pinned, func() served { return served{config: "not.a.jws"} }, nil)
		if r := rig.c.Poll(ctx); r != PollRejected {
			t.Errorf("malformed: %s", r)
		}
	})
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

// captureLogs replaces the package logger for a test.
func captureLogs(t *testing.T) func() []string {
	t.Helper()
	var mu sync.Mutex
	var lines []string
	prev := logf
	logf = func(format string, args ...any) {
		mu.Lock()
		defer mu.Unlock()
		lines = append(lines, fmt.Sprintf(format, args...))
	}
	warnUnpinnedOnce = sync.Once{}
	t.Cleanup(func() {
		logf = prev
		Shutdown(context.Background())
		configureEngine(engineSettings{applicationName: "default", getenv: noEnv})
	})
	return func() []string {
		mu.Lock()
		defer mu.Unlock()
		return append([]string(nil), lines...)
	}
}

func TestInitAndTheSignedConfig(t *testing.T) {
	k1 := keyPair(t, "k1")

	t.Run("without a pin: no config fetch, built-in defaults in monitor mode, one log line per process, no reported event", func(t *testing.T) {
		logs := captureLogs(t)
		var mu sync.Mutex
		var paths []string
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			mu.Lock()
			paths = append(paths, r.URL.Path)
			mu.Unlock()
			_, _ = w.Write([]byte("{}"))
		}))
		defer srv.Close()
		ic := InitContext{ApplicationName: "orders-api", URL: srv.URL, APIKey: "k", Getenv: noEnv}
		if !Init(&Options{Mode: ModeBlock, Attacks: map[AttackType]Mode{SSRF: ModeOff}, DisableComponents: true}, ic) {
			t.Fatal("not on")
		}
		if ModeFor(SQLInjection) != ModeMonitor || ModeFor(SSRF) != ModeOff {
			t.Errorf("modes %s %s", ModeFor(SQLInjection), ModeFor(SSRF))
		}
		Init(&Options{DisableComponents: true}, ic)
		Shutdown(context.Background())
		mu.Lock()
		defer mu.Unlock()
		if len(paths) != 0 {
			t.Errorf("requests %v", paths)
		}
		if l := logs(); len(l) != 1 || !strings.Contains(l[0], "ConfigPublicKey") {
			t.Errorf("logs %v", l)
		}
	})

	t.Run("trust on first use: only with the opt-in, never in production", func(t *testing.T) {
		captureLogs(t)
		if !TofuAllowed(true, "", noEnv) || !TofuAllowed(false, "", envOf("SHIELD360_CONFIG_TOFU", "dev")) || TofuAllowed(false, "", noEnv) {
			t.Error("opt-in")
		}
		if TofuAllowed(true, "", envOf("NODE_ENV", "production")) || TofuAllowed(false, "", envOf("SHIELD360_CONFIG_TOFU", "dev", "ENVIRONMENT", "production")) ||
			TofuAllowed(true, "production", noEnv) || TofuAllowed(true, "", envOf("ASPNETCORE_ENVIRONMENT", "Production")) {
			t.Error("production")
		}
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(503) }))
		defer srv.Close()
		Init(&Options{Mode: ModeBlock, AllowUnpinnedConfig: true, DisableComponents: true},
			InitContext{ApplicationName: "a", URL: srv.URL, APIKey: "k", Getenv: envOf("ENVIRONMENT", "production")})
		if ModeFor(SQLInjection) != ModeMonitor {
			t.Error("tofu honored in production")
		}
		Init(&Options{Mode: ModeBlock, DisableComponents: true, CacheDir: t.TempDir()},
			InitContext{ApplicationName: "a", URL: srv.URL, APIKey: "k", Getenv: envOf("SHIELD360_CONFIG_TOFU", "dev")})
		if ModeFor(SQLInjection) != ModeBlock {
			t.Error("tofu in development caps block")
		}
	})

	t.Run("with a pin from SHIELD360_CONFIG_PUBLIC_KEY: the signed kill switch turns checks off", func(t *testing.T) {
		captureLogs(t)
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if strings.HasPrefix(r.URL.Path, "/api/rasp/config") {
				_ = json.NewEncoder(w).Encode(map[string]any{"config": jws(k1, claims(map[string]any{"exp": time.Now().Unix() + 600, "killSwitch": true}), nil)})
				return
			}
			_, _ = w.Write([]byte("{}"))
		}))
		defer srv.Close()
		Init(&Options{DisableComponents: true, CacheDir: t.TempDir()}, InitContext{
			ApplicationName: "orders-api", URL: srv.URL, APIKey: "k",
			Getenv: envOf("SHIELD360_CONFIG_PUBLIC_KEY", jsonText(map[string]any{"keys": []any{jwk(k1)}})),
		})
		deadline := time.Now().Add(5 * time.Second)
		for Active() && time.Now().Before(deadline) {
			time.Sleep(10 * time.Millisecond)
		}
		if Active() {
			t.Error("kill switch not applied")
		}
		if !Enabled() {
			t.Error("the kill switch must not un-enable RASP")
		}
	})

	t.Run("SHIELD360_RASP=off wins over Options; no URL means local options only", func(t *testing.T) {
		captureLogs(t)
		if Init(&Options{}, InitContext{ApplicationName: "a", Getenv: envOf("SHIELD360_RASP", "off")}) {
			t.Error("env off ignored")
		}
		if !Init(&Options{Mode: ModeBlock}, InitContext{ApplicationName: "a", Getenv: noEnv}) || ModeFor(SQLInjection) != ModeBlock {
			t.Error("local block")
		}
		if !Init(nil, InitContext{ApplicationName: "a", Getenv: envOf("SHIELD360_RASP", "monitor")}) {
			t.Error("env monitor")
		}
		if Init(nil, InitContext{ApplicationName: "a", Getenv: noEnv}) {
			t.Error("on without options or env")
		}
		if Init(&Options{Disabled: true}, InitContext{ApplicationName: "a", Getenv: noEnv}) {
			t.Error("Disabled ignored")
		}
	})

	t.Run("always-allowed hosts are the Shield360 URL and the OTLP endpoint", func(t *testing.T) {
		captureLogs(t)
		Init(&Options{DisableComponents: true}, InitContext{ApplicationName: "a", Getenv: noEnv, URL: "https://Shield.example.com/x", APIKey: "k", OtlpEndpoint: "http://[::1]:4318"})
		got := AlwaysAllowedHosts()
		if len(got) != 2 || got[0] != "shield.example.com" || got[1] != "::1" {
			t.Errorf("hosts %v", got)
		}
	})
}

// The contract rejects a config once exp + 60 s <= now, with no rounding of
// a fractional exp.
func TestFractionalExpIsNotRoundedUp(t *testing.T) {
	k1 := keyPair(t, "k1")
	pinned := ParsePublicKeys(jsonText(jwk(k1)))
	token := jws(k1, claims(map[string]any{"exp": float64(nowS) + 0.1}), nil)
	at := time.UnixMilli(int64(nowS)*1000 + 60_500) // exp + 60.4 s
	if r := verifyReason(token, pinned, "orders-api", at); r != "expired" {
		t.Errorf("reason %q, want expired", r)
	}
	if r := verifyReason(token, pinned, "orders-api", time.UnixMilli(int64(nowS)*1000+60_000)); r != "" {
		t.Errorf("exp + 59.9 s: %q", r)
	}
}

// A poll in flight when Stop is called applies and caches nothing, so a
// re-Init's new client is never overwritten by the old one.
func TestStoppedClientNeverApplies(t *testing.T) {
	k1 := keyPair(t, "k1")
	pinned := ParsePublicKeys(jsonText(jwk(k1)))
	got := make(chan struct{})
	release := make(chan struct{})
	var once sync.Once
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		once.Do(func() { close(got) })
		<-release
		_ = json.NewEncoder(w).Encode(map[string]any{"config": jws(k1, claims(nil), nil)})
	}))
	defer srv.Close()
	var mu sync.Mutex
	var applied []*Claims
	dir := t.TempDir()
	c := NewConfigClient(ConfigClientOptions{
		URL: srv.URL, APIKey: "k", App: "orders-api", Pinned: pinned, CacheDir: dir,
		Now:      func() time.Time { return now0 },
		OnConfig: func(cl *Claims) { mu.Lock(); applied = append(applied, cl); mu.Unlock() },
	})
	result := make(chan PollResult)
	go func() { result <- c.Poll(context.Background()) }()
	<-got
	c.Stop()
	close(release)
	if r := <-result; r == PollUpdated {
		t.Errorf("poll result %s after Stop", r)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(applied) != 0 || c.Current() != nil {
		t.Errorf("a stopped client applied %v", applied)
	}
	if _, err := os.Stat(c.CacheFile()); !os.IsNotExist(err) {
		t.Errorf("a stopped client wrote the cache: %v", err)
	}
}

// Re-Init never waits on the previous reporter's network sends.
func TestReInitDoesNotBlockOnTheNetwork(t *testing.T) {
	captureLogs(t)
	hang := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-hang:
		case <-r.Context().Done():
		}
	}))
	t.Cleanup(func() { close(hang); srv.Close() })
	ic := InitContext{ApplicationName: "orders-api", URL: srv.URL, APIKey: "k", Getenv: noEnv}
	if !Init(&Options{DisableComponents: true}, ic) {
		t.Fatal("not on")
	}
	f := finding
	if d, _ := HandleFinding(context.Background(), &f, "pg.query", FindingExtra{}); d != DecisionMonitored {
		t.Fatalf("decision %s", d)
	}
	start := time.Now()
	Init(&Options{DisableComponents: true}, InitContext{ApplicationName: "billing-api", Getenv: noEnv})
	if d := time.Since(start); d > time.Second {
		t.Errorf("re-Init took %s waiting on the old reporter", d)
	}
}
