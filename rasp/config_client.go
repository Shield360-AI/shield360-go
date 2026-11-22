package rasp

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"io"
	"math"
	"math/rand/v2"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

// The signed RASP config client (README "The signed config").
//
// GET /api/rasp/config?app= returns {config: <compact JWS>, keys}. The JWS is
// trusted only when it verifies against a key the app pinned
// (Options.ConfigPublicKey / SHIELD360_CONFIG_PUBLIC_KEY: a JWK, a JWKS for
// rotation, or the bare base64url Ed25519 x). The keys in the response are
// never trusted on their own: they came over the same channel as the config.
// Only with trust on first use (development: Options.AllowUnpinnedConfig or
// SHIELD360_CONFIG_TOFU=dev, never in production) is the first kid seen
// pinned; a config signed by another kid after that is rejected. A pinned key
// that does not verify never falls back to trust on first use.
//
// ETag polling every 60 s ± 10 s, 5 minutes after a failure; the last
// verified config is kept in memory and in a cache file that is re-verified
// when loaded. Never panics and never blocks start-up.

// Signed-config constants.
const (
	JWSType      = "shield360-rasp+jws"
	Skew         = 60 * time.Second
	PollInterval = 60 * time.Second
	PollJitter   = 10 * time.Second
	Backoff      = 5 * time.Minute
	fetchTimeout = 10 * time.Second
	maxToken     = 256 * 1024
	maxResponse  = 1024 * 1024
)

// Claims are the signed config's claims.
type Claims struct {
	V          int
	App        string
	Iat        int64
	Exp        float64 // seconds; a fractional exp is kept as sent
	Version    string
	KillSwitch bool
	Snippets   bool
	// ReportTargets lets allow-list events carry shield360.rasp.target
	// (absent = false).
	ReportTargets bool
	Mode          Mode
	Attacks       map[AttackType]Mode
	// Allow is nil when the config does not set it; a nil list inside keeps
	// the local one.
	Allow *RemoteAllow
	// Rules is nil for "rules": null (keep the built-in list).
	Rules []VirtualPatchRule
	// Sinks are sink rules as sent. Go is compiled without runtime patching
	// and ignores them (README "Sink rules"); they are kept for completeness.
	Sinks []json.RawMessage
	// CustomRules are the custom rules as sent (README "Custom rules"); nil
	// for none. The engine validates and compiles them.
	CustomRules []json.RawMessage
	// Deception is the usable deception block (README "Deception"); nil
	// when absent or off.
	Deception *DeceptionConfig
	// Iast is the passive IAST switch ("on", "off", or "" when absent) and
	// IastSampleRate its sampling rate (nil when absent or not a number).
	Iast           string
	IastSampleRate *float64
	// Uploads is the upload policy as sent (README "Upload policy and deep
	// scan"); nil when absent. ParseUploadPolicy reads it.
	Uploads json.RawMessage
	// EdgeKeys are the signed config's edgeContext keys (protection triangle).
	EdgeKeys []EdgeKey
	// AttackAgents is the attackAgents block, read (README "AI attack
	// agents"); nil when absent or not an object.
	AttackAgents *AttackAgentConfig
	// Raw is the verified claims as sent (JSON), for documents other than
	// the RASP config (the Defend policy).
	Raw []byte
}

// PinnedKey is an Ed25519 public key a config must verify against.
type PinnedKey struct {
	Kid string
	X   string
	Key ed25519.PublicKey
}

var b64urlRe = regexp.MustCompile(`^[A-Za-z0-9_-]+$`)

func b64url(s string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(strings.TrimRight(s, "="))
}

func keyFromJWK(raw json.RawMessage) (PinnedKey, bool) {
	var j struct {
		Kty string `json:"kty"`
		Crv string `json:"crv"`
		X   any    `json:"x"`
		Kid any    `json:"kid"`
	}
	if json.Unmarshal(raw, &j) != nil || j.Kty != "OKP" || j.Crv != "Ed25519" {
		return PinnedKey{}, false
	}
	x, ok := j.X.(string)
	if !ok {
		return PinnedKey{}, false
	}
	k, ok := keyFromX(x)
	if !ok {
		return PinnedKey{}, false
	}
	if kid, ok := j.Kid.(string); ok {
		k.Kid = kid
	}
	return k, true
}

func keyFromX(x string) (PinnedKey, bool) {
	if !b64urlRe.MatchString(x) {
		return PinnedKey{}, false
	}
	b, err := b64url(x)
	if err != nil || len(b) != ed25519.PublicKeySize {
		return PinnedKey{}, false
	}
	return PinnedKey{X: x, Key: ed25519.PublicKey(b)}, true
}

// ParsePublicKeys parses a pinned key: a JWK, a JWKS ({"keys": [...]}, or a
// JSON array of JWKs), or the bare base64url Ed25519 x. Unusable entries are
// left out; the result is empty when none is usable.
func ParsePublicKeys(input string) []PinnedKey {
	s := strings.TrimSpace(input)
	if s == "" {
		return nil
	}
	if !strings.HasPrefix(s, "{") && !strings.HasPrefix(s, "[") {
		if k, ok := keyFromX(s); ok {
			return []PinnedKey{k}
		}
		return nil
	}
	var list []json.RawMessage
	if strings.HasPrefix(s, "[") {
		if json.Unmarshal([]byte(s), &list) != nil {
			return nil
		}
	} else {
		var obj map[string]json.RawMessage
		if json.Unmarshal([]byte(s), &obj) != nil {
			return nil
		}
		if keys, ok := obj["keys"]; ok && json.Unmarshal(keys, &list) == nil {
			// a JWKS
		} else {
			list = []json.RawMessage{json.RawMessage(s)}
		}
	}
	return parseKeyList(list)
}

func parseKeyList(list []json.RawMessage) []PinnedKey {
	var out []PinnedKey
	for i, raw := range list {
		if i >= 16 {
			break
		}
		if k, ok := keyFromJWK(raw); ok {
			out = append(out, k)
		}
	}
	return out
}

func jwsHeader(token string) map[string]any {
	first, _, _ := strings.Cut(token, ".")
	b, err := b64url(first)
	if err != nil {
		return nil
	}
	var h map[string]any
	if json.Unmarshal(b, &h) != nil {
		return nil
	}
	return h
}

// JWSKid returns the kid in a JWS header, or "".
func JWSKid(token string) string {
	h := jwsHeader(token)
	kid, _ := h["kid"].(string)
	return kid
}

// VerifyConfigJWS verifies a compact JWS against the given keys only: alg
// EdDSA, typ shield360-rasp+jws, an Ed25519 signature by the pinned key whose
// kid matches the header (any pinned key when the header names none listed),
// v 1, app equal to ours, exp in the future (60 s skew), a version. On
// failure it returns a reason: malformed, alg, typ, no_key, signature,
// version, app, expired.
func VerifyConfigJWS(token string, keys []PinnedKey, app string, now time.Time) (claims *Claims, kid string, reason string) {
	return VerifyTypedJWS(token, keys, app, now, JWSType)
}

// VerifyTypedJWS is VerifyConfigJWS for another signed document of the same
// shape (the Defend policy, typ shield360-defend+jws).
func VerifyTypedJWS(token string, keys []PinnedKey, app string, now time.Time, typ string) (claims *Claims, kid string, reason string) {
	defer func() {
		if recover() != nil {
			claims, kid, reason = nil, "", "malformed"
		}
	}()
	if token == "" || len(token) > maxToken {
		return nil, "", "malformed"
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, "", "malformed"
	}
	for _, p := range parts {
		if !b64urlRe.MatchString(p) {
			return nil, "", "malformed"
		}
	}
	h := jwsHeader(token)
	if h == nil {
		return nil, "", "malformed"
	}
	if h["alg"] != "EdDSA" {
		return nil, "", "alg"
	}
	if h["typ"] != typ {
		return nil, "", "typ"
	}
	kid, _ = h["kid"].(string)
	var candidates []PinnedKey
	if kid != "" {
		for _, k := range keys {
			if k.Kid == kid {
				candidates = append(candidates, k)
			}
		}
	}
	if len(candidates) == 0 {
		candidates = keys
	}
	if len(candidates) == 0 {
		return nil, kid, "no_key"
	}
	signed := []byte(parts[0] + "." + parts[1])
	sig, err := b64url(parts[2])
	if err != nil {
		return nil, kid, "malformed"
	}
	verified := false
	for _, k := range candidates {
		if len(k.Key) == ed25519.PublicKeySize && ed25519.Verify(k.Key, signed, sig) {
			verified = true
			break
		}
	}
	if !verified {
		return nil, kid, "signature"
	}
	payload, err := b64url(parts[1])
	if err != nil {
		return nil, kid, "malformed"
	}
	c, reason := parseClaims(payload)
	if reason != "" {
		return nil, kid, reason
	}
	c.Raw = payload
	if c.App != app {
		return nil, kid, "app"
	}
	if c.Exp+Skew.Seconds() <= float64(now.UnixMilli())/1000 {
		return nil, kid, "expired"
	}
	if c.Version == "" {
		return nil, kid, "version"
	}
	return c, kid, ""
}

// parseClaims reads the claims with the TypeScript client's type checks.
func parseClaims(payload []byte) (*Claims, string) {
	var m map[string]json.RawMessage
	if err := json.Unmarshal(payload, &m); err != nil {
		var probe any
		if json.Unmarshal(payload, &probe) == nil {
			return nil, "version" // valid JSON, not an object
		}
		return nil, "malformed"
	}
	if m == nil {
		return nil, "version"
	}
	var v float64
	if json.Unmarshal(m["v"], &v) != nil || v != 1 {
		return nil, "version"
	}
	c := &Claims{V: 1}
	var app any
	_ = json.Unmarshal(m["app"], &app)
	appStr, ok := app.(string)
	if !ok {
		return nil, "app"
	}
	c.App = appStr
	var exp any
	if json.Unmarshal(m["exp"], &exp) != nil {
		return nil, "expired"
	}
	expF, ok := exp.(float64)
	if !ok || math.IsNaN(expF) {
		return nil, "expired"
	}
	c.Exp = expF
	var iat float64
	if json.Unmarshal(m["iat"], &iat) == nil {
		c.Iat = int64(iat)
	}
	_ = json.Unmarshal(m["version"], &c.Version)
	var b bool
	if json.Unmarshal(m["killSwitch"], &b) == nil {
		c.KillSwitch = b
	}
	b = false
	if json.Unmarshal(m["snippets"], &b) == nil {
		c.Snippets = b
	}
	b = false
	if json.Unmarshal(m["reportTargets"], &b) == nil {
		c.ReportTargets = b
	}
	var mode string
	if json.Unmarshal(m["mode"], &mode) == nil {
		c.Mode = asMode(mode)
	}
	var attacks map[string]any
	if json.Unmarshal(m["attacks"], &attacks) == nil && attacks != nil {
		c.Attacks = map[AttackType]Mode{}
		for k, val := range attacks {
			if s, ok := val.(string); ok {
				c.Attacks[AttackType(k)] = Mode(s)
			}
		}
	}
	var allow map[string]json.RawMessage
	if json.Unmarshal(m["allow"], &allow) == nil && allow != nil {
		a := &RemoteAllow{}
		a.Commands, _ = stringsOf(allow["commands"])
		a.OutboundHosts, _ = stringsOf(allow["outboundHosts"])
		a.FileRoots, _ = stringsOf(allow["fileRoots"])
		c.Allow = a
	}
	var rules []json.RawMessage
	if json.Unmarshal(m["rules"], &rules) == nil && rules != nil {
		c.Rules = parseRules(rules)
	}
	var sinks []json.RawMessage
	if json.Unmarshal(m["sinks"], &sinks) == nil && sinks != nil {
		c.Sinks = sinks
	}
	var custom []json.RawMessage
	if json.Unmarshal(m["customRules"], &custom) == nil && custom != nil {
		c.CustomRules = custom
	}
	c.Deception = ParseDeception(m["deception"])
	c.EdgeKeys = ParseEdgeKeys(m["edgeContext"])
	if raw := m["attackAgents"]; len(raw) > 0 && raw[0] == '{' {
		a := ParseAttackAgents(raw)
		c.AttackAgents = &a
	}
	if u := m["uploads"]; len(u) > 0 && string(u) != "null" {
		c.Uploads = u
	}
	// The TypeScript client also reads a boolean switch and a numeric string
	// rate.
	var iast any
	if json.Unmarshal(m["iast"], &iast) == nil {
		switch v := iast.(type) {
		case string:
			c.Iast = v
		case bool:
			c.Iast = map[bool]string{true: "on", false: "off"}[v]
		}
	}
	var rate any
	if json.Unmarshal(m["iastSampleRate"], &rate) == nil {
		switch v := rate.(type) {
		case float64:
			c.IastSampleRate = &v
		case string:
			if f, err := strconv.ParseFloat(strings.TrimSpace(v), 64); err == nil {
				c.IastSampleRate = &f
			}
		}
	}
	return c, ""
}

// PollResult is the outcome of one poll.
type PollResult string

// The poll outcomes.
const (
	PollUpdated   PollResult = "updated"
	PollUnchanged PollResult = "unchanged"
	PollRejected  PollResult = "rejected"
	PollFailed    PollResult = "failed"
)

// ConfigClientOptions configure a ConfigClient.
type ConfigClientOptions struct {
	URL    string
	APIKey string
	App    string
	// Pinned are the pinned keys (ParsePublicKeys).
	Pinned []PinnedKey
	// AllowUnpinned is trust on first use, development only (the caller
	// already refused it in production): pin the first kid the server sends.
	AllowUnpinned bool
	CacheDir      string
	// OnConfig receives a verified config, or nil when the one in force
	// expired.
	OnConfig func(*Claims)
	// OnWarning receives why a config was refused (once per reason).
	OnWarning  func(reason string)
	HTTPClient *http.Client
	Now        func() time.Time
	Random     func() float64
	// Path and JWSType name another signed document of the same shape
	// (default /api/rasp/config and shield360-rasp+jws).
	Path    string
	JWSType string
}

type cacheFile struct {
	Config string            `json:"config"`
	Tofu   []json.RawMessage `json:"tofu,omitempty"`
}

// ConfigClient polls and verifies the signed config.
type ConfigClient struct {
	o    ConfigClientOptions
	base string

	mu      sync.Mutex
	etag    string
	tofu    []PinnedKey
	warned  map[string]bool
	current *Claims

	// applyMu serializes applying a config with Stop: once Stop returns,
	// no poll in flight applies or caches anything.
	applyMu  sync.Mutex
	stopped  bool
	stopOnce sync.Once
	stop     chan struct{}
	done     chan struct{}
}

// NewConfigClient builds a client; Start begins polling.
func NewConfigClient(o ConfigClientOptions) *ConfigClient {
	if o.Now == nil {
		o.Now = time.Now
	}
	if o.Random == nil {
		o.Random = rand.Float64
	}
	if o.HTTPClient == nil {
		o.HTTPClient = &http.Client{Timeout: fetchTimeout}
	}
	if o.Path == "" {
		o.Path = "/api/rasp/config"
	}
	if o.JWSType == "" {
		o.JWSType = JWSType
	}
	return &ConfigClient{o: o, base: strings.TrimRight(o.URL, "/"), warned: map[string]bool{}, stop: make(chan struct{}), done: make(chan struct{})}
}

// Current is the config in force, or nil.
func (c *ConfigClient) Current() *Claims {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.current
}

// trusted are the keys a config must verify against right now.
func (c *ConfigClient) trustedLocked() []PinnedKey {
	if len(c.o.Pinned) > 0 {
		return c.o.Pinned
	}
	if c.o.AllowUnpinned {
		return c.tofu
	}
	return nil
}

var unsafeFileChar = regexp.MustCompile(`[^A-Za-z0-9._-]`)

// CacheFile is where the last verified config is cached.
func (c *ConfigClient) CacheFile() string {
	name := truncChars(unsafeFileChar.ReplaceAllString(c.o.App, "_"), 128)
	if name == "" {
		name = "default"
	}
	return filepath.Join(c.o.CacheDir, name+".json")
}

func (c *ConfigClient) warn(reason string) {
	c.mu.Lock()
	seen := c.warned[reason]
	c.warned[reason] = true
	c.mu.Unlock()
	if seen || c.o.OnWarning == nil {
		return
	}
	defer func() { _ = recover() }()
	c.o.OnWarning(reason)
}

// apply makes claims the config in force and, with a token, caches it.
// A stopped client applies and caches nothing. It reports whether it applied.
func (c *ConfigClient) apply(claims *Claims, token string) bool {
	c.applyMu.Lock()
	defer c.applyMu.Unlock()
	if c.stopped {
		return false
	}
	c.mu.Lock()
	c.current = claims
	c.mu.Unlock()
	if token != "" {
		c.saveCache(token)
	}
	if c.o.OnConfig != nil {
		func() {
			defer func() { _ = recover() }() // fail open
			c.o.OnConfig(claims)
		}()
	}
	return true
}

// LoadCache loads the cached config and re-verifies it. Pinned keys are never
// read from the cache.
func (c *ConfigClient) LoadCache() (ok bool) {
	defer func() {
		if recover() != nil {
			ok = false
		}
	}()
	data, err := os.ReadFile(c.CacheFile())
	if err != nil {
		return false
	}
	var saved cacheFile
	if json.Unmarshal(data, &saved) != nil {
		return false
	}
	c.mu.Lock()
	if len(c.o.Pinned) == 0 && c.o.AllowUnpinned && len(c.tofu) == 0 {
		c.tofu = parseKeyList(saved.Tofu)
	}
	keys := c.trustedLocked()
	c.mu.Unlock()
	claims, _, reason := VerifyTypedJWS(saved.Config, keys, c.o.App, c.o.Now(), c.o.JWSType)
	if reason != "" {
		return false
	}
	return c.apply(claims, "")
}

func (c *ConfigClient) saveCache(token string) {
	defer func() { _ = recover() }() // the cache is best effort
	if err := os.MkdirAll(c.o.CacheDir, 0o700); err != nil {
		return
	}
	body := cacheFile{Config: token}
	c.mu.Lock()
	if len(c.o.Pinned) == 0 {
		for _, k := range c.tofu {
			j := map[string]string{"kty": "OKP", "crv": "Ed25519", "x": k.X}
			if k.Kid != "" {
				j["kid"] = k.Kid
			}
			raw, _ := json.Marshal(j)
			body.Tofu = append(body.Tofu, raw)
		}
	}
	c.mu.Unlock()
	data, err := json.Marshal(body)
	if err != nil {
		return
	}
	file := c.CacheFile()
	tmp := file + "." + strconv.Itoa(os.Getpid()) + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return
	}
	if err := os.Rename(tmp, file); err != nil {
		_ = os.Remove(tmp)
	}
}

// expire drops the config in force once it has expired (the platform could
// not be reached for its whole lifetime).
func (c *ConfigClient) expire() {
	c.mu.Lock()
	cur := c.current
	expired := cur != nil && cur.Exp+Skew.Seconds() <= float64(c.o.Now().UnixMilli())/1000
	if expired {
		c.etag = ""
	}
	c.mu.Unlock()
	if expired {
		c.apply(nil, "")
	}
}

// Poll fetches the config once. Never panics.
func (c *ConfigClient) Poll(ctx context.Context) PollResult {
	r := c.fetchOnce(ctx)
	c.expire()
	return r
}

func (c *ConfigClient) fetchOnce(ctx context.Context) (result PollResult) {
	defer func() {
		if recover() != nil {
			result = PollFailed
		}
	}()
	if len(c.o.Pinned) == 0 && !c.o.AllowUnpinned {
		c.warn("unpinned")
		return PollRejected
	}
	if ctx == nil {
		ctx = context.Background()
	}
	ctx, cancel := context.WithTimeout(ctx, fetchTimeout)
	defer cancel()
	q := strings.ReplaceAll(url.QueryEscape(c.o.App), "+", "%20")
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.base+c.o.Path+"?app="+q, nil)
	if err != nil {
		return PollFailed
	}
	req.Header.Set("Authorization", "Bearer "+c.o.APIKey)
	req.Header.Set("Accept", "application/json")
	c.mu.Lock()
	if c.etag != "" && c.current != nil {
		req.Header.Set("If-None-Match", c.etag)
	}
	c.mu.Unlock()
	res, err := c.o.HTTPClient.Do(req)
	if err != nil {
		return PollFailed
	}
	defer res.Body.Close()
	if res.StatusCode == http.StatusNotModified {
		return PollUnchanged
	}
	if res.StatusCode < 200 || res.StatusCode > 299 {
		return PollFailed
	}
	data, err := io.ReadAll(io.LimitReader(res.Body, maxResponse))
	if err != nil {
		return PollFailed
	}
	var decoded any
	if json.Unmarshal(bytes.TrimSpace(data), &decoded) != nil {
		return PollFailed
	}
	obj, _ := decoded.(map[string]any)
	token, _ := obj["config"].(string)
	var offeredRaw []json.RawMessage
	if keys, ok := obj["keys"].([]any); ok {
		for _, k := range keys {
			if raw, err := json.Marshal(k); err == nil {
				offeredRaw = append(offeredRaw, raw)
			}
		}
	}
	c.mu.Lock()
	if len(c.o.Pinned) == 0 && c.o.AllowUnpinned && len(c.tofu) == 0 {
		// Trust on first use (development only): pin the key the response names.
		kid := JWSKid(token)
		offered := parseKeyList(offeredRaw)
		var first *PinnedKey
		for i := range offered {
			if offered[i].Kid == kid {
				first = &offered[i]
				break
			}
		}
		if first == nil && len(offered) == 1 {
			first = &offered[0]
		}
		if first != nil {
			c.tofu = []PinnedKey{*first}
			c.mu.Unlock()
			c.warn("trust_on_first_use")
			c.mu.Lock()
		}
	}
	keys := c.trustedLocked()
	c.mu.Unlock()
	claims, _, reason := VerifyTypedJWS(token, keys, c.o.App, c.o.Now(), c.o.JWSType)
	if reason != "" {
		c.warn(reason)
		return PollRejected
	}
	c.mu.Lock()
	c.etag = res.Header.Get("ETag")
	c.mu.Unlock()
	if !c.apply(claims, token) {
		return PollRejected // stopped while the request was in flight
	}
	return PollUpdated
}

// NextDelay is the delay before the next poll after a result.
func (c *ConfigClient) NextDelay(r PollResult) time.Duration {
	if r == PollFailed || r == PollRejected {
		return Backoff
	}
	j := math.Round((c.o.Random()*2 - 1) * float64(PollJitter.Milliseconds()))
	return PollInterval + time.Duration(j)*time.Millisecond
}

// Start loads the cached config (a local file read) and polls in the
// background until Stop; the first poll runs at once, off the caller.
func (c *ConfigClient) Start() {
	c.LoadCache()
	go func() {
		defer close(c.done)
		defer func() { _ = recover() }()
		var delay time.Duration
		for {
			select {
			case <-c.stop:
				return
			case <-time.After(delay):
			}
			r := c.Poll(context.Background())
			delay = c.NextDelay(r)
		}
	}()
}

// Stop ends polling.
// Stop ends polling. Once it returns, a poll still in flight applies and
// caches nothing.
func (c *ConfigClient) Stop() {
	c.stopOnce.Do(func() { close(c.stop) })
	c.applyMu.Lock()
	c.stopped = true
	c.applyMu.Unlock()
}
