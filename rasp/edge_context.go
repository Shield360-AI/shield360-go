package rasp

// SHIELD: the protection triangle (agent-guides/edge-deception-spec.md,
// "Protection triangle"). Shield360 Edge in front of the app sends a signed,
// short-lived X-Shield360-Edge-Context header; RASP verifies it and may
// tighten on it. A detection in a request that came through Edge is answered
// with a signed X-Shield360-Verdict response header so Edge blocks the client
// on its next request. Both are v1.<kid>.<base64url payload>.<base64url
// HMAC-SHA-256> with the environment's key from the signed config
// (edgeContext). A header that does not verify is ignored. Never panics.
// Port of sdk/typescript/src/rasp/edge-context.ts; passes
// sdk/rasp/testdata/triangle.json.

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"math"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	// EdgeContextHeader is the request header Edge signs.
	EdgeContextHeader = "X-Shield360-Edge-Context"
	// EdgeVerdictHeader is the response header the app signs for Edge.
	EdgeVerdictHeader = "X-Shield360-Verdict"

	edgeContextTTL = 30
	edgeSkew       = 5
	edgeMaxHeader  = 4096
)

var (
	edgeKidRe = regexp.MustCompile(`^[0-9a-f]{8}$`)
	edgeRidRe = regexp.MustCompile(`^[A-Za-z0-9_-]{8,64}$`)
	edgeCatRe = regexp.MustCompile(`^[a-z][a-z0-9_]{0,39}$`)
	edgeKeyRe = regexp.MustCompile(`^[A-Za-z0-9_-]{43}$`)
	edgeB64Re = regexp.MustCompile(`^[A-Za-z0-9_-]*$`)

	edgeClients     = map[string]bool{"human": true, "verified_crawler": true, "verified_agent": true, "automation": true, "suspected_agent": true, "unknown": true}
	edgeContextKeys = map[string]bool{"rid": true, "iat": true, "exp": true, "m": true, "ph": true, "ct": true, "risk": true, "waf": true, "trap": true, "fl": true, "tp": true, "rt": true, "sid": true, "fp": true, "dk": true, "dt": true}
	// A red team run id (rt): Edge verified the request's X-Shield360-Red-Team header.
	edgeRunRe = regexp.MustCompile(`^[a-z0-9]{8,40}$`)
	// Edge's security session (sid, the s360_sid cookie) and request fingerprint (fp).
	edgeSidRe = regexp.MustCompile(`^[A-Za-z0-9_-]{22}$`)
	edgeFpRe  = regexp.MustCompile(`^[0-9a-f]{16}$`)
	// Edge's trusted device key (dk, its id) and trust level (dt).
	edgeDkRe     = regexp.MustCompile(`^[A-Za-z0-9_-]{8,64}$`)
	edgeDtValues = map[string]bool{"software": true, "hardware": true, "attested": true}
)

// EdgeKey is one key of the signed config's edgeContext.
type EdgeKey struct {
	Kid    string
	secret []byte
}

// EdgeRequestContext is Edge's verified context for a request.
type EdgeRequestContext struct {
	Rid         string
	Iat, Exp    int64
	Method      string
	PathHash    string
	ClientType  string
	Risk, Trap  int
	Flagged     bool
	Waf         []string
	Traceparent string
	// RedTeam is the red team run Edge verified the request belongs to (its
	// X-Shield360-Red-Team header), else "".
	RedTeam string
	// Session is Edge's security session (the s360_sid cookie) and
	// Fingerprint the request fingerprint, else "" (routes without Edge's
	// security cookie).
	Session     string
	Fingerprint string
	// DeviceKey is the trusted device key Edge verified the request comes
	// from and DeviceTrust its trust level (software, hardware, attested),
	// else "" (routes without trusted devices, or no verified device).
	DeviceKey   string
	DeviceTrust string
}

// ParseEdgeKeys reads the signed config's edgeContext ({"keys": [{"kid",
// "key"}]}), at most two; anything malformed gives none.
func ParseEdgeKeys(raw json.RawMessage) []EdgeKey {
	var v struct {
		Keys []json.RawMessage `json:"keys"`
	}
	if len(raw) == 0 || json.Unmarshal(raw, &v) != nil || v.Keys == nil {
		return nil
	}
	var out []EdgeKey
	for i, k := range v.Keys {
		if i >= 2 {
			break
		}
		var e map[string]json.RawMessage
		if json.Unmarshal(k, &e) != nil || e == nil {
			return nil
		}
		var kid, key string
		if json.Unmarshal(e["kid"], &kid) != nil || json.Unmarshal(e["key"], &key) != nil || !edgeKidRe.MatchString(kid) || !edgeKeyRe.MatchString(key) {
			return nil
		}
		secret, err := base64.RawURLEncoding.DecodeString(key)
		if err != nil || len(secret) != 32 {
			return nil
		}
		out = append(out, EdgeKey{Kid: kid, secret: secret})
	}
	return out
}

// EdgePathHash is hex(SHA-256(path)[0:8]).
func EdgePathHash(path string) string {
	d := sha256.Sum256([]byte(path))
	return hex.EncodeToString(d[:8])
}

func edgeMAC(secret []byte, label, payload string) []byte {
	m := hmac.New(sha256.New, secret)
	m.Write([]byte(label))
	m.Write([]byte(payload))
	return m.Sum(nil)
}

func edgeB64(s string) ([]byte, bool) {
	if !edgeB64Re.MatchString(s) || len(s)%4 == 1 {
		return nil, false
	}
	b, err := base64.RawURLEncoding.DecodeString(s)
	return b, err == nil
}

func edgeOpen(keys []EdgeKey, label, value string, allowed map[string]bool) map[string]any {
	if value == "" || len(value) > edgeMaxHeader {
		return nil
	}
	parts := strings.Split(value, ".")
	if len(parts) != 4 || parts[0] != "v1" || !edgeKidRe.MatchString(parts[1]) {
		return nil
	}
	var secret []byte
	for _, k := range keys {
		if k.Kid == parts[1] {
			secret = k.secret
			break
		}
	}
	if secret == nil {
		return nil
	}
	sig, ok := edgeB64(parts[3])
	if !ok || !hmac.Equal(sig, edgeMAC(secret, label, parts[2])) {
		return nil
	}
	body, ok := edgeB64(parts[2])
	if !ok {
		return nil
	}
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.UseNumber()
	var obj map[string]any
	if dec.Decode(&obj) != nil || obj == nil || dec.More() {
		return nil
	}
	for k := range obj {
		if !allowed[k] {
			return nil
		}
	}
	return obj
}

func edgeInt(v any) (int64, bool) {
	n, ok := v.(json.Number)
	if !ok {
		return 0, false
	}
	f, err := strconv.ParseFloat(string(n), 64)
	if err != nil || math.IsInf(f, 0) || f != math.Trunc(f) {
		return 0, false
	}
	return int64(f), true
}

// EdgeReplayCache remembers ids until they expire; bounded.
type EdgeReplayCache struct {
	mu    sync.Mutex
	seen  map[string]int64
	order []string
	max   int
}

// NewEdgeReplayCache returns an empty cache of at most max ids (10,000 when max <= 0).
func NewEdgeReplayCache(max int) *EdgeReplayCache {
	if max <= 0 {
		max = 10000
	}
	return &EdgeReplayCache{seen: map[string]int64{}, max: max}
}

func (c *EdgeReplayCache) first(key string, exp, now int64) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if t, ok := c.seen[key]; ok && t > now {
		return false
	}
	if len(c.seen) >= c.max {
		kept := c.order[:0]
		for _, k := range c.order {
			if t, ok := c.seen[k]; ok && t > now {
				kept = append(kept, k)
			} else {
				delete(c.seen, k)
			}
		}
		c.order = kept
		for len(c.seen) >= c.max && len(c.order) > 0 {
			delete(c.seen, c.order[0])
			c.order = c.order[1:]
		}
	}
	if _, ok := c.seen[key]; !ok {
		c.order = append(c.order, key)
	}
	c.seen[key] = exp
	return true
}

var edgeReplay = NewEdgeReplayCache(0)

// VerifyEdgeContext returns the verified context for this request, or nil:
// the process replay cache and the clock. requestID is Edge's X-Request-Id
// as the app received it; it must equal the signed rid (empty: refused).
func VerifyEdgeContext(keys []EdgeKey, value, method, path, requestID string) *EdgeRequestContext {
	return verifyEdgeContext(keys, value, method, path, requestID, time.Now().Unix(), edgeReplay)
}

func verifyEdgeContext(keys []EdgeKey, value, method, path, requestID string, now int64, cache *EdgeReplayCache) (out *EdgeRequestContext) {
	defer func() {
		if recover() != nil {
			out = nil
		}
	}()
	if value == "" || len(keys) == 0 {
		return nil
	}
	c := edgeOpen(keys, "s360-ctx|v1|", value, edgeContextKeys)
	if c == nil {
		return nil
	}
	rid, _ := c["rid"].(string)
	ct, _ := c["ct"].(string)
	if !edgeRidRe.MatchString(rid) || !edgeClients[ct] {
		return nil
	}
	iat, ok1 := edgeInt(c["iat"])
	exp, ok2 := edgeInt(c["exp"])
	if !ok1 || !ok2 || iat > now+edgeSkew || exp < now-edgeSkew || exp-iat > edgeContextTTL {
		return nil
	}
	m, _ := c["m"].(string)
	ph, _ := c["ph"].(string)
	if _, isStr := c["m"].(string); !isStr || m != method || ph != EdgePathHash(path) || requestID != rid {
		return nil
	}
	risk, ok1 := edgeInt(c["risk"])
	trap, ok2 := edgeInt(c["trap"])
	if !ok1 || !ok2 || risk < 0 || risk > 100 || trap < 0 || trap > 4 {
		return nil
	}
	var waf []string
	if w, present := c["waf"]; present && w != nil {
		list, ok := w.([]any)
		if !ok || len(list) > 16 {
			return nil
		}
		waf = []string{}
		for _, x := range list {
			s, ok := x.(string)
			if !ok || !edgeCatRe.MatchString(s) {
				return nil
			}
			waf = append(waf, s)
		}
	}
	rt, _ := c["rt"].(string)
	if v, present := c["rt"]; present && (v == nil || !edgeRunRe.MatchString(rt)) {
		return nil
	}
	sid, _ := c["sid"].(string)
	if _, present := c["sid"]; present && !edgeSidRe.MatchString(sid) {
		return nil
	}
	fp, _ := c["fp"].(string)
	if _, present := c["fp"]; present && !edgeFpRe.MatchString(fp) {
		return nil
	}
	dk, _ := c["dk"].(string)
	if _, present := c["dk"]; present && !edgeDkRe.MatchString(dk) {
		return nil
	}
	dt, _ := c["dt"].(string)
	if _, present := c["dt"]; present && !edgeDtValues[dt] {
		return nil
	}
	if cache != nil && !cache.first("c:"+rid, exp+edgeSkew, now) {
		return nil
	}
	fl, _ := c["fl"].(bool)
	tp, _ := c["tp"].(string)
	return &EdgeRequestContext{Rid: rid, Iat: iat, Exp: exp, Method: m, PathHash: ph, ClientType: ct, Risk: int(risk), Trap: int(trap), Flagged: fl, Waf: waf, Traceparent: tp, RedTeam: rt, Session: sid, Fingerprint: fp, DeviceKey: dk, DeviceTrust: dt}
}

// SignEdgeVerdict returns a signed verdict for Edge with the current (first)
// key, or "".
func SignEdgeVerdict(keys []EdgeKey, rid, act, cat, src string, ttl, iat int64) string {
	if len(keys) == 0 || !edgeRidRe.MatchString(rid) || (act != "block" && act != "flag") || !edgeCatRe.MatchString(cat) ||
		(src != "rasp" && src != "sdk" && src != "defend") || ttl < 0 || ttl > 86400 {
		return ""
	}
	// rid, act, cat and src are plain [A-Za-z0-9_-]: no JSON escaping needed.
	body := `{"rid":"` + rid + `","iat":` + strconv.FormatInt(iat, 10) + `,"act":"` + act + `","cat":"` + cat + `","src":"` + src + `","ttl":` + strconv.FormatInt(ttl, 10) + `}`
	payload := base64.RawURLEncoding.EncodeToString([]byte(body))
	return "v1." + keys[0].Kid + "." + payload + "." + base64.RawURLEncoding.EncodeToString(edgeMAC(keys[0].secret, "s360-verdict|v1|", payload))
}

// EdgeSaysSuspect reports whether Edge already marked this client:
// injection-class attacks tighten from monitor to block.
func EdgeSaysSuspect(c *EdgeRequestContext) bool {
	return c != nil && c.ClientType != "verified_crawler" && c.ClientType != "verified_agent" && (c.Flagged || c.Trap >= 2 || c.Risk >= 70)
}

// edgeTighten are the attacks Edge's view of the client may tighten from
// monitor to block.
var edgeTighten = map[AttackType]bool{
	"sql_injection": true, "nosql_injection": true, "command_injection": true, "shell_spawn": true, "code_injection": true,
	"path_traversal": true, "ssrf": true, "deserialization": true, "xxe": true,
}

// SimulatedClient is the reserved test identity Edge's simulated hits use
// (TEST-NET-1): never named in a verdict (SHIELD: decoy and trap verdicts).
const SimulatedClient = "192.0.2.1"

// HitVerdict is the signed verdict a decoy or trap hit sends Edge
// (edge-deception-spec "What each layer does"), for a request Edge's
// verified context e names: "" without a context, for a verified crawler or
// agent, a red team run (rt) or the simulated client.
func HitVerdict(keys []EdgeKey, e *EdgeRequestContext, ip, act, cat, src string, ttl, iat int64) string {
	if e == nil || len(keys) == 0 || e.ClientType == "verified_crawler" || e.ClientType == "verified_agent" || e.RedTeam != "" {
		return ""
	}
	if strings.TrimPrefix(ip, "::ffff:") == SimulatedClient {
		return ""
	}
	return SignEdgeVerdict(keys, e.Rid, act, cat, src, ttl, iat)
}
