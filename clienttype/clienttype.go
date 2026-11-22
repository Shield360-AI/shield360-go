// Package clienttype says who is calling, with the reasons, deterministic
// and explainable (docs/latest/shield360/client-type.mdx). The same
// signatures as the TypeScript, Python, PHP and Rust SDKs (signatures.json,
// a byte-identical copy of sdk/client-type/signatures.json; a test says so).
//
//   - human: nothing says it is automated.
//   - verified_agent: a Shield360 agent passport or Web Bot Auth signature
//     verified, or Edge says it verified the client.
//   - unverified_automation: a script, a library, a headless browser, a
//     crawler that only claims to be one.
//   - suspected_ai_agent: a trap or LLM tripwire hit, an AI agent's own
//     name, an agent framework, or automation that roams widely.
//   - ai_attack_agent: an autonomous pentest agent: its own header, or a
//     RASP mark (sdk/rasp/README.md "AI attack agents").
//   - scanner: an attack tool's User-Agent (sqlmap, nuclei, ffuf, ...).
//
// The strongest signal wins, in that order of trust: verified, trap, the
// Edge context, then what the request itself says. Reasons are short codes
// (ua_ai_agent:claude-user), never a header value. Port of
// client-type/classify.ts.
package clienttype

import (
	_ "embed"
	"encoding/json"
	"strconv"
	"strings"
	"sync"
)

// The client types.
const (
	Human                = "human"
	VerifiedAgent        = "verified_agent"
	UnverifiedAutomation = "unverified_automation"
	SuspectedAIAgent     = "suspected_ai_agent"
	// AIAttackAgent and Scanner: README "AI attack agents" (tool-only
	// evidence stays Scanner).
	AIAttackAgent = "ai_attack_agent"
	Scanner       = "scanner"
)

// Types are the client types, in order.
var Types = []string{Human, VerifiedAgent, UnverifiedAutomation, SuspectedAIAgent, AIAttackAgent, Scanner}

// BreadthAgent is how many distinct path prefixes in a minute make
// automation an AI agent.
const BreadthAgent = 30

//go:embed signatures.json
var signaturesJSON []byte

type signature struct {
	ID    string `json:"id"`
	Match string `json:"match"`
}

type signatures struct {
	Version         string      `json:"version"`
	AIAgents        []signature `json:"aiAgents"`
	AICrawlers      []signature `json:"aiCrawlers"`
	AgentFrameworks []signature `json:"agentFrameworks"`
	Automation      []signature `json:"automation"`
	Headless        []signature `json:"headless"`
	// AttackTools match the User-Agent; AttackAgentHeaders match a header
	// name (equal, or a prefix when the match ends in "-").
	AttackTools        []signature `json:"attackTools"`
	AttackAgentHeaders []signature `json:"attackAgentHeaders"`
}

var sigs = func() signatures {
	var s signatures
	_ = json.Unmarshal(signaturesJSON, &s)
	return s
}()

// SignaturesVersion is the version of the shared signatures.
func SignaturesVersion() string { return sigs.Version }

// SignaturesJSON is the embedded signatures file, byte for byte.
func SignaturesJSON() []byte { return signaturesJSON }

func find(ua string, list []signature) *signature {
	for i := range list {
		if list[i].Match != "" && strings.Contains(ua, list[i].Match) {
			return &list[i]
		}
	}
	return nil
}

// EdgeSignal is what Edge's verified context says about the client.
type EdgeSignal struct {
	ClientType string
	Trap       int
	Flagged    bool
	Risk       int
}

// Signals are what the caller knows beyond the headers.
type Signals struct {
	VerifiedAgent bool
	TrapHit       bool
	Edge          *EdgeSignal
	// Breadth is how many distinct path prefixes this client reached in the
	// last minute (BreadthCounter); 0 when unknown.
	Breadth int
	// AttackMark is the client's RASP mark (AIAttackAgent or Scanner), when
	// it has one (README "AI attack agents").
	AttackMark string
}

// AttackFingerprint is what a request's headers say about an attack agent
// (README "AI attack agents", "Fingerprint"): an agent's own header gives
// AIAttackAgent, else an attack tool's User-Agent gives Scanner, with the
// signature id; empty kind when neither. Header names are compared
// lower-case.
func AttackFingerprint(headers map[string]string) (kind, id string) {
	if h := agentHeader(headers); h != nil {
		return AIAttackAgent, h.ID
	}
	if t := attackTool(headers); t != nil {
		return Scanner, t.ID
	}
	return "", ""
}

func agentHeader(headers map[string]string) *signature {
	for i := range sigs.AttackAgentHeaders {
		s := &sigs.AttackAgentHeaders[i]
		prefix := strings.HasSuffix(s.Match, "-")
		for name := range headers {
			n := asciiLower(name)
			if n == s.Match || (prefix && strings.HasPrefix(n, s.Match)) {
				return s
			}
		}
	}
	return nil
}

func attackTool(headers map[string]string) *signature {
	raw := ""
	for name, v := range headers {
		if asciiLower(name) == "user-agent" {
			raw = v
			break
		}
	}
	if raw == "" {
		return nil
	}
	if len(raw) > 512 {
		cut := 512
		for cut > 0 && !utf8Start(raw[cut]) {
			cut--
		}
		raw = raw[:cut]
	}
	return find(asciiLower(raw), sigs.AttackTools)
}

// Classification is a client type with its reasons and confidence (low,
// medium, high).
type Classification struct {
	ClientType string
	Reasons    []string
	Confidence string
}

func out(t string, reasons []string, confidence string) Classification {
	if reasons == nil {
		reasons = []string{}
	}
	return Classification{ClientType: t, Reasons: reasons, Confidence: confidence}
}

func hasChromeVersion(ua string) bool {
	for i := 0; ; {
		j := strings.Index(ua[i:], "chrome/")
		if j < 0 {
			return false
		}
		k := i + j + len("chrome/")
		if k < len(ua) && ua[k] >= '0' && ua[k] <= '9' {
			return true
		}
		i = i + j + 1
	}
}

// Classify works out the client type from the request's headers (names
// lower-case) and the signals.
func Classify(headers map[string]string, s Signals) Classification {
	raw := headers["user-agent"]
	if len(raw) > 512 {
		cut := 512
		for cut > 0 && !utf8Start(raw[cut]) {
			cut--
		}
		raw = raw[:cut]
	}
	ua := asciiLower(raw)
	var edge EdgeSignal
	if s.Edge != nil {
		edge = *s.Edge
	}
	ct := edge.ClientType
	if s.VerifiedAgent {
		return out(VerifiedAgent, []string{"agent_verified"}, "high")
	}
	if ct == "verified_agent" || ct == "verified_crawler" {
		return out(VerifiedAgent, []string{"edge:" + ct}, "high")
	}
	// An attack agent's own header, a RASP mark, then an attack tool's
	// User-Agent (tool-only evidence stays Scanner).
	if h := agentHeader(headers); h != nil {
		return out(AIAttackAgent, []string{"attack_agent_header:" + h.ID}, "high")
	}
	if s.AttackMark == AIAttackAgent {
		return out(AIAttackAgent, []string{"attack_mark:ai_attack_agent"}, "high")
	}
	if t := find(ua, sigs.AttackTools); t != nil && ua != "" {
		return out(Scanner, []string{"ua_attack_tool:" + t.ID}, "high")
	}
	if s.AttackMark == Scanner {
		return out(Scanner, []string{"attack_mark:scanner"}, "high")
	}
	if s.TrapHit {
		return out(SuspectedAIAgent, []string{"trap_hit"}, "high")
	}
	if edge.Trap >= 2 {
		return out(SuspectedAIAgent, []string{"edge:trap_level_" + strconv.Itoa(edge.Trap)}, "high")
	}
	var reasons []string
	if ct == "suspected_agent" {
		reasons = append(reasons, "edge:suspected_agent")
	}
	if a := find(ua, sigs.AIAgents); a != nil {
		reasons = append(reasons, "ua_ai_agent:"+a.ID)
	}
	if f := find(ua, sigs.AgentFrameworks); f != nil {
		reasons = append(reasons, "ua_agent_framework:"+f.ID)
	}
	if len(reasons) > 0 {
		conf := "medium"
		if ct == "suspected_agent" {
			conf = "high"
		}
		return out(SuspectedAIAgent, reasons, conf)
	}
	crawler := find(ua, sigs.AICrawlers)
	automation := find(ua, sigs.Automation)
	headless := find(ua, sigs.Headless)
	if crawler != nil {
		reasons = append(reasons, "ua_ai_crawler:"+crawler.ID)
	}
	if automation != nil {
		reasons = append(reasons, "ua_automation:"+automation.ID)
	}
	if headless != nil {
		reasons = append(reasons, "headless:"+headless.ID)
	}
	if ua == "" {
		reasons = append(reasons, "no_user_agent")
	}
	if hasChromeVersion(ua) && headless == nil && headers["sec-ch-ua"] == "" && headers["sec-fetch-mode"] == "" && headers["accept-language"] == "" {
		reasons = append(reasons, "browser_headers_missing")
	}
	if ct == "automation" {
		reasons = append(reasons, "edge:automation")
	}
	if len(reasons) > 0 {
		if s.Breadth >= BreadthAgent {
			return out(SuspectedAIAgent, append(reasons, "breadth"), "medium")
		}
		if crawler != nil || automation != nil || headless != nil {
			return out(UnverifiedAutomation, reasons, "high")
		}
		return out(UnverifiedAutomation, reasons, "medium")
	}
	if edge.Flagged {
		return out(UnverifiedAutomation, []string{"edge:flagged"}, "medium")
	}
	if edge.Risk >= 70 {
		return out(UnverifiedAutomation, []string{"edge:risk"}, "medium")
	}
	return out(Human, nil, "low")
}

func utf8Start(b byte) bool { return b&0xC0 != 0x80 }

func asciiLower(s string) string {
	b := []byte(s)
	for i, c := range b {
		if c >= 'A' && c <= 'Z' {
			b[i] = c + 32
		}
	}
	return string(b)
}

// BreadthCounter counts how many distinct path prefixes (the first three
// segments) each client reaches in a window; the oldest client is dropped
// past the cap.
type BreadthCounter struct {
	window int64
	cap    int
	mu     sync.Mutex
	seen   map[string]*breadth
	order  []string
}

type breadth struct {
	since int64
	keys  map[string]bool
}

// NewBreadthCounter makes a counter (window in milliseconds; 0: 60 s; cap
// 0: 10 000 clients).
func NewBreadthCounter(windowMs int64, cap int) *BreadthCounter {
	if windowMs <= 0 {
		windowMs = 60_000
	}
	if cap <= 0 {
		cap = 10_000
	}
	return &BreadthCounter{window: windowMs, cap: cap, seen: map[string]*breadth{}}
}

// See records a request and returns how many distinct prefixes the client
// reached in its window.
func (b *BreadthCounter) See(client, path string, nowMs int64) int {
	parts := strings.Split(path, "/")
	if len(parts) > 4 {
		parts = parts[:4]
	}
	key := strings.Join(parts, "/")
	b.mu.Lock()
	defer b.mu.Unlock()
	e, ok := b.seen[client]
	if !ok || nowMs-e.since > b.window {
		if !ok {
			for len(b.seen) >= b.cap && len(b.order) > 0 {
				old := b.order[0]
				b.order = b.order[1:]
				if _, had := b.seen[old]; had {
					delete(b.seen, old)
					break
				}
			}
		} else {
			for i, k := range b.order {
				if k == client {
					b.order = append(b.order[:i], b.order[i+1:]...)
					break
				}
			}
		}
		b.order = append(b.order, client)
		e = &breadth{since: nowMs, keys: map[string]bool{}}
		b.seen[client] = e
	}
	if len(e.keys) < 64 {
		e.keys[key] = true
	}
	return len(e.keys)
}
