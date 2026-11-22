// Package crumb is Shield360's one crumb generator: stateless deception
// tokens (fake paths, credentials, headers, LLM tripwires, decoy files)
// derived from HMAC(environment secret, epoch, owner fingerprint) and
// verifiable on a hit with no storage. Edge (cli/internal/edge/honeypot) and
// the host agent (cli/internal/hostagent/honeypot) both mint and check with
// it, so a crumb planted by one is recognized by the other as the same
// trail. The format is the shared specification in
// agent-guides/edge-deception-spec.md; any change here changes it there.
package crumb

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base32"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"net/netip"
	"strings"
	"time"
)

// Crumb kinds (byte 5 of a token).
const (
	KindPath       = 'p'
	KindCredential = 'c'
	KindHeader     = 'h'
	KindTripwire   = 't'
	KindNetwork    = 'n'
	KindDocument   = 'd'
)

// Crumb states.
const (
	StateFresh  = "fresh"
	StateGrace  = "grace"
	StateBurned = "burned"
)

const (
	tokenVersion = 1
	tokenBytes   = 20
	// TokenLen is the length of a token's text form.
	TokenLen      = 32
	DefaultEpoch  = 24 * time.Hour
	MinEpoch      = time.Hour
	MaxEpoch      = 7 * 24 * time.Hour
	DefaultGrace  = 1
	MaxGrace      = 3
	SecretBytes   = 32
	maxUserAgent  = 256
	maxCandidates = 8
)

var b32 = base32.StdEncoding.WithPadding(base32.NoPadding)

// FP is a client fingerprint: SHA-256("s360-fp|v1|" + ip + "|" + ua)[0:6].
type FP [6]byte

// Hex is the fingerprint as reported (crumb.owner).
func (f FP) Hex() string { return hex.EncodeToString(f[:]) }

// HostFingerprint is the owner of the crumbs a host agent plants (decoy
// files): SHA-256("s360-fp|v1|host|" + host id)[0:6], where the host id is
// its collector id. "host" is never an address, so it cannot collide with a
// client's fingerprint input.
func HostFingerprint(hostID string) FP {
	sum := sha256.Sum256([]byte("s360-fp|v1|host|" + hostID))
	var f FP
	copy(f[:], sum[:6])
	return f
}

// ParseFP reads a fingerprint's hex form (12 lower-case hex characters).
func ParseFP(s string) (FP, bool) {
	var f FP
	if len(s) != 12 {
		return f, false
	}
	raw, err := hex.DecodeString(s)
	if err != nil || hex.EncodeToString(raw) != s {
		return f, false
	}
	copy(f[:], raw)
	return f, true
}

// Fingerprint is a client's fingerprint (ua "" for network decoys).
func Fingerprint(ip netip.Addr, ua string) FP {
	ua = strings.ToLower(ua)
	if len(ua) > maxUserAgent {
		ua = ua[:maxUserAgent]
	}
	sum := sha256.Sum256([]byte("s360-fp|v1|" + ip.Unmap().String() + "|" + ua))
	var f FP
	copy(f[:], sum[:6])
	return f
}

// Crumbs mints and verifies tokens for one secret. The zero epoch and grace
// are the spec's defaults.
type Crumbs struct {
	secret []byte
	epoch  time.Duration
	grace  int
	now    func() time.Time
}

// NewCrumbs builds a minter. The secret must be 32 bytes.
func NewCrumbs(secret []byte, epoch time.Duration, grace int, now func() time.Time) (*Crumbs, error) {
	if len(secret) != SecretBytes {
		return nil, errors.New("the honeypot secret must be 32 bytes")
	}
	if epoch == 0 {
		epoch = DefaultEpoch
	}
	if epoch < MinEpoch || epoch > MaxEpoch {
		return nil, errors.New("the honeypot epoch must be between 1h and 7 days")
	}
	if grace < 0 || grace > MaxGrace {
		return nil, errors.New("the honeypot grace must be 0 to 3 epochs")
	}
	if now == nil {
		now = time.Now
	}
	return &Crumbs{secret: append([]byte(nil), secret...), epoch: epoch, grace: grace, now: now}, nil
}

// Epoch is the current epoch number.
func (c *Crumbs) Epoch() uint32 { return uint32(c.now().Unix() / int64(c.epoch/time.Second)) }

// Token mints the crumb of a kind for a client, in the current epoch.
func (c *Crumbs) Token(kind byte, fp FP) string { return c.TokenAt(c.Epoch(), kind, fp) }

// TokenAt mints the crumb of a kind for a client in a given epoch.
func (c *Crumbs) TokenAt(epoch uint32, kind byte, fp FP) string {
	var b [tokenBytes]byte
	b[0] = tokenVersion
	binary.BigEndian.PutUint32(b[1:5], epoch)
	b[5] = kind
	copy(b[6:12], fp[:])
	copy(b[12:], c.mac(b[:12]))
	return strings.ToLower(b32.EncodeToString(b[:]))
}

func (c *Crumbs) mac(head []byte) []byte {
	m := hmac.New(sha256.New, c.secret)
	m.Write([]byte("s360-crumb|"))
	m.Write(head)
	return m.Sum(nil)[:8]
}

// Crumb is a verified token.
type Crumb struct {
	Kind  byte
	Epoch uint32
	Owner FP
	State string
}

// Verify checks a token. ok is false for anything that is not a crumb of
// this secret (or is from more than one epoch ahead).
func (c *Crumbs) Verify(tok string) (Crumb, bool) {
	if len(tok) != TokenLen || !isB32(tok) {
		return Crumb{}, false
	}
	raw, err := b32.DecodeString(strings.ToUpper(tok))
	if err != nil || len(raw) != tokenBytes || raw[0] != tokenVersion {
		return Crumb{}, false
	}
	if subtle.ConstantTimeCompare(raw[12:], c.mac(raw[:12])) != 1 {
		return Crumb{}, false
	}
	cr := Crumb{Kind: raw[5], Epoch: binary.BigEndian.Uint32(raw[1:5])}
	copy(cr.Owner[:], raw[6:12])
	now := c.Epoch()
	switch {
	case cr.Epoch > now+1:
		return Crumb{}, false
	case cr.Epoch >= now:
		cr.State = StateFresh
	case now-cr.Epoch <= uint32(c.grace):
		cr.State = StateGrace
	default:
		cr.State = StateBurned
	}
	return cr, true
}

func isB32(s string) bool {
	for i := 0; i < len(s); i++ {
		ch := s[i]
		if !(ch >= 'a' && ch <= 'z' || ch >= '2' && ch <= '7') {
			return false
		}
	}
	return true
}

// Find verifies every candidate in s (lower-cased first): the crumbs of
// this secret it carries, at most 8.
func (c *Crumbs) Find(s string) []Crumb {
	var out []Crumb
	for _, tok := range Candidates(strings.ToLower(s)) {
		if cr, ok := c.Verify(tok); ok {
			out = append(out, cr)
		}
	}
	return out
}

// KindName is a kind's reported name.
func KindName(k byte) string {
	switch k {
	case KindPath:
		return "path"
	case KindCredential:
		return "credential"
	case KindHeader:
		return "header"
	case KindTripwire:
		return "tripwire"
	case KindNetwork:
		return "network"
	case KindDocument:
		return "document"
	}
	return "unknown"
}

// Candidates are the runs of exactly 32 base32 characters in s, at most 8:
// what a token could be. Cheap enough for every request.
func Candidates(s string) []string {
	var out []string
	run := 0
	for i := 0; i <= len(s); i++ {
		in := i < len(s) && (s[i] >= 'a' && s[i] <= 'z' || s[i] >= '2' && s[i] <= '7')
		if in {
			run++
			continue
		}
		if run == TokenLen {
			out = append(out, s[i-TokenLen:i])
			if len(out) == maxCandidates {
				return out
			}
		}
		run = 0
	}
	return out
}
