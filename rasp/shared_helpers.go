package rasp

// Small exported helpers the Defend package (sdk/go/defend) shares with
// RASP, so both read addresses, Edge's context and deception marks the same
// way.

// IPNet is an address range read by ParseIPNet.
type IPNet struct{ n ipNet }

// ParseIPNet reads a.b.c.d/n, x:y::z/n, or a bare address (all bits).
func ParseIPNet(s string) (IPNet, bool) {
	n, ok := parseCidr(s)
	return IPNet{n}, ok
}

// Contains says whether ip is inside the range.
func (n IPNet) Contains(ip string) bool { return inCidr(ip, n.n) }

// ValidIP says whether s is an IPv4 or IPv6 address as RASP reads one.
func ValidIP(s string) bool {
	_, ok := parseIPBytes(s)
	return ok
}

// VerifyEdgeContextAt verifies Edge's context header at a given time (Unix
// seconds) with the caller's own replay cache (nil: none).
func VerifyEdgeContextAt(keys []EdgeKey, value, method, path, requestID string, now int64, cache *EdgeReplayCache) *EdgeRequestContext {
	return verifyEdgeContext(keys, value, method, path, requestID, now, cache)
}

// DeceptionMarked says whether RASP deception marked this client
// suspicious (it touched a decoy this app served).
func DeceptionMarked(ip string) bool {
	if ip == "" {
		return false
	}
	return suspiciousTable().Suspicious(ip)
}
