package shield360

import (
	"net/url"
	"os"
	"strings"
)

// SHIELD: request tracing without the noise. Health probes (Kubernetes, load
// balancers, uptime checks) arrive every few seconds and say nothing about the
// app, and the SDK's own calls to Shield360 (guard reports, heartbeats, config)
// are not the app's work. Neither is traced.
// Must stay in sync with: sdk/typescript/src/instrumentation/http-noise.ts

var healthPaths = map[string]bool{
	"/health": true, "/healthz": true, "/healthcheck": true, "/ready": true, "/readyz": true,
	"/live": true, "/livez": true, "/ping": true, "/status": true, "/metrics": true, "/api/health": true,
}

var probeAgents = []string{
	"kube-probe", "elb-healthchecker", "googlehc", "consul health check", "amazon-route53-health-check-service", "uptimerobot",
}

// isHealthProbe reports whether an incoming request is a health probe: a
// probe's user agent, or a well-known health path.
func isHealthProbe(path, userAgent string) bool {
	agent := strings.ToLower(userAgent)
	for _, p := range probeAgents {
		if strings.HasPrefix(agent, p) {
			return true
		}
	}
	p := strings.TrimRight(strings.SplitN(path, "?", 2)[0], "/")
	if p == "" {
		p = "/"
	}
	return healthPaths[strings.ToLower(p)]
}

// shield360Host is the host the SDK reports to (from Config.Shield360URL or
// SHIELD360_URL), or "".
func shield360Host() string {
	raw := ""
	if cfg := GetConfig(); cfg != nil {
		raw = cfg.Shield360URL
	}
	if raw == "" {
		raw = os.Getenv("SHIELD360_URL")
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return ""
	}
	return strings.ToLower(u.Host)
}

// isOwnCall reports whether an outgoing request goes to Shield360 itself.
func isOwnCall(host, own string) bool {
	return own != "" && strings.EqualFold(host, own)
}
