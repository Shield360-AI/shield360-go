package shield360

import "testing"

func TestSignalEndpointURL(t *testing.T) {
	cases := []struct {
		endpoint, signal, want string
	}{
		// Bare collector endpoints keep the exporter's own default path.
		{"http://127.0.0.1:4318", "traces", "http://127.0.0.1:4318"},
		{"http://127.0.0.1:4318/", "metrics", "http://127.0.0.1:4318/"},
		// A gateway route gets the signal appended, per signal.
		{"https://app.example.com/api/collector/device/otlp", "traces", "https://app.example.com/api/collector/device/otlp/v1/traces"},
		{"https://app.example.com/api/collector/device/otlp/", "metrics", "https://app.example.com/api/collector/device/otlp/v1/metrics"},
		// An explicit signal URL is honoured and re-pointed for other signals.
		{"https://otel.example.com/v1/traces", "traces", "https://otel.example.com/v1/traces"},
		{"https://otel.example.com/v1/traces", "metrics", "https://otel.example.com/v1/metrics"},
		// Unparseable input is left for the exporter to report.
		{"not a url", "traces", "not a url"},
	}
	for _, c := range cases {
		if got := signalEndpointURL(c.endpoint, c.signal); got != c.want {
			t.Errorf("signalEndpointURL(%q, %q) = %q, want %q", c.endpoint, c.signal, got, c.want)
		}
	}
}
