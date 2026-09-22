package shield360

import (
	"net/url"
	"strings"
)

// signalEndpointURL turns the configured OTLP base endpoint into the URL for
// one signal ("traces", "metrics", "logs").
//
// The exporters' WithEndpointURL uses any path it is given verbatim, so a base
// endpoint with a path — an OTLP route behind a gateway such as
// https://app.example.com/api/collector/device/otlp — would send every signal
// to the same URL. Following the OpenTelemetry convention for a
// non-signal-specific endpoint, the signal path is appended to the base path.
//
//   - no path or "/"          → unchanged; the exporter adds /v1/<signal>
//   - ends in /v1/<signal>    → the signal path is swapped for this signal
//   - any other path          → /v1/<signal> is appended
func signalEndpointURL(endpoint, signal string) string {
	u, err := url.Parse(endpoint)
	if err != nil || u.Host == "" {
		return endpoint
	}
	path := strings.TrimRight(u.Path, "/")
	if path == "" {
		return endpoint
	}
	for _, s := range []string{"traces", "metrics", "logs"} {
		if suffix := "/v1/" + s; strings.HasSuffix(path, suffix) {
			path = strings.TrimSuffix(path, suffix)
			break
		}
	}
	u.Path = path + "/v1/" + signal
	return u.String()
}
