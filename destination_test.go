package shield360

import "testing"

// With no OTLP endpoint, a Shield360 URL and API key are the destination, as
// in the Python and TypeScript SDKs; an explicit endpoint or Authorization
// header always wins.
func TestResolveDestination(t *testing.T) {
	env := func(vars map[string]string) func(string) string {
		return func(name string) string { return vars[name] }
	}

	t.Run("url and key resolve to the ingest route with a bearer", func(t *testing.T) {
		c := Config{Shield360URL: "https://app.shield360.ai/", Shield360APIKey: "k-1"}
		c.resolveDestination(env(nil))
		if c.OtlpEndpoint != "https://app.shield360.ai/api/ingest/otlp" {
			t.Fatalf("endpoint = %q", c.OtlpEndpoint)
		}
		if c.OtlpHeaders["Authorization"] != "Bearer k-1" {
			t.Fatalf("headers = %v", c.OtlpHeaders)
		}
	})

	t.Run("from SHIELD360_URL and SHIELD360_API_KEY", func(t *testing.T) {
		c := Config{}
		c.resolveDestination(env(map[string]string{"SHIELD360_URL": "https://s.example", "SHIELD360_API_KEY": "k-2"}))
		if c.OtlpEndpoint != "https://s.example/api/ingest/otlp" || c.OtlpHeaders["Authorization"] != "Bearer k-2" {
			t.Fatalf("got %q %v", c.OtlpEndpoint, c.OtlpHeaders)
		}
	})

	t.Run("an explicit endpoint wins", func(t *testing.T) {
		c := Config{OtlpEndpoint: "http://collector:4318", Shield360URL: "https://s.example", Shield360APIKey: "k"}
		c.resolveDestination(env(nil))
		if c.OtlpEndpoint != "http://collector:4318" || c.OtlpHeaders != nil {
			t.Fatalf("got %q %v", c.OtlpEndpoint, c.OtlpHeaders)
		}
	})

	t.Run("OTEL_EXPORTER_OTLP_ENDPOINT wins over the URL", func(t *testing.T) {
		c := Config{Shield360URL: "https://s.example", Shield360APIKey: "k"}
		c.resolveDestination(env(map[string]string{"OTEL_EXPORTER_OTLP_ENDPOINT": "http://otel:4318"}))
		if c.OtlpEndpoint != "http://otel:4318" || c.OtlpHeaders != nil {
			t.Fatalf("got %q %v", c.OtlpEndpoint, c.OtlpHeaders)
		}
	})

	t.Run("an explicit Authorization header is kept", func(t *testing.T) {
		c := Config{Shield360URL: "https://s.example", Shield360APIKey: "k", OtlpHeaders: map[string]string{"authorization": "Basic x"}}
		c.resolveDestination(env(nil))
		if c.OtlpEndpoint != "https://s.example/api/ingest/otlp" || len(c.OtlpHeaders) != 1 || c.OtlpHeaders["authorization"] != "Basic x" {
			t.Fatalf("got %q %v", c.OtlpEndpoint, c.OtlpHeaders)
		}
	})

	t.Run("a URL without a key leaves the endpoint to the default", func(t *testing.T) {
		c := Config{Shield360URL: "https://s.example"}
		c.resolveDestination(env(nil))
		if c.OtlpEndpoint != "" {
			t.Fatalf("endpoint = %q", c.OtlpEndpoint)
		}
	})
}
