package shield360

import (
	"database/sql"
	"net/http"

	"github.com/Shield360-AI/shield360-go/rasp"
	"github.com/XSAM/otelsql"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
	semconv "go.opentelemetry.io/otel/semconv/v1.26.0"
	"go.opentelemetry.io/otel/trace"
)

// SHIELD: request tracing for Go apps. Go has no zero-code start (that is the
// eBPF path on the host), so these are one-line wraps on top of the standard
// OpenTelemetry instrumentations:
//
//	http.ListenAndServe(":8080", shield360.Handler(mux, "orders-api"))
//	client := shield360.HTTPClient()
//	db, err := shield360.OpenDB("postgres", dsn)
//
// Each incoming request is a trace named by its route (Go 1.22 ServeMux
// patterns, "GET /orders/{id}"), with health probes left out; outgoing calls
// and SQL statements appear inside it, calls to Shield360 left out, SQL
// recorded without its arguments. Call Init first so the spans are exported.

// Handler traces each request h serves. operation names requests no route
// matched.
func Handler(h http.Handler, operation string) http.Handler {
	routed := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// SHIELD: request correlation — an incoming request's X-Request-Id on
		// its server span (rasp/edge_request.go).
		rasp.TagServerSpan(trace.SpanFromContext(r.Context()), rasp.RequestIDOf(r.Header.Get(rasp.RequestIDHeader)))
		h.ServeHTTP(w, r)
		// A ServeMux sets the matched pattern while routing; otelhttp renames the
		// span from it (spanName below) and this records the route.
		if r.Pattern != "" {
			trace.SpanFromContext(r.Context()).SetAttributes(semconv.HTTPRoute(patternPath(r.Pattern)))
		}
	})
	return otelhttp.NewHandler(routed, operation,
		otelhttp.WithFilter(func(r *http.Request) bool { return !isHealthProbe(r.URL.Path, r.UserAgent()) }),
		otelhttp.WithSpanNameFormatter(spanName),
	)
}

// Transport traces each request base sends (http.DefaultTransport when nil),
// except calls to Shield360.
func Transport(base http.RoundTripper) http.RoundTripper {
	if base == nil {
		base = http.DefaultTransport
	}
	return otelhttp.NewTransport(base,
		otelhttp.WithFilter(func(r *http.Request) bool { return !isOwnCall(r.URL.Host, shield360Host()) }),
	)
}

// HTTPClient is an http.Client whose requests are traced.
func HTTPClient() *http.Client {
	return &http.Client{Transport: Transport(nil)}
}

// OpenDB opens a database whose queries are traced (statement text, never the
// arguments), as sql.Open would.
func OpenDB(driverName, dataSourceName string) (*sql.DB, error) {
	return otelsql.Open(driverName, dataSourceName, otelsql.WithSpanOptions(otelsql.SpanOptions{
		DisableErrSkip:  true,
		OmitConnPrepare: true,
		OmitRows:        true,
	}))
}

// spanName is the route once a ServeMux matched one, else the method and operation.
func spanName(operation string, r *http.Request) string {
	if r.Pattern != "" {
		return routeName(r.Method, r.Pattern)
	}
	return r.Method + " " + operation
}

// routeName is "GET /orders/{id}" for a pattern with or without its method.
func routeName(method, pattern string) string {
	if _, _, ok := splitMethod(pattern); ok {
		return pattern
	}
	return method + " " + pattern
}

// patternPath is the path part of a ServeMux pattern ("GET example.com/a/{b}" → "/a/{b}").
func patternPath(pattern string) string {
	_, rest, ok := splitMethod(pattern)
	if !ok {
		rest = pattern
	}
	for i := 0; i < len(rest); i++ {
		if rest[i] == '/' {
			return rest[i:]
		}
	}
	return rest
}

func splitMethod(pattern string) (string, string, bool) {
	for i := 0; i < len(pattern); i++ {
		if pattern[i] == ' ' {
			return pattern[:i], pattern[i+1:], i > 0
		}
		if pattern[i] == '/' {
			break
		}
	}
	return "", pattern, false
}
