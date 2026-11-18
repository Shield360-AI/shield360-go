package shield360

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"go.opentelemetry.io/otel"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
)

// SHIELD: requests are traces by route, health probes and calls to Shield360
// left out (mirrors sdk/typescript/src/instrumentation/__tests__/http-noise.test.ts).

func TestIsHealthProbe(t *testing.T) {
	cases := []struct {
		path, agent string
		probe       bool
	}{
		{"/healthz", "", true},
		{"/health/", "", true},
		{"/api/health", "", true},
		{"/readyz?deep=1", "", true},
		{"/anything", "kube-probe/1.31", true},
		{"/", "ELB-HealthChecker/2.0", true},
		{"/api/orders", "Mozilla/5.0", false},
		{"/healthy-recipes", "", false},
		{"", "", false},
	}
	for _, c := range cases {
		if got := isHealthProbe(c.path, c.agent); got != c.probe {
			t.Errorf("isHealthProbe(%q, %q) = %v, want %v", c.path, c.agent, got, c.probe)
		}
	}
	if !isOwnCall("APP.shield360.ai", "app.shield360.ai") || isOwnCall("api.openai.com", "app.shield360.ai") || isOwnCall("x", "") {
		t.Error("isOwnCall")
	}
}

func recorder(t *testing.T) *tracetest.SpanRecorder {
	t.Helper()
	rec := tracetest.NewSpanRecorder()
	prev := otel.GetTracerProvider()
	otel.SetTracerProvider(sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(rec)))
	t.Cleanup(func() { otel.SetTracerProvider(prev) })
	return rec
}

func TestHandlerNamesRequestsByRouteAndSkipsProbes(t *testing.T) {
	rec := recorder(t)
	mux := http.NewServeMux()
	mux.HandleFunc("GET /orders/{id}", func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, r.PathValue("id")) })
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "ok") })
	srv := httptest.NewServer(Handler(mux, "orders-api"))
	defer srv.Close()

	for _, p := range []string{"/orders/42", "/healthz"} {
		res, err := http.Get(srv.URL + p)
		if err != nil {
			t.Fatal(err)
		}
		_ = res.Body.Close()
	}

	var names []string
	for _, s := range rec.Ended() {
		names = append(names, s.Name())
	}
	if len(names) != 1 || names[0] != "GET /orders/{id}" {
		t.Fatalf("server spans = %v, want only GET /orders/{id}", names)
	}
	route := ""
	for _, a := range rec.Ended()[0].Attributes() {
		if a.Key == "http.route" {
			route = a.Value.AsString()
		}
	}
	if route != "/orders/{id}" {
		t.Errorf("http.route = %q", route)
	}
}

func TestTransportSkipsCallsToShield360(t *testing.T) {
	rec := recorder(t)
	own := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {}))
	defer own.Close()
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {}))
	defer other.Close()
	t.Setenv("SHIELD360_URL", own.URL)

	client := HTTPClient()
	for _, u := range []string{own.URL + "/api/guard/events", other.URL + "/v1/messages"} {
		res, err := client.Get(u)
		if err != nil {
			t.Fatal(err)
		}
		_ = res.Body.Close()
	}
	spans := rec.Ended()
	if len(spans) != 1 {
		t.Fatalf("client spans = %d, want 1 (the call to Shield360 is not traced)", len(spans))
	}
}

func TestRouteNames(t *testing.T) {
	if got := routeName("GET", "/orders/{id}"); got != "GET /orders/{id}" {
		t.Error(got)
	}
	if got := routeName("POST", "POST /orders"); got != "POST /orders" {
		t.Error(got)
	}
	if got := patternPath("GET example.com/a/{b}"); got != "/a/{b}" {
		t.Error(got)
	}
}

// A driver that answers every query, to see what OpenDB records.
type fakeDriver struct{}
type fakeConn struct{}
type fakeStmt struct{}
type fakeRows struct{ done bool }

func (fakeDriver) Open(string) (driver.Conn, error)  { return fakeConn{}, nil }
func (fakeConn) Prepare(string) (driver.Stmt, error) { return nil, driver.ErrSkip }
func (fakeConn) Close() error                        { return nil }
func (fakeConn) Begin() (driver.Tx, error)           { return nil, driver.ErrSkip }
func (*fakeRows) Columns() []string                  { return []string{"v"} }
func (*fakeRows) Close() error                       { return nil }
func (r *fakeRows) Next(dest []driver.Value) error {
	if r.done {
		return io.EOF
	}
	r.done = true
	dest[0] = "x"
	return nil
}

func TestOpenDBRecordsStatementsWithoutArguments(t *testing.T) {
	rec := recorder(t)
	sql.Register("shield360-fake", fakeDriver{})
	db, err := OpenDB("shield360-fake", "")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var v string
	if err := db.QueryRow("SELECT v FROM orders WHERE email = ?", "ada@example.com").Scan(&v); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, s := range rec.Ended() {
		for _, a := range s.Attributes() {
			if strings.Contains(a.Value.Emit(), "ada@example.com") {
				t.Fatalf("argument recorded in %s: %s", s.Name(), a.Key)
			}
			if strings.Contains(a.Value.Emit(), "SELECT v FROM orders") {
				found = true
			}
		}
	}
	if !found {
		t.Fatal("statement not recorded")
	}
}

func (fakeConn) QueryContext(context.Context, string, []driver.NamedValue) (driver.Rows, error) {
	return &fakeRows{}, nil
}
