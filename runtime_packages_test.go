package shield360

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/ThinkfleetAI/shield360-go/rasp"
)

// Mirrors sdk/typescript/src/__tests__/runtime-packages.test.ts.

type sentBatch struct {
	Auth string
	Body struct {
		Resource map[string]string `json:"resource"`
		Events   []rasp.Event      `json:"events"`
	}
}

func pkgRecorder(t *testing.T, status int) (*httptest.Server, func() []sentBatch) {
	t.Helper()
	var mu sync.Mutex
	var got []sentBatch
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var b sentBatch
		b.Auth = r.Header.Get("Authorization")
		if r.URL.Path != "/api/guard/events" {
			t.Errorf("path %q", r.URL.Path)
		}
		_ = json.NewDecoder(r.Body).Decode(&b.Body)
		mu.Lock()
		got = append(got, b)
		mu.Unlock()
		w.WriteHeader(status)
	}))
	t.Cleanup(srv.Close)
	return srv, func() []sentBatch {
		mu.Lock()
		defer mu.Unlock()
		return append([]sentBatch(nil), got...)
	}
}

func onePackage() []rasp.Component {
	return []rasp.Component{{Ecosystem: "go", Name: "github.com/go-chi/chi/v5", Version: "v5.2.1"}}
}

func TestRuntimePackagesEnabled(t *testing.T) {
	env := func(v string) func(string) string { return func(string) string { return v } }
	if !RuntimePackagesEnabled(false, env("")) || !RuntimePackagesEnabled(false, env("on")) {
		t.Fatal("on by default")
	}
	if RuntimePackagesEnabled(true, env("")) {
		t.Fatal("Disabled wins")
	}
	for _, v := range []string{"off", "false", "0", "NO"} {
		if RuntimePackagesEnabled(false, env(v)) {
			t.Fatalf("%q should turn it off", v)
		}
	}
}

func TestReportRuntimePackagesSendsNamesAndVersions(t *testing.T) {
	srv, got := pkgRecorder(t, 200)
	ok := ReportRuntimePackages(context.Background(), RuntimePackagesOptions{
		URL: srv.URL + "/", APIKey: "test-key", ApplicationName: "orders-api", Environment: "prod", SDKVersion: "1.0.0", Collect: onePackage,
	})
	if !ok {
		t.Fatal("not delivered")
	}
	b := got()
	if len(b) != 1 || b[0].Auth != "Bearer test-key" {
		t.Fatalf("batches %+v", b)
	}
	if b[0].Body.Resource["service.name"] != "orders-api" || b[0].Body.Resource["deployment.environment"] != "prod" {
		t.Fatalf("resource %+v", b[0].Body.Resource)
	}
	e := b[0].Body.Events[0]
	want := map[string]string{
		"shield360.rasp.app":                 "orders-api",
		"shield360.rasp.component.ecosystem": "go",
		"shield360.rasp.component.name":      "github.com/go-chi/chi/v5",
		"shield360.rasp.component.version":   "v5.2.1",
	}
	if e.Name != "shield360.rasp.component" || len(e.Attrs) != len(want) {
		t.Fatalf("event %+v", e)
	}
	for k, v := range want {
		if e.Attrs[k] != v {
			t.Fatalf("%s = %q", k, e.Attrs[k])
		}
	}
}

func TestReportRuntimePackagesBatchesAndCaps(t *testing.T) {
	srv, got := pkgRecorder(t, 200)
	many := make([]rasp.Component, 700)
	for i := range many {
		many[i] = rasp.Component{Ecosystem: "go", Name: "example.com/m", Version: "v1.0." + string(rune('0'+i%10))}
	}
	ReportRuntimePackages(context.Background(), RuntimePackagesOptions{URL: srv.URL, APIKey: "k", ApplicationName: "a", Collect: func() []rasp.Component { return many }})
	var sizes []int
	for _, b := range got() {
		sizes = append(sizes, len(b.Body.Events))
	}
	if len(sizes) != 5 || sizes[0] != 100 || sizes[4] != 100 {
		t.Fatalf("sizes %v", sizes)
	}
}

func TestReportRuntimePackagesStopsAtRefusal(t *testing.T) {
	srv, got := pkgRecorder(t, 401)
	many := make([]rasp.Component, 250)
	for i := range many {
		many[i] = rasp.Component{Ecosystem: "go", Name: "example.com/m", Version: "v1.0.0"}
	}
	if ReportRuntimePackages(context.Background(), RuntimePackagesOptions{URL: srv.URL, APIKey: "k", ApplicationName: "a", Collect: func() []rasp.Component { return many }, RetryDelay: time.Millisecond}) {
		t.Fatal("refused report reported as delivered")
	}
	if len(got()) != 1 {
		t.Fatalf("kept sending after a refusal: %d", len(got()))
	}
	if ReportRuntimePackages(context.Background(), RuntimePackagesOptions{APIKey: "k", Collect: onePackage}) {
		t.Fatal("sent without a URL")
	}
	if ReportRuntimePackages(context.Background(), RuntimePackagesOptions{URL: srv.URL, APIKey: "k", Collect: func() []rasp.Component { panic("boom") }}) {
		t.Fatal("a panic must not count as delivered")
	}
}

func TestStartRuntimePackagesOncePerProcess(t *testing.T) {
	srv, got := pkgRecorder(t, 200)
	o := RuntimePackagesOptions{URL: srv.URL, APIKey: "k", ApplicationName: "a", Collect: onePackage, StartDelay: 10 * time.Millisecond, Every: time.Hour, Getenv: func(string) string { return "" }}
	if !StartRuntimePackages(o) {
		t.Fatal("did not start")
	}
	defer StopRuntimePackages()
	if StartRuntimePackages(o) {
		t.Fatal("started twice")
	}
	if !RuntimePackagesActive() {
		t.Fatal("not active")
	}
	deadline := time.Now().Add(5 * time.Second)
	for len(got()) == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if len(got()) != 1 {
		t.Fatalf("reports %d", len(got()))
	}
	StopRuntimePackages()
	if RuntimePackagesActive() {
		t.Fatal("still active")
	}
}

func TestStartRuntimePackagesOff(t *testing.T) {
	if StartRuntimePackages(RuntimePackagesOptions{URL: "https://s.example", APIKey: "k", Disabled: true}) {
		t.Fatal("Disabled started it")
	}
	if StartRuntimePackages(RuntimePackagesOptions{URL: "https://s.example", APIKey: "k", Getenv: func(string) string { return "off" }}) {
		t.Fatal("env off started it")
	}
	if StartRuntimePackages(RuntimePackagesOptions{APIKey: "k"}) {
		t.Fatal("started without a URL")
	}
}
