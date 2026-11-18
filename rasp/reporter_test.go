package rasp

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"runtime/debug"
	"sync"
	"testing"
	"time"
)

// The reporter: batched events through the guard events transport, folding
// of repeats, the per-minute cap, the components report.

func event(rule string) Event {
	return Event{Name: EventName, Time: "1970-01-01T00:00:00.000Z", Attrs: map[string]string{"shield360.rasp.attack": "sql_injection", "shield360.rasp.rule": rule}}
}

type post struct {
	path string
	auth string
	body struct {
		Resource map[string]string `json:"resource"`
		Events   []Event           `json:"events"`
	}
}

type reporterRig struct {
	r     *Reporter
	mu    sync.Mutex
	posts []post
	now   time.Time
}

func newReporterRig(t *testing.T, status int) *reporterRig {
	rig := &reporterRig{now: time.Unix(1_000_000, 0)}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var p post
		p.path, p.auth = r.URL.Path, r.Header.Get("Authorization")
		_ = json.NewDecoder(r.Body).Decode(&p.body)
		rig.mu.Lock()
		rig.posts = append(rig.posts, p)
		rig.mu.Unlock()
		w.WriteHeader(status)
	}))
	t.Cleanup(srv.Close)
	rig.r = NewReporter(ReporterOptions{
		URL: srv.URL + "/", APIKey: "test-api-key", ApplicationName: "orders-api", Environment: "prod", SDKVersion: "1.2.0",
		Now: func() time.Time { rig.mu.Lock(); defer rig.mu.Unlock(); return rig.now }, RetryDelay: time.Millisecond,
	})
	return rig
}

func (rig *reporterRig) advance(d time.Duration) {
	rig.mu.Lock()
	rig.now = rig.now.Add(d)
	rig.mu.Unlock()
}

func (rig *reporterRig) sent() []Event {
	rig.mu.Lock()
	defer rig.mu.Unlock()
	var out []Event
	for _, p := range rig.posts {
		out = append(out, p.body.Events...)
	}
	return out
}

func TestReporter(t *testing.T) {
	ctx := context.Background()

	t.Run("posts batches to /api/guard/events with the resource and the API key", func(t *testing.T) {
		rig := newReporterRig(t, 200)
		rig.r.Add(event("sqli.userinput"), "k1")
		rig.r.Flush(ctx, false)
		if len(rig.posts) != 1 {
			t.Fatalf("posts %d", len(rig.posts))
		}
		p := rig.posts[0]
		if p.path != "/api/guard/events" || p.auth != "Bearer test-api-key" {
			t.Errorf("post %s %s", p.path, p.auth)
		}
		res := p.body.Resource
		if res["service.name"] != "orders-api" || res["deployment.environment"] != "prod" || res["service.version"] != "1.2.0" {
			t.Errorf("resource %v", res)
		}
		if p.body.Events[0].Name != EventName {
			t.Error("event name")
		}
	})

	t.Run("folds repeats within 10 s into one more event with shield360.rasp.count", func(t *testing.T) {
		rig := newReporterRig(t, 200)
		if !rig.r.Add(event("sqli.userinput"), "same") || rig.r.Add(event("sqli.userinput"), "same") || rig.r.Add(event("sqli.userinput"), "same") {
			t.Error("fold")
		}
		if !rig.r.Add(event("sqli.stacked"), "other") {
			t.Error("other key")
		}
		rig.advance(FoldWindow)
		rig.r.Flush(ctx, false)
		sent := rig.sent()
		if len(sent) != 3 || sent[2].Attrs["shield360.rasp.count"] != "2" || sent[2].Attrs["shield360.rasp.rule"] != "sqli.userinput" {
			t.Errorf("sent %v", sent)
		}
	})

	t.Run("caps events at 100 a minute per process", func(t *testing.T) {
		rig := newReporterRig(t, 200)
		for i := 0; i < PerMinute+20; i++ {
			rig.r.Add(event("sqli.userinput"), "k"+string(rune('a'+i%26))+string(rune('a'+i/26)))
		}
		if n := len(rig.r.Pending()); n != PerMinute {
			t.Errorf("pending %d", n)
		}
		rig.advance(time.Minute)
		if !rig.r.Add(event("sqli.userinput"), "later") {
			t.Error("new window")
		}
		rig.r.Flush(ctx, false)
		// Folds that closed with repeats count against the new window too;
		// none of these keys repeated.
		if n := len(rig.sent()); n != PerMinute+1 {
			t.Errorf("sent %d", n)
		}
	})

	t.Run("Stop closes open folds and sends them", func(t *testing.T) {
		rig := newReporterRig(t, 200)
		rig.r.Start()
		rig.r.Add(event("sqli.userinput"), "k")
		rig.r.Add(event("sqli.userinput"), "k")
		rig.r.Stop(ctx)
		sent := rig.sent()
		if len(sent) != 2 || sent[0].Attrs["shield360.rasp.count"] != "" || sent[1].Attrs["shield360.rasp.count"] != "1" {
			t.Errorf("sent %v", sent)
		}
	})

	t.Run("components: names and versions only, as component records", func(t *testing.T) {
		rig := newReporterRig(t, 200)
		rig.r.ReportComponents([]Component{{Ecosystem: "go", Name: "github.com/go-chi/chi/v5", Version: "v5.2.1"}})
		rig.r.Flush(ctx, false)
		e := rig.sent()[0]
		want := map[string]string{"shield360.rasp.app": "orders-api", "shield360.rasp.component.ecosystem": "go", "shield360.rasp.component.name": "github.com/go-chi/chi/v5", "shield360.rasp.component.version": "v5.2.1"}
		if e.Name != ComponentName || len(e.Attrs) != len(want) {
			t.Fatalf("event %v", e)
		}
		for k, v := range want {
			if e.Attrs[k] != v {
				t.Errorf("%s = %q", k, e.Attrs[k])
			}
		}
	})

	t.Run("never panics when the transport fails or refuses", func(t *testing.T) {
		rig := newReporterRig(t, 401)
		rig.r.Add(event("sqli.userinput"), "k")
		rig.r.Flush(ctx, false)
		if len(rig.posts) != 1 {
			t.Errorf("a refusal is not retried: %d posts", len(rig.posts))
		}
		offline := NewReporter(ReporterOptions{URL: "http://127.0.0.1:1", APIKey: "k", ApplicationName: "a", RetryDelay: time.Millisecond})
		offline.Add(event("sqli.userinput"), "k")
		offline.Flush(ctx, false)
	})
}

func TestCollectComponents(t *testing.T) {
	bi := &debug.BuildInfo{Deps: []*debug.Module{
		{Path: "github.com/go-chi/chi/v5", Version: "v5.2.1"},
		{Path: "golang.org/x/net", Version: "v0.58.0", Replace: &debug.Module{Path: "golang.org/x/net", Version: "v0.59.0"}},
		{Path: "example.com/local", Version: "v1.0.0", Replace: &debug.Module{Path: "../local"}},
		{Path: "example.com/bad", Version: "(devel)"},
		{Path: "github.com/go-chi/chi/v5", Version: "v5.2.1"},
		nil,
	}}
	got := componentsFrom(bi, "1.26.10")
	want := []Component{
		{Ecosystem: "runtime", Name: "go", Version: "1.26.10"},
		{Ecosystem: "go", Name: "github.com/go-chi/chi/v5", Version: "v5.2.1"},
		{Ecosystem: "go", Name: "golang.org/x/net", Version: "v0.59.0"},
		{Ecosystem: "go", Name: "example.com/local", Version: "v1.0.0"},
	}
	if len(got) != len(want) {
		t.Fatalf("got %v", got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("%d: %v, want %v", i, got[i], want[i])
		}
	}
	if c := CollectComponents(); len(c) == 0 || c[0].Ecosystem != "runtime" || c[0].Name != "go" {
		t.Errorf("CollectComponents %v", c)
	}
}
