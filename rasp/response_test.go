package rasp

import (
	"bufio"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

const xssInput = `<script>alert(1)</script>`

func xssPage() string { return "<html><body>Hello " + xssInput + "</body></html>" }

// passWriter is another ResponseWriter wrapper (compression, metrics).
type passWriter struct{ http.ResponseWriter }

func serveXSS(ctx context.Context, wrap func(http.ResponseWriter, *http.Request) (http.ResponseWriter, func())) (bool, error) {
	rec := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/kit", nil).WithContext(ctx)
	w, done := wrap(rec, r)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = io.WriteString(w, xssPage())
	done()
	xssPending.Wait()
	return rec.Body.String() == xssPage() && rec.Code == http.StatusOK, nil
}

func TestResponseWriterContract(t *testing.T) {
	runSinkContract(t, sinkCase{
		name:        "rasp.WrapResponseWriter",
		attack:      XSS,
		inputs:      AddInput(nil, xssInput, "query.name"),
		neverBlocks: true,
		call: func(t *testing.T, ctx context.Context) (bool, error) {
			return serveXSS(ctx, WrapResponseWriter)
		},
		composed: map[string]sinkCall{
			"another wrapper on top": func(t *testing.T, ctx context.Context) (bool, error) {
				return serveXSS(ctx, func(w http.ResponseWriter, r *http.Request) (http.ResponseWriter, func()) {
					inner, done := WrapResponseWriter(w, r)
					return passWriter{inner}, done
				})
			},
			"another wrapper underneath": func(t *testing.T, ctx context.Context) (bool, error) {
				return serveXSS(ctx, func(w http.ResponseWriter, r *http.Request) (http.ResponseWriter, func()) {
					return WrapResponseWriter(passWriter{w}, r)
				})
			},
		},
	})
}

func TestCheckResponsesWithMiddleware(t *testing.T) {
	page := func(w http.ResponseWriter, r *http.Request) {
		// No Content-Type: net/http sniffs text/html, and so does the check.
		_, _ = io.WriteString(w, "<html><body>"+r.URL.Query().Get("name")+"</body></html>")
	}
	target := "/hello?name=" + url.QueryEscape(xssInput)

	t.Run("reported once, response unchanged, even in block mode", func(t *testing.T) {
		log := setupEngine(t, engineSettings{mode: ModeBlock})
		w := do(t, Middleware(CheckResponses(http.HandlerFunc(page))), http.MethodGet, target, "", nil)
		xssPending.Wait()
		if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), xssInput) {
			t.Fatalf("response changed: %d %q", w.Code, w.Body.String())
		}
		ev := eventsOf(log, XSS)
		if len(ev) != 1 || ev[0].Attrs["shield360.rasp.decision"] != "monitored" || ev[0].Attrs["shield360.rasp.sink"] != "http.response" {
			t.Fatalf("events %v", log.all())
		}
	})
	t.Run("not HTML, escaped, or too large: nothing", func(t *testing.T) {
		log := setupEngine(t, engineSettings{mode: ModeMonitor})
		jsonPage := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, `{"name":"`+r.URL.Query().Get("name")+`"}`)
		})
		escaped := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/html")
			_, _ = io.WriteString(w, "<p>&lt;script&gt;alert(1)&lt;/script&gt;</p>")
		})
		large := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/html")
			_, _ = io.WriteString(w, r.URL.Query().Get("name"))
			_, _ = io.WriteString(w, strings.Repeat("a", MaxXSSBody))
		})
		for _, h := range []http.Handler{jsonPage, escaped, large} {
			do(t, Middleware(CheckResponses(h)), http.MethodGet, target, "", nil)
		}
		xssPending.Wait()
		if len(log.all()) != 0 {
			t.Fatalf("events %v", log.all())
		}
	})
	t.Run("outside Middleware it is a pass-through", func(t *testing.T) {
		setupEngine(t, engineSettings{mode: ModeMonitor})
		var seen http.ResponseWriter
		h := CheckResponses(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { seen = w }))
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
		if seen != rec {
			t.Fatal("wrapped without a RASP context")
		}
	})
	t.Run("Flush, Unwrap and ResponseController reach the writer", func(t *testing.T) {
		setupEngine(t, engineSettings{mode: ModeMonitor})
		rec := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodGet, "/", nil).WithContext(requestCtx(nil, nil))
		w, done := WrapResponseWriter(rec, r)
		defer done()
		if err := http.NewResponseController(w).Flush(); err != nil || !rec.Flushed {
			t.Fatalf("flush: %v", err)
		}
		if u, ok := w.(interface{ Unwrap() http.ResponseWriter }); !ok || u.Unwrap() != rec {
			t.Fatal("Unwrap")
		}
	})
}

// fullWriter has every optional capability.
type fullWriter struct {
	*httptest.ResponseRecorder
	pushed, hijacked bool
}

func (f *fullWriter) Push(string, *http.PushOptions) error { f.pushed = true; return nil }
func (f *fullWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	f.hijacked = true
	return nil, nil, nil
}

// The wrapper has exactly the writer's Flusher, Hijacker and Pusher.
func TestResponseWriterKeepsCapabilities(t *testing.T) {
	setupEngine(t, engineSettings{mode: ModeMonitor})
	r := httptest.NewRequest(http.MethodGet, "/", nil).WithContext(requestCtx(nil, nil))
	caps := func(w http.ResponseWriter) (f, h, p bool) {
		_, f = w.(http.Flusher)
		_, h = w.(http.Hijacker)
		_, p = w.(http.Pusher)
		return
	}
	cases := []struct {
		name    string
		w       http.ResponseWriter
		f, h, p bool
	}{
		{"recorder", httptest.NewRecorder(), true, false, false},
		{"plain", passWriter{httptest.NewRecorder()}, false, false, false},
		{"full", &fullWriter{ResponseRecorder: httptest.NewRecorder()}, true, true, true},
	}
	for _, c := range cases {
		w, done := WrapResponseWriter(c.w, r)
		if w == c.w {
			t.Fatalf("%s: not wrapped", c.name)
		}
		if f, h, p := caps(w); f != c.f || h != c.h || p != c.p {
			t.Errorf("%s: flusher=%v hijacker=%v pusher=%v, want %v %v %v", c.name, f, h, p, c.f, c.h, c.p)
		}
		if !c.f {
			if err := http.NewResponseController(w).Flush(); !errors.Is(err, http.ErrNotSupported) {
				t.Errorf("%s: Flush error %v, want ErrNotSupported", c.name, err)
			}
		}
		done()
	}
	fw := &fullWriter{ResponseRecorder: httptest.NewRecorder()}
	w, done := WrapResponseWriter(fw, r)
	defer done()
	if err := w.(http.Pusher).Push("/a.css", nil); err != nil || !fw.pushed {
		t.Fatal("Push not forwarded")
	}
	if _, _, err := w.(http.Hijacker).Hijack(); err != nil || !fw.hijacked {
		t.Fatal("Hijack not forwarded")
	}
}

// The judgment runs after the response is handed off: done returns while
// the detector is still running.
func TestResponseCheckNeverDelaysTheResponse(t *testing.T) {
	log := setupEngine(t, engineSettings{mode: ModeMonitor})
	release := make(chan struct{})
	hook := func(string) { <-release }
	testHookDetect.Store(&hook)
	t.Cleanup(func() { testHookDetect.Store(nil) })

	returned := make(chan struct{})
	go func() {
		_, _ = serveXSSNoWait(requestCtx(AddInput(nil, xssInput, "query.name"), nil))
		close(returned)
	}()
	select {
	case <-returned:
	case <-time.After(5 * time.Second):
		close(release)
		t.Fatal("done waited for the detector")
	}
	if len(log.all()) != 0 {
		t.Fatal("judged before the detector finished")
	}
	close(release)
	xssPending.Wait()
	if ev := eventsOf(log, XSS); len(ev) != 1 {
		t.Fatalf("want one event after the check, got %v", log.all())
	}
}

func serveXSSNoWait(ctx context.Context) (bool, error) {
	rec := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/kit", nil).WithContext(ctx)
	w, done := WrapResponseWriter(rec, r)
	w.Header().Set("Content-Type", "text/html")
	_, _ = io.WriteString(w, xssPage())
	done()
	return rec.Body.String() == xssPage(), nil
}
