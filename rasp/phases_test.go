package rasp

import (
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
)

// When request rules run (sdk/rasp/README.md "Custom rules" -> "When rules
// run"): the head phase sees only the inputs known before the body, findings
// raised while the request is captured are judged with that request
// current, and a request with no body or an empty one has a known, empty
// body, so the body phase still runs.

func TestRulePhases(t *testing.T) {
	t.Run("head rules see only the inputs known before the body", func(t *testing.T) {
		log := setupEngine(t, engineSettings{})
		// A rule that reads input.* but not request.body runs at head; it must
		// not see the buffered body there, only at body (after "path").
		customRemote(t, nil,
			rule(map[string]any{"id": "body-input", "expression": `input.key.startsWith("body.")`}),
			rule(map[string]any{"id": "query-input", "expression": `input.key == "query.a"`}),
			rule(map[string]any{"id": "path", "expression": `request.path == "/p"`}),
		)
		r := httptest.NewRequest(http.MethodPost, "/p?a=1", strings.NewReader(`{"q":"v"}`))
		r.Header.Set("Content-Type", "application/json")
		if _, ran := serve(r, nil); !ran {
			t.Fatal("blocked")
		}
		if got := ruleEvents(log); !reflect.DeepEqual(got, []string{"custom.query-input", "custom.path", "custom.body-input"}) {
			t.Errorf("order %v", got)
		}
	})

	t.Run("upload file names join only at body", func(t *testing.T) {
		log := setupEngine(t, engineSettings{})
		customRemote(t, nil,
			rule(map[string]any{"id": "upload-name", "expression": `input.key == "body.attachment.filename"`}),
			rule(map[string]any{"id": "path", "expression": `request.path == "/upload"`}),
		)
		body, ct := multipartBody(part{"attachment", "report.pdf", "fixture"})
		r := httptest.NewRequest(http.MethodPost, "/upload", strings.NewReader(body))
		r.Header.Set("Content-Type", ct)
		if _, ran := serve(r, nil); !ran {
			t.Fatal("blocked")
		}
		if got := ruleEvents(log); !reflect.DeepEqual(got, []string{"custom.path", "custom.upload-name"}) {
			t.Errorf("order %v", got)
		}
	})

	t.Run("RecordRequestBody on a captured context judges the head before the body", func(t *testing.T) {
		log := setupEngine(t, engineSettings{})
		customRemote(t, nil,
			rule(map[string]any{"id": "body-input", "expression": `input.key.startsWith("body.")`}),
			rule(map[string]any{"id": "path", "expression": `request.path == "/p"`}),
		)
		c := CaptureRequest(httptest.NewRequest(http.MethodPost, "/p", nil), nil, Framework)
		if err := RecordRequestBody(NewContextWith(t.Context(), c), map[string]any{"q": "v"}, "application/json"); err != nil {
			t.Fatal(err)
		}
		if got := ruleEvents(log); !reflect.DeepEqual(got, []string{"custom.path", "custom.body-input"}) {
			t.Errorf("order %v", got)
		}
	})

	t.Run("body-phase input rules still see the body inputs given to RecordRequestBody", func(t *testing.T) {
		log := setupEngine(t, engineSettings{})
		customRemote(t, nil, rule(map[string]any{"id": "role", "expression": `input.key == "body.role" && input.value == "admin"`}))
		// GET with a body: Middleware does not read it, so it stays unknown
		// until the app records it.
		r := httptest.NewRequest(http.MethodGet, "/p", strings.NewReader(`{"role":"admin"}`))
		serve(r, func(w http.ResponseWriter, r *http.Request) {
			if len(log.all()) != 0 {
				t.Errorf("head: %v", ruleEvents(log))
			}
			if err := RecordRequestBody(r.Context(), map[string]any{"role": "admin"}, "application/json"); err != nil {
				t.Error(err)
			}
		})
		if got := ruleEvents(log); !reflect.DeepEqual(got, []string{"custom.role"}) {
			t.Errorf("body: %v", got)
		}
	})

	t.Run("a virtual patch finding is judged with the request current", func(t *testing.T) {
		log := setupEngine(t, engineSettings{})
		customRemote(t, nil, rule(map[string]any{"id": "vp-ctx",
			"expression": `attack.type == "virtual_patch" && request.path == "/vp" && request.ip == "10.1.2.3" && request.query["a"] == "1" && input.key == "query.a"`}))
		r := httptest.NewRequest(http.MethodGet, "/vp?a=1", nil)
		r.RemoteAddr = "10.1.2.3:5555"
		r.Header.Set("x-shield360-rasp-test", "exploit")
		serve(r, nil)
		if got := ruleEvents(log); !reflect.DeepEqual(got, []string{"vp.example-test-header", "custom.vp-ctx"}) {
			t.Errorf("events %v", got)
		}
	})

	t.Run("an upload finding is judged with the request current", func(t *testing.T) {
		log := setupEngine(t, engineSettings{})
		customRemote(t, nil, rule(map[string]any{"id": "upload-ctx",
			"expression": `attack.type == "file_write" && sink.name == "request.upload" && request.path == "/upload" && request.ip == "10.1.2.3" && input.key == "body.attachment.filename"`}))
		body, ct := multipartBody(part{"attachment", scriptName("page", "php"), "fixture"})
		r := httptest.NewRequest(http.MethodPost, "/upload", strings.NewReader(body))
		r.Header.Set("Content-Type", ct)
		r.RemoteAddr = "10.1.2.3:5555"
		serve(r, nil)
		if got := ruleEvents(log); !reflect.DeepEqual(got, []string{"file_write.upload", "custom.upload-ctx"}) {
			t.Errorf("events %v", got)
		}
	})

	t.Run("no body or an empty body is a known empty body: the body phase runs", func(t *testing.T) {
		for _, tc := range []struct{ name, method, body, ct string }{
			{"GET", http.MethodGet, "", ""},
			{"empty POST", http.MethodPost, "", ""},
			{"empty JSON POST", http.MethodPost, "", "application/json"},
			{"empty JSON object", http.MethodPost, "{}", "application/json"},
		} {
			t.Run(tc.name, func(t *testing.T) {
				log := setupEngine(t, engineSettings{})
				customRemote(t, nil, rule(map[string]any{"id": "no-x", "expression": `request.body["x"] == null`}))
				h := Middleware(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
				headers := map[string]string{}
				if tc.ct != "" {
					headers["Content-Type"] = tc.ct
				}
				do(t, h, tc.method, "/p", tc.body, headers)
				if got := ruleEvents(log); !reflect.DeepEqual(got, []string{"custom.no-x"}) {
					t.Errorf("events %v", got)
				}
			})
		}
	})

	t.Run("a body Middleware did not read stays unknown until recorded", func(t *testing.T) {
		log := setupEngine(t, engineSettings{})
		customRemote(t, nil, rule(map[string]any{"id": "no-x", "expression": `request.body["x"] == null`}))
		r := httptest.NewRequest(http.MethodGet, "/p", strings.NewReader(`{"x":"1"}`))
		serve(r, nil)
		if got := ruleEvents(log); len(got) != 0 {
			t.Errorf("events %v", got)
		}
	})

	t.Run("a body recorded after a known empty one still reaches the built-in checks, once", func(t *testing.T) {
		log := setupEngine(t, engineSettings{})
		customRemote(t, nil, rule(map[string]any{"id": "no-x", "expression": `request.body["x"] == null`}))
		var keys map[string]string
		h := Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// No body as far as Middleware knows (http.NoBody): the app
			// still hands one over itself.
			_ = RecordRequestBody(r.Context(), map[string]any{"x": "late"}, "application/json")
			_ = RecordRequestBody(r.Context(), map[string]any{"x": "twice"}, "application/json")
			keys = keysOf(r)
		}))
		do(t, h, http.MethodGet, "/p", "", nil)
		if keys["body.x"] != "late" {
			t.Errorf("keys %v", keys)
		}
		// The custom body phase ran once, on the empty body, and does not re-run.
		if got := ruleEvents(log); !reflect.DeepEqual(got, []string{"custom.no-x"}) {
			t.Errorf("events %v", got)
		}
	})
}
