package guardevents

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func TestPost(t *testing.T) {
	var calls atomic.Int32
	status := atomic.Int32{}
	status.Store(503)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		var p struct {
			Resource map[string]string `json:"resource"`
			Events   []map[string]any  `json:"events"`
		}
		if r.Header.Get("Authorization") != "Bearer key" || r.Header.Get("Content-Type") != "application/json" ||
			json.NewDecoder(r.Body).Decode(&p) != nil || p.Resource["service.name"] != "a" || len(p.Events) != 1 {
			w.WriteHeader(400)
			return
		}
		w.WriteHeader(int(status.Load()))
	}))
	defer srv.Close()
	payload := Payload{Resource: map[string]string{"service.name": "a"}, Events: []map[string]string{{"name": "x"}}}
	opts := Options{RetryDelay: time.Millisecond}

	if Post(context.Background(), srv.URL+Path, "key", payload, opts) || calls.Load() != 3 {
		t.Errorf("a 503 is retried three times, then dropped: %d calls", calls.Load())
	}
	calls.Store(0)
	status.Store(200)
	if !Post(context.Background(), srv.URL+Path, "key", payload, opts) || calls.Load() != 1 {
		t.Errorf("accepted: %d calls", calls.Load())
	}
	calls.Store(0)
	if Post(context.Background(), srv.URL+Path, "wrong", payload, opts) || calls.Load() != 1 {
		t.Errorf("a refusal is not retried: %d calls", calls.Load())
	}
}
