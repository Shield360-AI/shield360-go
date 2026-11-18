// Package guardevents is the transport to Shield360's /api/guard/events: the
// endpoint guard reports, heartbeats and runtime-protection (RASP) events
// share. It matches the TypeScript SDK's postGuardEvents (guard/report.ts).
package guardevents

import (
	"bytes"
	"context"
	"encoding/json"
	"log"
	"net/http"
	"reflect"
	"time"
)

// Path is the endpoint path under the Shield360 URL.
const Path = "/api/guard/events"

// Payload is one batch: the resource the events describe and the events.
type Payload struct {
	Resource map[string]string `json:"resource"`
	Events   any               `json:"events"`
}

// Options tune one Post.
type Options struct {
	// Label says what the batch is, for the warning when it cannot be
	// delivered. Default "guard report".
	Label string
	// Attempts is how many times to try. Default 3.
	Attempts int
	// RetryDelay is the delay before retry n, times n. Default 500 ms.
	RetryDelay time.Duration
	// Client sends the request. Default: a client with a 10 s timeout.
	Client *http.Client
}

var defaultClient = &http.Client{Timeout: 10 * time.Second}

// refused are the statuses that are not worth a retry.
var refused = map[int]bool{400: true, 401: true, 403: true, 413: true}

// Post sends one batch. It retries a few times, gives up on a refusal, and
// never panics. It reports whether Shield360 accepted the batch.
func Post(ctx context.Context, endpoint, apiKey string, p Payload, o Options) (ok bool) {
	defer func() {
		if recover() != nil {
			ok = false
		}
	}()
	label := o.Label
	if label == "" {
		label = "guard report"
	}
	attempts := o.Attempts
	if attempts <= 0 {
		attempts = 3
	}
	delay := o.RetryDelay
	if delay <= 0 {
		delay = 500 * time.Millisecond
	}
	client := o.Client
	if client == nil {
		client = defaultClient
	}
	body, err := json.Marshal(p)
	if err != nil {
		return false
	}
	if ctx == nil {
		ctx = context.Background()
	}
	for attempt := 0; attempt < attempts; attempt++ {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
		if err != nil {
			return false
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+apiKey)
		if res, err := client.Do(req); err == nil {
			res.Body.Close()
			if res.StatusCode >= 200 && res.StatusCode < 300 {
				return true
			}
			if refused[res.StatusCode] {
				log.Printf("Shield360 rejected %ss: HTTP %d", label, res.StatusCode)
				return false
			}
		}
		if attempt+1 < attempts {
			select {
			case <-ctx.Done():
				return false
			case <-time.After(delay * time.Duration(attempt+1)):
			}
		}
	}
	log.Printf("Could not deliver %d %s(s) to Shield360", count(p.Events), label)
	return false
}

func count(events any) int {
	v := reflect.ValueOf(events)
	if v.Kind() == reflect.Slice || v.Kind() == reflect.Array {
		return v.Len()
	}
	return 0
}
