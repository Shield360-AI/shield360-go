package defend

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"sync"
	"time"

	shield360 "github.com/Shield360-AI/shield360-go"
)

// Defend's decisions to Shield360: deny, challenge and trap decisions and
// failed sign-ins go to POST /api/defend/report, batched (at most 100 an
// HTTP call), folded (the same event within 10 s adds to a count), at most
// 300 a minute, from a background goroutine. Never a header, body, query
// string, user name or password.

// ReportPath is where decisions are reported.
const ReportPath = "/api/defend/report"

const (
	reportPerMinute = 300
	foldMs          = 10_000
	reportBatch     = 100
	maxQueued       = 1000
	flushEvery      = 2 * time.Second
)

// Event is one reported decision.
type Event struct {
	Kind       string   `json:"kind"`
	Decision   string   `json:"decision,omitempty"`
	Monitored  bool     `json:"monitored,omitempty"`
	ClientType string   `json:"clientType,omitempty"`
	IP         string   `json:"ip,omitempty"`
	Path       string   `json:"path"`
	Method     string   `json:"method"`
	Reasons    []string `json:"reasons"`
	RuleIDs    []string `json:"ruleIds"`
	At         string   `json:"at"`
	Count      int      `json:"count"`
}

type fold struct {
	i     int
	until int64
}

type reporter struct {
	endpoint, apiKey, app string
	client                *http.Client
	now                   func() int64

	mu           sync.Mutex
	queue        []Event
	folds        map[string]fold
	windowStart  int64
	sentInWindow int
	dropped      int

	stop chan struct{}
	done chan struct{}
	once sync.Once
}

func newReporter(url, apiKey, app string, client *http.Client, now func() int64) *reporter {
	return &reporter{
		endpoint: strings.TrimRight(url, "/") + ReportPath, apiKey: apiKey, app: app,
		client: client, now: now, folds: map[string]fold{},
	}
}

func (r *reporter) add(e Event) {
	now := r.now()
	mon := "0"
	if e.Monitored {
		mon = "1"
	}
	key := strings.Join([]string{e.Kind, e.Decision, mon, e.IP, e.Path, e.Method, strings.Join(e.Reasons, ","), strings.Join(e.RuleIDs, ",")}, "|")
	r.mu.Lock()
	defer r.mu.Unlock()
	if f, ok := r.folds[key]; ok && f.until > now && f.i < len(r.queue) {
		r.queue[f.i].Count++
		return
	}
	if now-r.windowStart >= 60_000 {
		r.windowStart, r.sentInWindow = now, 0
	}
	if r.sentInWindow >= reportPerMinute || len(r.queue) >= maxQueued {
		r.dropped++
		return
	}
	r.sentInWindow++
	if len(e.Reasons) > 16 {
		e.Reasons = e.Reasons[:16]
	}
	if len(e.RuleIDs) > 16 {
		e.RuleIDs = e.RuleIDs[:16]
	}
	if e.Reasons == nil {
		e.Reasons = []string{}
	}
	if e.RuleIDs == nil {
		e.RuleIDs = []string{}
	}
	e.At = time.UnixMilli(now).UTC().Format("2006-01-02T15:04:05.000Z")
	e.Count = 1
	r.queue = append(r.queue, e)
	if len(r.folds) > 5000 {
		r.folds = map[string]fold{}
	}
	r.folds[key] = fold{len(r.queue) - 1, now + foldMs}
}

func (r *reporter) pending() []Event {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]Event(nil), r.queue...)
}

func (r *reporter) flush() {
	r.mu.Lock()
	queue := r.queue
	r.queue = nil
	r.folds = map[string]fold{}
	r.mu.Unlock()
	for len(queue) > 0 {
		n := min(len(queue), reportBatch)
		batch := queue[:n]
		queue = queue[n:]
		if !r.send(batch) {
			r.mu.Lock()
			r.dropped += len(batch)
			r.mu.Unlock()
		}
	}
}

func (r *reporter) send(batch []Event) (ok bool) {
	defer func() {
		if recover() != nil {
			ok = false
		}
	}()
	body, err := json.Marshal(map[string]any{"app": r.app, "sdk": "go", "sdkVersion": shield360.Version, "events": batch})
	if err != nil {
		return false
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, r.endpoint, bytes.NewReader(body))
	if err != nil {
		return false
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+r.apiKey)
	res, err := r.client.Do(req)
	if err != nil {
		return false
	}
	_ = res.Body.Close()
	return res.StatusCode >= 200 && res.StatusCode < 300
}

func (r *reporter) start() {
	r.stop, r.done = make(chan struct{}), make(chan struct{})
	go func() {
		defer close(r.done)
		t := time.NewTicker(flushEvery)
		defer t.Stop()
		for {
			select {
			case <-r.stop:
				return
			case <-t.C:
				r.flush()
			}
		}
	}()
}

func (r *reporter) close() {
	r.once.Do(func() {
		if r.stop != nil {
			close(r.stop)
			<-r.done
		}
		r.flush()
	})
}
