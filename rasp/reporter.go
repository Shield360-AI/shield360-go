package rasp

import (
	"context"
	"net/http"
	"os"
	"regexp"
	"runtime/debug"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Shield360-AI/shield360-go/internal/guardevents"
)

// The RASP event reporter (README "Events"). Batches shield360.rasp.event
// and shield360.rasp.component records to POST /api/guard/events through the
// guard events transport, off the call path. At most 100 events a minute per
// process; repeats of the same (attack, rule, sink, route, decision) within
// 10 s fold into one more event carrying shield360.rasp.count. Events name
// locations, never values.

// Reporter limits.
const (
	EventName      = "shield360.rasp.event"
	ComponentName  = "shield360.rasp.component"
	PerMinute      = 100
	FoldWindow     = 10 * time.Second
	flushEvery     = 2 * time.Second
	maxQueued      = 1000
	MaxComponents  = 500
	batchSize      = 100
	componentEvery = 24 * time.Hour
)

type fold struct {
	event Event
	extra int
	until time.Time
}

// ReporterOptions configure a Reporter.
type ReporterOptions struct {
	URL             string
	APIKey          string
	ApplicationName string
	Environment     string
	SDKVersion      string
	HTTPClient      *http.Client
	Now             func() time.Time
	RetryDelay      time.Duration
}

// Reporter batches RASP events to Shield360.
type Reporter struct {
	o        ReporterOptions
	endpoint string
	resource map[string]string

	mu           sync.Mutex
	queue        []Event
	folds        map[string]*fold
	foldOrder    []string
	windowStart  time.Time
	windowOpen   bool
	sentInWindow int

	sendMu   sync.Mutex
	stopOnce sync.Once
	stop     chan struct{}
	done     chan struct{}
	started  bool
}

// NewReporter builds a reporter; Start begins the periodic flush.
func NewReporter(o ReporterOptions) *Reporter {
	if o.Now == nil {
		o.Now = time.Now
	}
	r := &Reporter{
		o:        o,
		endpoint: strings.TrimRight(o.URL, "/") + guardevents.Path,
		resource: map[string]string{"service.name": o.ApplicationName},
		folds:    map[string]*fold{},
		stop:     make(chan struct{}),
		done:     make(chan struct{}),
	}
	if h, err := os.Hostname(); err == nil && h != "" {
		r.resource["host.name"] = h
	}
	if o.Environment != "" {
		r.resource["deployment.environment"] = o.Environment
	}
	if o.SDKVersion != "" {
		r.resource["service.version"] = o.SDKVersion
	}
	return r
}

// Resource is the resource every batch carries.
func (r *Reporter) Resource() map[string]string { return r.resource }

// Start flushes every 2 s until Stop.
func (r *Reporter) Start() {
	r.mu.Lock()
	if r.started {
		r.mu.Unlock()
		return
	}
	r.started = true
	r.mu.Unlock()
	go func() {
		defer close(r.done)
		t := time.NewTicker(flushEvery)
		defer t.Stop()
		for {
			select {
			case <-r.stop:
				return
			case <-t.C:
				r.Flush(context.Background(), false)
			}
		}
	}()
}

func (r *Reporter) add(e Event, foldKey string) bool { return r.Add(e, foldKey) }

// Add queues an event, folding repeats of the same key. It reports whether
// the event was queued now. An empty foldKey never folds: the event is
// queued or refused (rate limit, full queue) and nothing is kept, for
// callers that count repeats themselves (passive IAST).
func (r *Reporter) Add(e Event, foldKey string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	now := r.o.Now()
	r.closeFoldsLocked(now, false)
	if foldKey == "" {
		return r.enqueueLocked(e, now)
	}
	if f, ok := r.folds[foldKey]; ok && now.Before(f.until) {
		f.extra++
		return false
	}
	if _, ok := r.folds[foldKey]; !ok {
		r.foldOrder = append(r.foldOrder, foldKey)
	}
	r.folds[foldKey] = &fold{event: e, until: now.Add(FoldWindow)}
	return r.enqueueLocked(e, now)
}

func (r *Reporter) enqueueLocked(e Event, now time.Time) bool {
	if !r.windowOpen || now.Sub(r.windowStart) >= time.Minute {
		r.windowStart, r.windowOpen = now, true
		r.sentInWindow = 0
	}
	if r.sentInWindow >= PerMinute || len(r.queue) >= maxQueued {
		return false
	}
	r.sentInWindow++
	r.queue = append(r.queue, e)
	return true
}

func (r *Reporter) closeFoldsLocked(now time.Time, force bool) {
	keep := r.foldOrder[:0]
	for _, k := range r.foldOrder {
		f := r.folds[k]
		if !force && now.Before(f.until) {
			keep = append(keep, k)
			continue
		}
		delete(r.folds, k)
		if f.extra > 0 {
			attrs := make(map[string]string, len(f.event.Attrs)+1)
			for ak, av := range f.event.Attrs {
				attrs[ak] = av
			}
			attrs["shield360.rasp.count"] = strconv.Itoa(f.extra)
			dropTraceIDs(attrs)
			at := now
			if force {
				at = r.o.Now()
			}
			r.enqueueLocked(Event{Name: f.event.Name, Time: isoTime(at), Attrs: attrs}, at)
		}
	}
	r.foldOrder = keep
}

func isoTime(t time.Time) string { return t.UTC().Format("2006-01-02T15:04:05.000Z") }

// Pending returns the queued events (tests).
func (r *Reporter) Pending() []Event {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]Event(nil), r.queue...)
}

// Flush sends what is queued; force also closes every open fold. Never
// panics.
func (r *Reporter) Flush(ctx context.Context, force bool) {
	defer func() { _ = recover() }()
	r.sendMu.Lock()
	defer r.sendMu.Unlock()
	r.mu.Lock()
	r.closeFoldsLocked(r.o.Now(), force)
	r.mu.Unlock()
	for {
		r.mu.Lock()
		if len(r.queue) == 0 {
			r.mu.Unlock()
			return
		}
		n := min(batchSize, len(r.queue))
		batch := append([]Event(nil), r.queue[:n]...)
		r.queue = r.queue[n:]
		r.mu.Unlock()
		guardevents.Post(ctx, r.endpoint, r.o.APIKey, guardevents.Payload{Resource: r.resource, Events: batch},
			guardevents.Options{Label: "runtime protection event", Client: r.o.HTTPClient, RetryDelay: r.o.RetryDelay})
	}
}

// ReportComponents queues the components report: names and versions only,
// at most 500.
func (r *Reporter) ReportComponents(components []Component) {
	r.mu.Lock()
	defer r.mu.Unlock()
	t := isoTime(r.o.Now())
	for i, c := range components {
		if i >= MaxComponents || len(r.queue) >= maxQueued {
			break
		}
		r.queue = append(r.queue, Event{Name: ComponentName, Time: t, Attrs: map[string]string{
			"shield360.rasp.app":                 r.o.ApplicationName,
			"shield360.rasp.component.ecosystem": c.Ecosystem,
			"shield360.rasp.component.name":      c.Name,
			"shield360.rasp.component.version":   c.Version,
		}})
	}
}

// Stop ends the periodic flush and sends everything, open folds included.
func (r *Reporter) Stop(ctx context.Context) {
	r.stopOnce.Do(func() {
		close(r.stop)
		r.mu.Lock()
		started := r.started
		r.mu.Unlock()
		if started {
			<-r.done
		}
	})
	r.Flush(ctx, true)
}

// Component is one entry of the components report.
type Component struct {
	Ecosystem string
	Name      string
	Version   string
}

var (
	componentName    = regexp.MustCompile(`^[A-Za-z0-9@_][A-Za-z0-9@/._+~-]{0,213}$`)
	componentVersion = regexp.MustCompile(`^v?[0-9A-Za-z][0-9A-Za-z.+_~-]{0,63}$`)
)

// CollectComponents lists the Go runtime and the modules the binary was
// built with (runtime/debug.ReadBuildInfo; a replaced module reports its
// replacement's version). Names and versions only; at most 500.
func CollectComponents() []Component {
	bi, _ := debug.ReadBuildInfo()
	return componentsFrom(bi, RuntimeVersion())
}

func componentsFrom(bi *debug.BuildInfo, goVersion string) []Component {
	out := []Component{{Ecosystem: "runtime", Name: "go", Version: goVersion}}
	if bi == nil {
		return out
	}
	seen := map[string]bool{}
	for _, m := range bi.Deps {
		if len(out) >= MaxComponents {
			break
		}
		if m == nil {
			continue
		}
		path, version := m.Path, m.Version
		if m.Replace != nil {
			if m.Replace.Version != "" {
				version = m.Replace.Version
			}
			if m.Replace.Version != "" && m.Replace.Path != "" && !strings.HasPrefix(m.Replace.Path, ".") && !strings.HasPrefix(m.Replace.Path, "/") {
				path = m.Replace.Path
			}
		}
		if !componentName.MatchString(path) || !componentVersion.MatchString(version) {
			continue
		}
		id := path + "@" + version
		if seen[id] {
			continue
		}
		seen[id] = true
		out = append(out, Component{Ecosystem: "go", Name: path, Version: version})
	}
	return out
}
