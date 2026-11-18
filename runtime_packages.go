package shield360

// SHIELD: runtime SCA — the modules this binary runs, reported to Shield360
// so it can match them against vulnerability data server-side (Security →
// Code, target type "runtime").
//
// On by default whenever Init has a Shield360 URL and API key, whether or not
// runtime protection is on; Config.DisableRuntimePackages or
// SHIELD360_RUNTIME_PACKAGES=off turns it off. The report is the same
// shield360.rasp.component record runtime protection sends
// (rasp.CollectComponents: the Go version and the modules the binary was
// built with, from runtime/debug.ReadBuildInfo), on the same route (POST
// /api/guard/events, the app's API key). Names and versions only, never a
// path; at most rasp.MaxComponents. Sent shortly after start and then every
// day from a goroutine; a report that cannot be delivered is dropped.
//
// Must stay in step with sdk/typescript/src/runtime-packages.ts.

import (
	"context"
	"net/http"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/ThinkfleetAI/shield360-go/internal/guardevents"
	"github.com/ThinkfleetAI/shield360-go/rasp"
)

// Runtime package report timing.
const (
	RuntimePackagesStartDelay = 15 * time.Second
	RuntimePackagesEvery      = 24 * time.Hour
	runtimePackagesBatch      = 100
)

var runtimePackagesOff = regexp.MustCompile(`(?i)^(off|false|0|no)$`)

// RuntimePackagesOptions configure StartRuntimePackages.
type RuntimePackagesOptions struct {
	URL             string
	APIKey          string
	ApplicationName string
	Environment     string
	SDKVersion      string
	// Disabled turns the report off (Config.DisableRuntimePackages).
	Disabled bool
	// Getenv reads the environment (tests); default os.Getenv.
	Getenv func(string) string
	// StartDelay and Every override the timing (tests).
	StartDelay time.Duration
	Every      time.Duration
	// Collect lists the components (tests); default rasp.CollectComponents.
	Collect    func() []rasp.Component
	HTTPClient *http.Client
	RetryDelay time.Duration
}

var (
	runtimePackagesMu   sync.Mutex
	runtimePackagesStop chan struct{}
)

// RuntimePackagesEnabled reports whether the report runs: Disabled, or
// SHIELD360_RUNTIME_PACKAGES=off|false|0|no, turns it off.
func RuntimePackagesEnabled(disabled bool, getenv func(string) string) bool {
	if disabled {
		return false
	}
	if getenv == nil {
		getenv = os.Getenv
	}
	return !runtimePackagesOff.MatchString(strings.TrimSpace(getenv("SHIELD360_RUNTIME_PACKAGES")))
}

// RuntimePackagesActive reports whether the report is running.
func RuntimePackagesActive() bool {
	runtimePackagesMu.Lock()
	defer runtimePackagesMu.Unlock()
	return runtimePackagesStop != nil
}

// ReportRuntimePackages sends one report now and reports whether every
// batch was accepted. Never panics.
func ReportRuntimePackages(ctx context.Context, o RuntimePackagesOptions) (ok bool) {
	defer func() {
		if recover() != nil {
			ok = false
		}
	}()
	if o.URL == "" || o.APIKey == "" {
		return false
	}
	collect := o.Collect
	if collect == nil {
		collect = rasp.CollectComponents
	}
	components := collect()
	if len(components) > rasp.MaxComponents {
		components = components[:rasp.MaxComponents]
	}
	now := time.Now().UTC().Format("2006-01-02T15:04:05.000Z")
	events := make([]rasp.Event, 0, len(components))
	for _, c := range components {
		events = append(events, rasp.Event{Name: rasp.ComponentName, Time: now, Attrs: map[string]string{
			"shield360.rasp.app":                 o.ApplicationName,
			"shield360.rasp.component.ecosystem": c.Ecosystem,
			"shield360.rasp.component.name":      c.Name,
			"shield360.rasp.component.version":   c.Version,
		}})
	}
	resource := map[string]string{"service.name": o.ApplicationName}
	if h, err := os.Hostname(); err == nil && h != "" {
		resource["host.name"] = h
	}
	if o.Environment != "" {
		resource["deployment.environment"] = o.Environment
	}
	if o.SDKVersion != "" {
		resource["service.version"] = o.SDKVersion
	}
	endpoint := strings.TrimRight(o.URL, "/") + guardevents.Path
	for i := 0; i < len(events); i += runtimePackagesBatch {
		end := min(i+runtimePackagesBatch, len(events))
		if !guardevents.Post(ctx, endpoint, o.APIKey, guardevents.Payload{Resource: resource, Events: events[i:end]},
			guardevents.Options{Label: "runtime package report", Client: o.HTTPClient, RetryDelay: o.RetryDelay}) {
			return false
		}
	}
	return true
}

// StartRuntimePackages starts the report: once after StartDelay, then every
// Every. It returns whether it started; a second call while it runs, a
// missing URL or key, or a turned-off report start nothing. While it runs,
// runtime protection leaves its components report to it.
func StartRuntimePackages(o RuntimePackagesOptions) bool {
	if o.URL == "" || o.APIKey == "" || !RuntimePackagesEnabled(o.Disabled, o.Getenv) {
		return false
	}
	runtimePackagesMu.Lock()
	if runtimePackagesStop != nil {
		runtimePackagesMu.Unlock()
		return false
	}
	stop := make(chan struct{})
	runtimePackagesStop = stop
	runtimePackagesMu.Unlock()
	rasp.SetComponentsReportedElsewhere(true)

	delay, every := o.StartDelay, o.Every
	if delay <= 0 {
		delay = RuntimePackagesStartDelay
	}
	if every <= 0 {
		every = RuntimePackagesEvery
	}
	go func() {
		defer func() { _ = recover() }()
		timer := time.NewTimer(delay)
		defer timer.Stop()
		for {
			select {
			case <-stop:
				return
			case <-timer.C:
				ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
				ReportRuntimePackages(ctx, o)
				cancel()
				timer.Reset(every)
			}
		}
	}()
	return true
}

// StopRuntimePackages stops the report (Shutdown, tests).
func StopRuntimePackages() {
	runtimePackagesMu.Lock()
	stop := runtimePackagesStop
	runtimePackagesStop = nil
	runtimePackagesMu.Unlock()
	if stop != nil {
		close(stop)
		rasp.SetComponentsReportedElsewhere(false)
	}
}
