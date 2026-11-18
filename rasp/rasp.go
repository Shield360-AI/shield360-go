package rasp

import (
	"context"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Options are the local RASP options (README "Enabling"). Passing Options to
// shield360.Init (Config.Rasp) turns RASP on unless Disabled is set;
// SHIELD360_RASP=monitor|block turns it on without them, and
// SHIELD360_RASP=off always wins.
type Options struct {
	// Disabled keeps RASP off although Options were given.
	Disabled bool
	// Mode is the default mode for every attack type without its own.
	// Default monitor (or SHIELD360_RASP=block|monitor).
	Mode Mode
	// Attacks sets the mode per attack type.
	Attacks map[AttackType]Mode
	// Allow holds the allow-lists.
	Allow Allow
	// DisableModelOutput stops treating model output seen by the SDK's LLM
	// instrumentation as untrusted input (the contract's modelOutput: false).
	DisableModelOutput bool
	// DisableRemote stops polling the signed config (remote: false).
	DisableRemote bool
	// ConfigPublicKey is required to use the signed config: the
	// environment's public key, as a JWK, a JWKS ({"keys": [...]}, so a
	// rotation can list the old and new key) or the bare base64url x. Also
	// SHIELD360_CONFIG_PUBLIC_KEY. Copy it from the app's Runtime protection
	// settings in Shield360. Without it the signed config is not fetched
	// and RASP runs its built-in defaults in monitor mode.
	ConfigPublicKey string
	// AllowUnpinnedConfig is development only: trust on first use (pin the
	// first kid the server sends). Also SHIELD360_CONFIG_TOFU=dev. Ignored
	// in production (ENVIRONMENT, NODE_ENV, ASPNETCORE_ENVIRONMENT or the
	// SDK's deployment environment set to production).
	AllowUnpinnedConfig bool
	// CacheDir is where the last verified config is cached. Default
	// os.TempDir()/shield360-rasp.
	CacheDir string
	// DisableComponents stops the components report (the app's modules
	// and versions, at start and every 24 h).
	DisableComponents bool
	// Iast turns on passive IAST: report where request input reaches a sink
	// unparameterized during normal traffic (README "Passive IAST"). Never
	// blocks. Also SHIELD360_IAST=on; SHIELD360_IAST=off and the signed
	// config's iast rank above it.
	Iast bool
	// IastSampleRate is the share of checks that run the IAST rules, 0 to 1
	// (0 keeps the default: every check, 1 in 10 in production).
	// SHIELD360_IAST_SAMPLE_RATE and the signed config's iastSampleRate rank
	// above it.
	IastSampleRate float64
}

// componentsElsewhere is set while the SDK's runtime package report
// (shield360.StartRuntimePackages) runs: it sends the same components
// report, so Init does not start a second one.
var componentsElsewhere atomic.Bool

// SetComponentsReportedElsewhere tells Init whether the SDK's runtime package
// report already sends the components report.
func SetComponentsReportedElsewhere(v bool) { componentsElsewhere.Store(v) }

// InitContext is what Init needs from the SDK.
type InitContext struct {
	ApplicationName string
	// Environment is the deployment environment (resource attribute).
	Environment string
	// URL and APIKey are the Shield360 destination for events and the
	// signed config.
	URL    string
	APIKey string
	// SDKVersion is the Go SDK's version.
	SDKVersion string
	// OtlpEndpoint is always allowed outbound, like URL.
	OtlpEndpoint string
	// Getenv reads the environment (tests); default os.Getenv.
	Getenv     func(string) string
	HTTPClient *http.Client
}

// AlwaysAllowed returns the hosts of the given URLs (the Shield360 URL and
// the OTLP endpoint), which outbound checks always allow.
func AlwaysAllowed(urls ...string) []string {
	seen := map[string]bool{}
	var out []string
	for _, u := range urls {
		if u == "" {
			continue
		}
		p, err := url.Parse(u)
		if err != nil || p.Hostname() == "" {
			continue
		}
		h := strings.ToLower(p.Hostname())
		if !seen[h] {
			seen[h] = true
			out = append(out, h)
		}
	}
	return out
}

func isProduction(v string) bool {
	v = strings.ToLower(strings.TrimSpace(v))
	return v == "prod" || v == "production"
}

// TofuAllowed reports whether trust on first use is allowed: the explicit
// opt-in (option or SHIELD360_CONFIG_TOFU=dev), never when NODE_ENV,
// ENVIRONMENT, ASPNETCORE_ENVIRONMENT or the deployment environment says
// production.
func TofuAllowed(option bool, environment string, getenv func(string) string) bool {
	if getenv == nil {
		getenv = os.Getenv
	}
	asked := option || strings.ToLower(strings.TrimSpace(getenv("SHIELD360_CONFIG_TOFU"))) == "dev"
	if !asked {
		return false
	}
	return !productionEnv(environment, getenv)
}

// resolveEnabled: Options given means on unless Disabled; no Options means
// SHIELD360_RASP=monitor|block decides; SHIELD360_RASP=off always wins.
func resolveEnabled(o *Options, getenv func(string) string) bool {
	e := envSetting(getenv)
	enabled := o != nil && !o.Disabled
	if o == nil && (e == ModeMonitor || e == ModeBlock) {
		enabled = true
	}
	if e == ModeOff {
		enabled = false
	}
	return enabled
}

var (
	warnUnpinnedOnce sync.Once
	logf             = log.Printf
)

func warnUnpinned() {
	warnUnpinnedOnce.Do(func() {
		logf("Shield360 RASP: the signed config key is not pinned, so the signed config is not used and RASP runs its built-in defaults in monitor mode. Set ConfigPublicKey (or SHIELD360_CONFIG_PUBLIC_KEY) to the environment's public key from the app's Runtime protection settings in Shield360.")
	})
}

type runtimeState struct {
	client     *ConfigClient
	reporter   *Reporter
	components chan struct{}
}

var (
	runtimeMu sync.Mutex
	rt        runtimeState
)

func toRemote(c *Claims) *RemoteConfig {
	if c == nil {
		return nil
	}
	return &RemoteConfig{
		Version:       c.Version,
		Exp:           c.Exp,
		KillSwitch:    c.KillSwitch,
		Snippets:      c.Snippets,
		ReportTargets: c.ReportTargets,
		Mode:          c.Mode,
		Attacks:       c.Attacks,
		Allow:         c.Allow,
		Rules:         c.Rules,
		CustomRules:   c.CustomRules,
		Deception:     c.Deception,
	}
}

// Shutdown stops polling, the components timer and the reporter (sending
// what is queued). RASP stays configured; Init configures it again.
func Shutdown(ctx context.Context) {
	if rep := detachRuntime(); rep != nil {
		rep.Stop(ctx)
	}
}

// reInitFlushTimeout bounds the background flush of the reporter a re-Init
// replaces.
const reInitFlushTimeout = 30 * time.Second

// detachRuntime stops polling and the components timer, unhooks the
// reporter from the engine, and returns it for the caller to stop. Nothing
// here touches the network.
func detachRuntime() *Reporter {
	runtimeMu.Lock()
	r := rt
	rt = runtimeState{}
	runtimeMu.Unlock()
	if r.client != nil {
		r.client.Stop()
	}
	if r.components != nil {
		close(r.components)
	}
	setEventSink(nil)
	return r.reporter
}

// Init turns RASP on (or leaves it off) for this process and returns
// whether it is on. It never panics and never blocks on the network.
// shield360.Init calls it; call it directly only without shield360.Init.
func Init(o *Options, ic InitContext) (on bool) {
	defer func() {
		if r := recover(); r != nil {
			logf("Shield360 RASP could not start")
			on = false
		}
	}()
	// The previous runtime's queued events are sent in the background with
	// a bounded deadline: Init never waits on the network.
	if rep := detachRuntime(); rep != nil {
		go func() {
			defer func() { _ = recover() }()
			ctx, cancel := context.WithTimeout(context.Background(), reInitFlushTimeout)
			defer cancel()
			rep.Stop(ctx)
		}()
	}
	getenv := ic.Getenv
	if getenv == nil {
		getenv = os.Getenv
	}
	opts := Options{}
	if o != nil {
		opts = *o
	}
	enabled := resolveEnabled(o, getenv)
	remoteWanted := enabled && !opts.DisableRemote && ic.URL != "" && ic.APIKey != ""
	keyText := opts.ConfigPublicKey
	if keyText == "" {
		keyText = getenv("SHIELD360_CONFIG_PUBLIC_KEY")
	}
	pinned := ParsePublicKeys(keyText)
	tofu := len(pinned) == 0 && TofuAllowed(opts.AllowUnpinnedConfig, ic.Environment, getenv)
	unpinned := remoteWanted && len(pinned) == 0 && !tofu
	configureEngine(engineSettings{
		enabled:         enabled,
		applicationName: ic.ApplicationName,
		mode:            opts.Mode,
		attacks:         opts.Attacks,
		allow:           opts.Allow,
		modelOutput:     !opts.DisableModelOutput,
		// No pinned key while a remote config was expected: built-in
		// defaults, monitor only.
		monitorOnly:   unpinned,
		alwaysAllowed: AlwaysAllowed(ic.URL, ic.OtlpEndpoint),
		getenv:        getenv,
	})
	configureIast(iastSettings{
		enabled:         opts.Iast,
		sampleRate:      opts.IastSampleRate,
		applicationName: ApplicationName(),
		environment:     ic.Environment,
		getenv:          getenv,
	})
	if !enabled {
		return false
	}

	runtimeMu.Lock()
	defer runtimeMu.Unlock()
	if ic.URL != "" && ic.APIKey != "" {
		rep := NewReporter(ReporterOptions{
			URL:             ic.URL,
			APIKey:          ic.APIKey,
			ApplicationName: ApplicationName(),
			Environment:     ic.Environment,
			SDKVersion:      ic.SDKVersion,
			HTTPClient:      ic.HTTPClient,
		})
		rep.Start()
		setEventSink(rep)
		rt.reporter = rep
		// SHIELD: runtime SCA — when the SDK's runtime package report runs it already sends these.
		if !opts.DisableComponents && !componentsElsewhere.Load() {
			stop := make(chan struct{})
			rt.components = stop
			go func() {
				defer func() { _ = recover() }()
				rep.ReportComponents(CollectComponents())
				t := time.NewTicker(componentEvery)
				defer t.Stop()
				for {
					select {
					case <-stop:
						return
					case <-t.C:
						rep.ReportComponents(CollectComponents())
					}
				}
			}()
		}
	}

	switch {
	case unpinned:
		warnUnpinned()
	case remoteWanted:
		if tofu {
			logf("Shield360 RASP: trust on first use is on for the signed config (development only); set ConfigPublicKey before production.")
		}
		cacheDir := opts.CacheDir
		if cacheDir == "" {
			cacheDir = filepath.Join(os.TempDir(), "shield360-rasp")
		}
		client := NewConfigClient(ConfigClientOptions{
			URL:           ic.URL,
			APIKey:        ic.APIKey,
			App:           ApplicationName(),
			Pinned:        pinned,
			AllowUnpinned: tofu,
			CacheDir:      cacheDir,
			HTTPClient:    ic.HTTPClient,
			OnConfig: func(c *Claims) {
				setRemoteConfig(toRemote(c))
				setIastRemote(c)
			},
			// Logged once per reason (the client dedupes); trust on first
			// use was already announced.
			OnWarning: func(reason string) {
				if reason == "trust_on_first_use" {
					return
				}
				logf("Shield360 RASP: a signed config was refused (%s); the last verified config or the local options stay in force.", reason)
			},
		})
		rt.client = client
		client.Start()
	}
	// Security baseline: once per process, in the background, monitor only.
	startBaseline(ic.Environment, getenv, remoteWanted, len(pinned) > 0)
	return true
}
