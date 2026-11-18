package flags

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log"
	"math"
	"math/rand/v2"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
)

const (
	// RulesPath is the feed of an environment's flags and segments.
	RulesPath = "/api/flags/rules"
	// PromptPath is the Prompt Hub endpoint Prompt fetches from.
	PromptPath = "/api/prompt/get-compiled"
	// SpanAttributePrefix + flag key is set to the served variation's key on the active span.
	SpanAttributePrefix = "shield360.flag."
	// DefaultPollInterval is how often rules are fetched unless Options say otherwise.
	DefaultPollInterval = 30 * time.Second
	// MinPollInterval is the shortest poll interval allowed.
	MinPollInterval = 5 * time.Second
	// DefaultTimeout bounds each request.
	DefaultTimeout = 10 * time.Second

	maxBodyBytes = 32 << 20
)

// Defaults are the settings shield360.Init passes to every flags client, used
// where a client's Options leave a field empty.
type Defaults struct {
	URL             string
	APIKey          string
	ApplicationName string
}

var defaults atomic.Pointer[Defaults]

// SetDefaults sets the destination and application name clients fall back
// to. shield360.Init calls it; call it yourself only without Init.
func SetDefaults(d Defaults) { defaults.Store(&d) }

func currentDefaults() Defaults {
	if d := defaults.Load(); d != nil {
		return *d
	}
	return Defaults{}
}

// Options configure a Client. Every field is optional.
type Options struct {
	// URL is Shield360's base URL. Default: shield360.Init's Shield360URL,
	// then SHIELD360_URL.
	URL string
	// APIKey is the environment's API key. Default: shield360.Init's
	// Shield360APIKey, then SHIELD360_API_KEY.
	APIKey string
	// ApplicationName is service.name, for flags scoped to one app.
	// Default: shield360.Init's ApplicationName.
	ApplicationName string
	// PollInterval is how often to fetch rules (at least 5s). Default 30s.
	PollInterval time.Duration
	// Timeout bounds each request. Default 10s.
	Timeout time.Duration
	// DisableSpanAttributes stops setting shield360.flag.<key> on the active span.
	DisableSpanAttributes bool
	// HTTPClient sends the requests. Default: a client without its own timeout
	// (Timeout applies per request).
	HTTPClient *http.Client
}

// Detail is a flag's value for a context, with the variation and why.
type Detail struct {
	// Value is the served variation's value, or the caller's default.
	Value any
	// Variation is the served variation's key; empty when the default was returned.
	Variation string
	// Reason says why: an engine reason, or NOT_READY, FLAG_NOT_FOUND,
	// WRONG_TYPE or ERROR when the default was returned.
	Reason Reason
}

// Client polls one environment's flags and segments and evaluates them
// locally. It is safe for concurrent use and never panics or returns errors
// into the app: until rules arrive, for an unknown flag, or on any error, the
// caller's default is returned.
type Client struct {
	opts Options

	mu       sync.RWMutex
	flags    map[string]map[string]any
	segments []any
	etag     string
	version  string

	ready     chan struct{}
	readyOnce sync.Once

	fetchMu sync.Mutex

	runMu   sync.Mutex
	running atomic.Bool
	cancel  context.CancelFunc

	warned atomic.Bool

	// manual leaves polling to the caller (tests drive Refresh themselves).
	manual bool
}

// New creates a client. Polling starts on first use, or on Start.
func New(opts Options) *Client {
	return &Client{opts: opts, flags: map[string]map[string]any{}, ready: make(chan struct{})}
}

var defaultClient = New(Options{})

// Default is the SDK's own client (shield360.Flags()). It reads
// shield360.Init's settings when it fetches.
func Default() *Client { return defaultClient }

func (c *Client) destination() (string, string, bool) {
	d := currentDefaults()
	url := firstNonEmpty(c.opts.URL, d.URL, os.Getenv("SHIELD360_URL"))
	key := firstNonEmpty(c.opts.APIKey, d.APIKey, os.Getenv("SHIELD360_API_KEY"))
	url = strings.TrimRight(strings.TrimSpace(url), "/")
	key = strings.TrimSpace(key)
	return url, key, url != "" && key != ""
}

func (c *Client) applicationName() string {
	return firstNonEmpty(c.opts.ApplicationName, currentDefaults().ApplicationName)
}

func (c *Client) timeout() time.Duration {
	if c.opts.Timeout > 0 {
		return c.opts.Timeout
	}
	return DefaultTimeout
}

func (c *Client) pollInterval() time.Duration {
	if c.opts.PollInterval <= 0 {
		return DefaultPollInterval
	}
	return max(c.opts.PollInterval, MinPollInterval)
}

func (c *Client) httpClient() *http.Client {
	if c.opts.HTTPClient != nil {
		return c.opts.HTTPClient
	}
	return http.DefaultClient
}

// ------------------------------------------------------------- polling

// Start starts polling in the background (once). It is called on first use;
// call it at startup to fetch early.
func (c *Client) Start() {
	if c.manual || c.running.Load() {
		return
	}
	c.runMu.Lock()
	defer c.runMu.Unlock()
	if c.running.Load() {
		return
	}
	ctx, cancel := context.WithCancel(context.Background())
	c.cancel = cancel
	c.running.Store(true)
	go c.run(ctx)
}

func (c *Client) run(ctx context.Context) {
	defer func() { _ = recover() }()
	for {
		c.refresh(ctx)
		// ±10% jitter, so many processes started together do not poll together.
		interval := c.pollInterval()
		delay := time.Duration(float64(interval) * (0.9 + rand.Float64()*0.2)) //nolint:gosec // jitter, not security
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
	}
}

// Close stops polling. Rules already fetched keep being served; a later
// Start (or evaluation) starts polling again.
func (c *Client) Close() {
	c.runMu.Lock()
	defer c.runMu.Unlock()
	if c.cancel != nil {
		c.cancel()
		c.cancel = nil
	}
	c.running.Store(false)
}

// IsReady reports whether rules have been fetched at least once.
func (c *Client) IsReady() bool {
	select {
	case <-c.ready:
		return true
	default:
		return false
	}
}

// WaitUntilReady starts polling and blocks until rules have been fetched
// once (true) or timeout passes (false).
func (c *Client) WaitUntilReady(timeout time.Duration) bool {
	c.Start()
	if c.IsReady() {
		return true
	}
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case <-c.ready:
		return true
	case <-timer.C:
		return false
	}
}

// Refresh fetches the rules now. It reports whether they are current; it
// never panics.
func (c *Client) Refresh() bool {
	return c.refresh(context.Background())
}

// Version is the version of the rules last fetched ("" before any).
func (c *Client) Version() string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.version
}

func (c *Client) refresh(parent context.Context) (ok bool) {
	c.fetchMu.Lock()
	defer c.fetchMu.Unlock()
	defer func() {
		if r := recover(); r != nil {
			ok = false
		}
	}()
	return c.fetch(parent)
}

func (c *Client) markReady() { c.readyOnce.Do(func() { close(c.ready) }) }

type rulesBody struct {
	Version  any   `json:"version"`
	Flags    []any `json:"flags"`
	Segments any   `json:"segments"`
}

func (c *Client) fetch(parent context.Context) bool {
	url, key, ok := c.destination()
	if !ok {
		if !c.warned.Swap(true) {
			log.Printf("shield360 flags: no Shield360 URL and API key (SHIELD360_URL, SHIELD360_API_KEY); every flag serves its default.")
		}
		return false
	}
	ctx, cancel := context.WithTimeout(parent, c.timeout())
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url+RulesPath, nil)
	if err != nil {
		return false
	}
	req.Header.Set("Authorization", "Bearer "+key)
	req.Header.Set("Accept", "application/json")
	c.mu.RLock()
	etag := c.etag
	c.mu.RUnlock()
	if etag != "" {
		req.Header.Set("If-None-Match", etag)
	}
	resp, err := c.httpClient().Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotModified {
		c.markReady()
		return true
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return false
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxBodyBytes))
	if err != nil {
		return false
	}
	var raw any
	if json.Unmarshal(data, &raw) != nil {
		return false
	}
	body, isObject := raw.(map[string]any)
	if !isObject {
		return false
	}
	rawFlags, isList := body["flags"].([]any)
	if !isList {
		return false
	}
	flags := make(map[string]map[string]any, len(rawFlags))
	for _, f := range rawFlags {
		// A flag that does not validate is left out: its callers get their default.
		if len(validateFlag(f)) > 0 {
			continue
		}
		fm := f.(map[string]any)
		flags[fm["key"].(string)] = fm
	}
	segments := []any{}
	if rawSegments, ok := body["segments"].([]any); ok {
		for _, s := range rawSegments {
			if len(ValidateSegment(s)) == 0 {
				segments = append(segments, s)
			}
		}
	}
	version, _ := body["version"].(string)
	c.mu.Lock()
	c.flags = flags
	c.segments = segments
	c.etag = resp.Header.Get("ETag")
	c.version = version
	c.mu.Unlock()
	c.markReady()
	return true
}

// ---------------------------------------------------------- evaluation

// sameKind reports whether a served value can stand in for the default.
func sameKind(value, def any) bool {
	switch normalizeScalar(def).(type) {
	case nil:
		return true
	case bool:
		_, ok := value.(bool)
		return ok
	case float64:
		_, ok := value.(float64)
		return ok
	case string:
		_, ok := value.(string)
		return ok
	}
	// Maps, slices, structs: a JSON object or array.
	switch value.(type) {
	case map[string]any, []any:
		return true
	}
	return false
}

// jsTruthy is JavaScript truthiness for a decoded JSON value.
func jsTruthy(v any) bool {
	switch x := v.(type) {
	case nil:
		return false
	case bool:
		return x
	case string:
		return x != ""
	case float64:
		return x != 0 && !math.IsNaN(x)
	}
	return true
}

func notServed(def any, kind string) Detail {
	return Detail{Value: def, Reason: Reason{Kind: kind}}
}

// GetFlagDetail is the flag's value for this context, with the variation and
// why. def is returned when nothing is served: before rules arrive
// (NOT_READY), for an unknown flag or one scoped to another app
// (FLAG_NOT_FOUND), for a malformed flag (ERROR), when the value is not of
// the default's kind (WRONG_TYPE; a nil default accepts any value), or on any
// error. When a variation is served, shield360.flag.<key> is set to its key
// on the recording span in ctx. Never panics.
func (c *Client) GetFlagDetail(ctx context.Context, key string, evalCtx map[string]any, def any) (detail Detail) {
	defer func() {
		if recover() != nil {
			detail = notServed(def, ReasonError)
		}
	}()
	c.Start()
	if !c.IsReady() {
		return notServed(def, ReasonNotReady)
	}
	c.mu.RLock()
	flag, found := c.flags[key]
	segments := c.segments
	c.mu.RUnlock()
	if !found {
		return notServed(def, ReasonFlagNotFound)
	}
	if appName := flag["appName"]; jsTruthy(appName) {
		if name, ok := appName.(string); !ok || name != c.applicationName() {
			return notServed(def, ReasonFlagNotFound)
		}
	}
	normalized, _ := normalize(evalCtx).(map[string]any)
	result := evaluate(flag, normalized, segments)
	if result.Variation == "" {
		return Detail{Value: def, Reason: result.Reason}
	}
	if !sameKind(result.Value, def) {
		return notServed(def, ReasonWrongType)
	}
	if !c.opts.DisableSpanAttributes && ctx != nil {
		if span := trace.SpanFromContext(ctx); span.IsRecording() {
			span.SetAttributes(attribute.String(SpanAttributePrefix+key, result.Variation))
		}
	}
	return Detail{Value: result.Value, Variation: result.Variation, Reason: result.Reason}
}

// GetFlag is the flag's value for this context, or def. Never panics.
func (c *Client) GetFlag(ctx context.Context, key string, evalCtx map[string]any, def any) any {
	return c.GetFlagDetail(ctx, key, evalCtx, def).Value
}

// GetBool is a boolean flag's value, or def.
func (c *Client) GetBool(ctx context.Context, key string, evalCtx map[string]any, def bool) bool {
	if v, ok := c.GetFlagDetail(ctx, key, evalCtx, def).Value.(bool); ok {
		return v
	}
	return def
}

// GetString is a string flag's value, or def.
func (c *Client) GetString(ctx context.Context, key string, evalCtx map[string]any, def string) string {
	if v, ok := c.GetFlagDetail(ctx, key, evalCtx, def).Value.(string); ok {
		return v
	}
	return def
}

// GetNumber is a number flag's value, or def.
func (c *Client) GetNumber(ctx context.Context, key string, evalCtx map[string]any, def float64) float64 {
	if v, ok := c.GetFlagDetail(ctx, key, evalCtx, def).Value.(float64); ok {
		return v
	}
	return def
}

// GetJSON is a JSON flag's value (decoded: map[string]any, []any, ...), or
// def. A non-nil def must be a map, slice or struct, and then only an object
// or array is served.
func (c *Client) GetJSON(ctx context.Context, key string, evalCtx map[string]any, def any) any {
	return c.GetFlagDetail(ctx, key, evalCtx, def).Value
}

// IsEnabled reports whether a boolean flag is on for this context; false
// until rules arrive, for an unknown flag, or on error.
func (c *Client) IsEnabled(ctx context.Context, key string, evalCtx map[string]any) bool {
	return c.GetBool(ctx, key, evalCtx, false)
}

// ----------------------------------------------------------- AI helpers

// Model is a string flag whose variations are provider/model ids (such as
// "openai/gpt-4o-mini"); def when the flag serves nothing or an empty id.
func (c *Client) Model(ctx context.Context, key string, evalCtx map[string]any, def string) string {
	if v := strings.TrimSpace(c.GetString(ctx, key, evalCtx, def)); v != "" {
		return v
	}
	return def
}

// KillSwitch reports whether the switch is engaged: the feature should stop.
// The flag is a boolean that is true while the feature may run, so the
// switch is engaged when it serves false. Until rules arrive, or on any
// error, the switch is not engaged.
func (c *Client) KillSwitch(ctx context.Context, key string, evalCtx map[string]any) bool {
	return !c.GetBool(ctx, key, evalCtx, true)
}

// PromptRef names a Prompt Hub prompt; an empty Version is the latest.
type PromptRef struct {
	Name    string `json:"name"`
	Version string `json:"version,omitempty"`
}

// PromptOptions configure Prompt's fetch.
type PromptOptions struct {
	// Variables fill the prompt's placeholders when Compile is true.
	Variables map[string]any
	// Compile asks Prompt Hub to fill the variables in (shouldCompile).
	Compile bool
}

// PromptResult is the prompt a flag chose, and what Prompt Hub returned.
type PromptResult struct {
	Name    string
	Version string
	// Variation is the flag's served variation; empty when def was used.
	Variation string
	// Prompt is Prompt Hub's "data"; nil on failure.
	Prompt any
	// Err says what went wrong; empty on success.
	Err string
}

// promptRefOf reads a flag value as a prompt reference: {"name", "version"?}
// or "name" / "name@version".
func promptRefOf(v any) (PromptRef, bool) {
	switch x := v.(type) {
	case map[string]any:
		name, _ := x["name"].(string)
		name = strings.TrimSpace(name)
		if name == "" {
			return PromptRef{}, false
		}
		ref := PromptRef{Name: name}
		switch version := x["version"].(type) {
		case string:
			ref.Version = strings.TrimSpace(version)
		case float64:
			ref.Version, _ = TextOf(version)
		}
		return ref, true
	case string:
		text := strings.TrimSpace(x)
		name, version := text, ""
		if i := strings.LastIndex(text, "@"); i > 0 {
			name, version = strings.TrimSpace(text[:i]), strings.TrimSpace(text[i+1:])
		}
		if name == "" {
			return PromptRef{}, false
		}
		return PromptRef{Name: name, Version: version}, true
	}
	return PromptRef{}, false
}

// Prompt picks a Prompt Hub prompt by flag and fetches it. The flag's value
// is a reference: a JSON object {"name": ..., "version": ...} or a string
// "name" or "name@version". When the flag serves nothing usable, def is
// fetched. Failures are reported in Err; Prompt never panics.
func (c *Client) Prompt(ctx context.Context, key string, evalCtx map[string]any, def PromptRef, opts PromptOptions) (result PromptResult) {
	defer func() {
		if r := recover(); r != nil {
			result.Prompt = nil
			result.Err = "shield360 flags: prompt fetch failed"
		}
	}()
	if ctx == nil {
		ctx = context.Background()
	}
	detail := c.GetFlagDetail(ctx, key, evalCtx, nil)
	ref, ok := promptRefOf(detail.Value)
	if ok && detail.Variation != "" {
		result.Variation = detail.Variation
	} else {
		ref = PromptRef{Name: strings.TrimSpace(def.Name), Version: strings.TrimSpace(def.Version)}
	}
	result.Name, result.Version = ref.Name, ref.Version
	if ref.Name == "" {
		result.Err = "shield360 flags: no prompt name from flag " + strconv.Quote(key) + " or the default"
		return result
	}
	result.Prompt, result.Err = c.fetchPrompt(ctx, ref, opts)
	return result
}

func (c *Client) fetchPrompt(ctx context.Context, ref PromptRef, opts PromptOptions) (any, string) {
	url, key, ok := c.destination()
	if !ok {
		return nil, "shield360 flags: no Shield360 URL and API key (SHIELD360_URL, SHIELD360_API_KEY)"
	}
	variables := opts.Variables
	if variables == nil {
		variables = map[string]any{}
	}
	payload := map[string]any{
		"name":          ref.Name,
		"shouldCompile": opts.Compile,
		"variables":     variables,
		"source":        "go-sdk",
	}
	if ref.Version != "" {
		payload["version"] = ref.Version
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return nil, "shield360 flags: prompt variables are not JSON"
	}
	ctx, cancel := context.WithTimeout(ctx, c.timeout())
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url+PromptPath, bytes.NewReader(body))
	if err != nil {
		return nil, "shield360 flags: bad Shield360 URL"
	}
	req.Header.Set("Authorization", "Bearer "+key)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	resp, err := c.httpClient().Do(req)
	if err != nil {
		return nil, "shield360 flags: prompt request failed"
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return nil, "shield360 flags: prompt request answered HTTP " + strconv.Itoa(resp.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxBodyBytes))
	if err != nil {
		return nil, "shield360 flags: prompt response could not be read"
	}
	var decoded map[string]any
	if json.Unmarshal(data, &decoded) != nil || decoded == nil {
		return nil, "shield360 flags: prompt response is not a JSON object"
	}
	if e, ok := decoded["err"].(string); ok && e != "" {
		return nil, e
	}
	if decoded["data"] == nil {
		return nil, "shield360 flags: prompt response has no data"
	}
	return decoded["data"], ""
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}
