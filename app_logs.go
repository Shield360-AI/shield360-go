package shield360

// SHIELD: application logs to Shield360, when asked for.
//
// Shield360 ingests OTLP logs on the same per-API-key route as traces. The
// slog handler here writes OpenTelemetry log records through the SDK's own
// LoggerProvider, so they go to the same endpoint (signal path /v1/logs) with
// the same headers and resource as the spans, and carry the trace and span ids
// of the span in the context passed to the logging call.
//
// Nothing is sent unless it is turned on: Config.CaptureLogs, the
// SHIELD360_CAPTURE_LOGS environment variable, or a call to CaptureLogs().
// The Python SDK (shield360/otel/app_logs.py) is the reference: the same
// severities, attribute names, own-logger exclusion and masking.

import (
	"context"
	"errors"
	"fmt"
	"github.com/ThinkfleetAI/shield360-go/internal/masking"
	"io"
	stdlog "log"
	"log/slog"
	"os"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"go.opentelemetry.io/otel/attribute"
	otellog "go.opentelemetry.io/otel/log"
)

const (
	// DefaultLogLevel is the lowest level sent when application logs are on.
	DefaultLogLevel = "info"
	// DefaultLoggerName is the instrumentation scope of records from LogHandler("").
	DefaultLoggerName = "app"
	// DefaultLogsPerSecond is the most records a handler sends a second.
	DefaultLogsPerSecond = 500

	maxLogBodyChars       = 16384
	maxLogStacktraceChars = 16384
	maxLogAttrChars       = 4096
)

// Severity numbers and short names of the OpenTelemetry log data model.
var severityText = map[otellog.Severity]string{
	otellog.SeverityTrace: "TRACE",
	otellog.SeverityDebug: "DEBUG",
	otellog.SeverityInfo:  "INFO",
	otellog.SeverityWarn:  "WARN",
	otellog.SeverityError: "ERROR",
	otellog.SeverityFatal: "FATAL",
}

var levelNames = map[string]otellog.Severity{
	"trace":    otellog.SeverityTrace,
	"debug":    otellog.SeverityDebug,
	"info":     otellog.SeverityInfo,
	"warn":     otellog.SeverityWarn,
	"warning":  otellog.SeverityWarn,
	"error":    otellog.SeverityError,
	"fatal":    otellog.SeverityFatal,
	"critical": otellog.SeverityFatal,
}

// ResolveLogLevel turns a level name ("info", "WARN", "critical") into the
// lowest severity sent; empty or unknown names are INFO.
func ResolveLogLevel(name string) otellog.Severity {
	key := strings.ToLower(strings.TrimSpace(name))
	if key == "" {
		return otellog.SeverityInfo
	}
	if s, ok := levelNames[key]; ok {
		return s
	}
	stdlog.Printf("shield360: unknown log level %q; using INFO", name)
	return otellog.SeverityInfo
}

// slogSeverity maps a slog level to an OpenTelemetry severity: below Debug is
// TRACE, Debug DEBUG, Info INFO, Warn WARN, Error ERROR, above Error FATAL.
func slogSeverity(l slog.Level) otellog.Severity {
	switch {
	case l < slog.LevelDebug:
		return otellog.SeverityTrace
	case l < slog.LevelInfo:
		return otellog.SeverityDebug
	case l < slog.LevelWarn:
		return otellog.SeverityInfo
	case l < slog.LevelError:
		return otellog.SeverityWarn
	case l == slog.LevelError:
		return otellog.SeverityError
	default:
		return otellog.SeverityFatal
	}
}

// resolveCaptureLogs: the config, else SHIELD360_CAPTURE_LOGS, else off.
func resolveCaptureLogs(cfg Config) bool {
	if cfg.CaptureLogs != nil {
		return *cfg.CaptureLogs
	}
	switch strings.ToLower(strings.TrimSpace(os.Getenv("SHIELD360_CAPTURE_LOGS"))) {
	case "true", "1", "yes", "on":
		return true
	}
	return false
}

// resolveLogLevel: the config, else SHIELD360_LOG_LEVEL, else info.
func resolveLogLevel(cfg Config) string {
	if strings.TrimSpace(cfg.LogLevel) != "" {
		return cfg.LogLevel
	}
	return os.Getenv("SHIELD360_LOG_LEVEL")
}

// ------------------------------------------------------------------ masking

func truncRunes(s string, n int) string {
	if utf8.RuneCountInString(s) <= n {
		return s
	}
	i := 0
	for pos := range s {
		if i == n {
			return s[:pos]
		}
		i++
	}
	return s
}

// MaskLogText is at most max characters of s, masked by the contract every
// SDK shares (sdk/rasp/README.md, "Masking") before it is cut: credential
// pairs, bearer credentials and opaque tokens are masked; readable
// identifiers such as class names and file paths survive.
func MaskLogText(s string, max int) string {
	return masking.Text(s, max)
}

// ------------------------------------------------------------------ limiter

type logLimiter struct {
	mu          sync.Mutex
	max         int
	windowStart time.Time
	count       int
	now         func() time.Time
}

func newLogLimiter(max int) *logLimiter {
	if max <= 0 {
		max = DefaultLogsPerSecond
	}
	return &logLimiter{max: max, now: time.Now}
}

func (l *logLimiter) allow() bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	t := l.now()
	if t.Sub(l.windowStart) >= time.Second {
		l.windowStart = t
		l.count = 0
	}
	l.count++
	return l.count <= l.max
}

// -------------------------------------------------------------- global state

var appLogs struct {
	mu       sync.RWMutex
	provider otellog.LoggerProvider // nil: application logs are off
	level    otellog.Severity

	installed  bool
	prevLogger *slog.Logger
	prevWriter io.Writer
	prevFlags  int
}

func currentAppLogs() (otellog.LoggerProvider, otellog.Severity) {
	appLogs.mu.RLock()
	defer appLogs.mu.RUnlock()
	return appLogs.provider, appLogs.level
}

// the SDK's LoggerProvider, set by Init and cleared by Shutdown.
var sdkLoggerProvider struct {
	mu sync.Mutex
	p  otellog.LoggerProvider
}

func setSDKLoggerProvider(p otellog.LoggerProvider) {
	sdkLoggerProvider.mu.Lock()
	sdkLoggerProvider.p = p
	sdkLoggerProvider.mu.Unlock()
}

// CaptureLogs sends slog records at level ("info" by default) and above to
// Shield360: the handlers LogHandler returns start sending, and slog.Default
// (and with it the log package) also forwards, its output still going where it
// went before. Calling it again changes the level. Call it after Init; it
// returns false when Init has not set up a LoggerProvider.
func CaptureLogs(level string) bool {
	sdkLoggerProvider.mu.Lock()
	p := sdkLoggerProvider.p
	sdkLoggerProvider.mu.Unlock()
	if p == nil {
		stdlog.Printf("shield360: CaptureLogs needs Init first; application logs are not sent")
		return false
	}
	enableAppLogs(p, ResolveLogLevel(level), true)
	return true
}

// enableAppLogs turns application logs on through p; with installDefault the
// slog default logger forwards too.
func enableAppLogs(p otellog.LoggerProvider, level otellog.Severity, installDefault bool) {
	appLogs.mu.Lock()
	defer appLogs.mu.Unlock()
	appLogs.provider = p
	appLogs.level = level
	if !installDefault || appLogs.installed {
		return
	}
	prev := slog.Default()
	appLogs.prevLogger = prev
	appLogs.prevWriter = stdlog.Writer()
	appLogs.prevFlags = stdlog.Flags()
	primary := prev.Handler()
	if isBuiltinDefault(primary) {
		// The built-in handler writes through the log package, which
		// slog.SetDefault redirects into the new handler: wrapping it would
		// loop. A handler that writes the same lines to the same writer
		// takes its place.
		primary = &classicHandler{out: stdlog.New(appLogs.prevWriter, stdlog.Prefix(), appLogs.prevFlags), level: slog.LevelInfo}
	}
	slog.SetDefault(slog.New(&fanoutHandler{handlers: []slog.Handler{primary, LogHandler(DefaultLoggerName)}}))
	appLogs.installed = true
}

// StopCapturingLogs stops sending application logs and puts slog.Default and
// the log package back as they were.
func StopCapturingLogs() {
	appLogs.mu.Lock()
	defer appLogs.mu.Unlock()
	appLogs.provider = nil
	appLogs.level = otellog.SeverityInfo
	if !appLogs.installed {
		return
	}
	stdlog.SetOutput(appLogs.prevWriter)
	stdlog.SetFlags(appLogs.prevFlags)
	slog.SetDefault(appLogs.prevLogger)
	appLogs.installed = false
	appLogs.prevLogger, appLogs.prevWriter = nil, nil
}

func isBuiltinDefault(h slog.Handler) bool {
	return fmt.Sprintf("%T", h) == "*slog.defaultHandler"
}

// ------------------------------------------------------------------ handler

// LogHandlerOptions configures NewLogHandler.
type LogHandlerOptions struct {
	// Name is the instrumentation scope; "app" by default.
	Name string
	// LoggerProvider receives the records. Nil follows the SDK: records go
	// through Init's LoggerProvider while application logs are on
	// (Config.CaptureLogs, SHIELD360_CAPTURE_LOGS or CaptureLogs) and
	// nowhere otherwise.
	LoggerProvider otellog.LoggerProvider
	// Level is the lowest level sent with an explicit LoggerProvider
	// ("info" by default). With the SDK's provider the SDK's level applies.
	Level string
	// MaxPerSecond caps the records sent a second (default 500); the rest
	// are dropped.
	MaxPerSecond int
}

// LogHandler is a log/slog Handler whose records go to Shield360 as
// OpenTelemetry log records when application logs are on, and nowhere
// otherwise, so a library can build one at start-up without deciding for the
// application:
//
//	logger := slog.New(shield360.LogHandler("checkout"))
//
// Records carry the trace and span ids of the span in the context passed to
// the logging call (slog.InfoContext), masked text, and the call site.
type logHandler struct {
	scope    string
	provider otellog.LoggerProvider // nil: the SDK's, read per record
	level    otellog.Severity
	limiter  *logLimiter
	attrs    []slog.Attr // already prefixed with their groups
	group    string      // dotted prefix for later attributes

	loggerOnce sync.Once
	logger     otellog.Logger
}

// LogHandler returns a slog handler sending to Shield360 through the SDK's
// LoggerProvider under scope name ("app" when empty); see logHandler.
func LogHandler(name string) slog.Handler {
	return NewLogHandler(LogHandlerOptions{Name: name})
}

// NewLogHandler returns a slog handler sending to Shield360 with these options.
func NewLogHandler(opts LogHandlerOptions) slog.Handler {
	scope := opts.Name
	if scope == "" {
		scope = DefaultLoggerName
	}
	level := otellog.SeverityInfo
	if opts.Level != "" {
		level = ResolveLogLevel(opts.Level)
	}
	return &logHandler{scope: scope, provider: opts.LoggerProvider, level: level, limiter: newLogLimiter(opts.MaxPerSecond)}
}

// isOwnScope: the SDK's and OpenTelemetry's own loggers are never exported.
func isOwnScope(name string) bool {
	for _, own := range []string{"shield360", "opentelemetry", "go.opentelemetry.io", "github.com/Shield360-AI/Shield360"} {
		if name == own || strings.HasPrefix(name, own+".") || strings.HasPrefix(name, own+"/") {
			return true
		}
	}
	return false
}

// ownMessage: the SDK's own lines (log.Printf("Shield360 initialized …"),
// "shield360: …") reach slog through the log package once slog.Default
// forwards; they are never exported.
var ownMessage = regexp.MustCompile(`(?i)^(shield360[\s:]|\[shield360\]|otel:|otlp)`)

type emittingKey struct{}

func (h *logHandler) target() (otellog.Logger, otellog.Severity, bool) {
	if h.provider != nil {
		h.loggerOnce.Do(func() { h.logger = h.provider.Logger(h.scope) })
		return h.logger, h.level, true
	}
	p, level := currentAppLogs()
	if p == nil {
		return nil, 0, false
	}
	return p.Logger(h.scope), level, true
}

func (h *logHandler) Enabled(_ context.Context, l slog.Level) bool {
	if isOwnScope(h.scope) {
		return false
	}
	_, min, ok := h.target()
	return ok && slogSeverity(l) >= min
}

func (h *logHandler) Handle(ctx context.Context, r slog.Record) (err error) {
	// Logging never fails or panics into the application.
	defer func() {
		_ = recover()
		err = nil
	}()
	if ctx == nil {
		ctx = context.Background()
	}
	// A record written while another is being written (an exporter that
	// logs with the context it was given) cannot feed itself.
	if ctx.Value(emittingKey{}) != nil || isOwnScope(h.scope) || ownMessage.MatchString(r.Message) {
		return nil
	}
	logger, min, ok := h.target()
	if !ok {
		return nil
	}
	sev := slogSeverity(r.Level)
	if sev < min || !h.limiter.allow() {
		return nil
	}

	var rec otellog.Record
	ts := r.Time
	if ts.IsZero() {
		ts = time.Now()
	}
	rec.SetTimestamp(ts)
	rec.SetObservedTimestamp(time.Now())
	rec.SetSeverity(sev)
	rec.SetSeverityText(severityText[sev])
	rec.SetBody(attribute.StringValue(MaskLogText(r.Message, maxLogBodyChars)))

	b := &attrBuilder{}
	if r.PC != 0 {
		frame, _ := runtime.CallersFrames([]uintptr{r.PC}).Next()
		if frame.File != "" {
			b.kvs = append(b.kvs,
				attribute.String("code.file.path", frame.File),
				attribute.String("code.function.name", frame.Function),
				attribute.Int64("code.line.number", int64(frame.Line)))
		}
	}
	for _, a := range h.attrs {
		b.add("", a)
	}
	r.Attrs(func(a slog.Attr) bool {
		b.add(h.group, a)
		return true
	})
	rec.AddAttributes(b.kvs...)

	logger.Emit(context.WithValue(ctx, emittingKey{}, true), rec)
	return nil
}

func (h *logHandler) clone() *logHandler {
	return &logHandler{
		scope:    h.scope,
		provider: h.provider,
		level:    h.level,
		limiter:  h.limiter,
		attrs:    append([]slog.Attr(nil), h.attrs...),
		group:    h.group,
	}
}

func (h *logHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	c := h.clone()
	for _, a := range attrs {
		if h.group != "" {
			a.Key = h.group + a.Key
		}
		c.attrs = append(c.attrs, a)
	}
	return c
}

func (h *logHandler) WithGroup(name string) slog.Handler {
	if name == "" {
		return h
	}
	c := h.clone()
	c.group = h.group + name + "."
	return c
}

// attrBuilder flattens slog attributes into OpenTelemetry ones: groups become
// dotted keys, the first error becomes exception.type / exception.message,
// strings are cut and masked.
type attrBuilder struct {
	kvs       []attribute.KeyValue
	exception bool
}

func (b *attrBuilder) add(prefix string, a slog.Attr) {
	a.Value = a.Value.Resolve()
	if a.Equal(slog.Attr{}) {
		return
	}
	key := prefix + a.Key
	v := a.Value
	// A value named like a credential (password, x-api-key, user.sessionId)
	// is masked whole, whatever its kind.
	if v.Kind() != slog.KindGroup && !unmaskedAttr(key) && masking.IsSensitiveKey(key) {
		b.kvs = append(b.kvs, attribute.String(key, masking.Mask))
		return
	}
	switch v.Kind() {
	case slog.KindGroup:
		p := prefix
		if a.Key != "" {
			p = key + "."
		}
		for _, g := range v.Group() {
			b.add(p, g)
		}
	case slog.KindString:
		b.kvs = append(b.kvs, attribute.String(key, maskAttr(key, v.String())))
	case slog.KindInt64:
		b.kvs = append(b.kvs, attribute.Int64(key, v.Int64()))
	case slog.KindUint64:
		u := v.Uint64()
		if u > 1<<63-1 {
			b.kvs = append(b.kvs, attribute.String(key, fmt.Sprint(u)))
		} else {
			b.kvs = append(b.kvs, attribute.Int64(key, int64(u)))
		}
	case slog.KindFloat64:
		b.kvs = append(b.kvs, attribute.Float64(key, v.Float64()))
	case slog.KindBool:
		b.kvs = append(b.kvs, attribute.Bool(key, v.Bool()))
	case slog.KindDuration:
		b.kvs = append(b.kvs, attribute.String(key, v.Duration().String()))
	case slog.KindTime:
		b.kvs = append(b.kvs, attribute.String(key, v.Time().Format(time.RFC3339Nano)))
	default:
		any := v.Any()
		if e, ok := any.(error); ok && !b.exception {
			b.exception = true
			b.kvs = append(b.kvs,
				attribute.String("exception.type", errorType(e)),
				attribute.String("exception.message", MaskLogText(e.Error(), maxLogAttrChars)))
			return
		}
		if list, ok := stringList(any); ok {
			values := make([]attribute.Value, len(list))
			for i, item := range list {
				values[i] = attribute.StringValue(maskAttr(key, item))
			}
			b.kvs = append(b.kvs, attribute.Slice(key, values...))
			return
		}
		var text string
		switch x := any.(type) {
		case []byte:
			text = string(x)
		case error:
			text = x.Error()
		case fmt.Stringer:
			text = x.String()
		default:
			text = fmt.Sprintf("%+v", x)
		}
		b.kvs = append(b.kvs, attribute.String(key, maskAttr(key, text)))
	}
}

// unmaskedAttr: the call site and the exception type are never masked.
func unmaskedAttr(key string) bool {
	return strings.HasPrefix(key, "code.") || key == "exception.type"
}

// stringList is a list of strings or of string-like values, masked item by item.
func stringList(v any) ([]string, bool) {
	switch x := v.(type) {
	case []string:
		return x, true
	case []any:
		out := make([]string, 0, len(x))
		for _, item := range x {
			s, ok := item.(string)
			if !ok {
				return nil, false
			}
			out = append(out, s)
		}
		return out, true
	}
	return nil, false
}

func maskAttr(key, s string) string {
	if unmaskedAttr(key) {
		return truncRunes(s, maxLogAttrChars)
	}
	if key == "exception.stacktrace" {
		return MaskLogText(s, maxLogStacktraceChars)
	}
	return MaskLogText(s, maxLogAttrChars)
}

// errorType names an error's type the way Go prints it (*fs.PathError),
// unwrapping fmt.Errorf wrappers to the innermost cause.
func errorType(e error) string {
	for {
		next := errors.Unwrap(e)
		if next == nil {
			break
		}
		e = next
	}
	return fmt.Sprintf("%T", e)
}

// ---------------------------------------------------------------- fan-out

// fanoutHandler sends each record to every handler that wants it. The first
// one's error is returned; the others (Shield360) never fail the call.
type fanoutHandler struct{ handlers []slog.Handler }

func (f *fanoutHandler) Enabled(ctx context.Context, l slog.Level) bool {
	for _, h := range f.handlers {
		if h.Enabled(ctx, l) {
			return true
		}
	}
	return false
}

func (f *fanoutHandler) Handle(ctx context.Context, r slog.Record) error {
	var first error
	for i, h := range f.handlers {
		if !h.Enabled(ctx, r.Level) {
			continue
		}
		if err := h.Handle(ctx, r.Clone()); err != nil && i == 0 {
			first = err
		}
	}
	return first
}

func (f *fanoutHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	out := make([]slog.Handler, len(f.handlers))
	for i, h := range f.handlers {
		out[i] = h.WithAttrs(attrs)
	}
	return &fanoutHandler{handlers: out}
}

func (f *fanoutHandler) WithGroup(name string) slog.Handler {
	out := make([]slog.Handler, len(f.handlers))
	for i, h := range f.handlers {
		out[i] = h.WithGroup(name)
	}
	return &fanoutHandler{handlers: out}
}

// classicHandler writes "LEVEL message k=v" lines through a log.Logger, as
// slog's built-in default handler does, for when that handler is replaced.
type classicHandler struct {
	out   *stdlog.Logger
	level slog.Leveler
	attrs []slog.Attr
	group string
}

func (c *classicHandler) Enabled(_ context.Context, l slog.Level) bool { return l >= c.level.Level() }

func (c *classicHandler) Handle(_ context.Context, r slog.Record) error {
	var sb strings.Builder
	sb.WriteString(r.Level.String())
	sb.WriteByte(' ')
	sb.WriteString(r.Message)
	var write func(prefix string, a slog.Attr)
	write = func(prefix string, a slog.Attr) {
		a.Value = a.Value.Resolve()
		if a.Equal(slog.Attr{}) {
			return
		}
		if a.Value.Kind() == slog.KindGroup {
			p := prefix
			if a.Key != "" {
				p = prefix + a.Key + "."
			}
			for _, g := range a.Value.Group() {
				write(p, g)
			}
			return
		}
		sb.WriteByte(' ')
		sb.WriteString(prefix + a.Key)
		sb.WriteByte('=')
		sb.WriteString(a.Value.String())
	}
	for _, a := range c.attrs {
		write("", a)
	}
	r.Attrs(func(a slog.Attr) bool {
		write(c.group, a)
		return true
	})
	return c.out.Output(0, sb.String())
}

func (c *classicHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	n := *c
	n.attrs = append([]slog.Attr(nil), c.attrs...)
	for _, a := range attrs {
		a.Key = c.group + a.Key
		n.attrs = append(n.attrs, a)
	}
	return &n
}

func (c *classicHandler) WithGroup(name string) slog.Handler {
	if name == "" {
		return c
	}
	n := *c
	n.group = c.group + name + "."
	return &n
}
