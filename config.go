package shield360

import (
	"os"
	"strings"
	"time"

	"github.com/ThinkfleetAI/shield360-go/rasp"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
)

// Config holds the configuration for Shield360 SDK initialization
type Config struct {
	// OtlpEndpoint is the OTLP endpoint for sending traces, metrics and logs.
	// Default: OTEL_EXPORTER_OTLP_ENDPOINT; else, with a Shield360 URL and API
	// key, <Shield360URL>/api/ingest/otlp with the key as bearer; else
	// "http://127.0.0.1:4318".
	OtlpEndpoint string

	// OtlpHeaders are additional headers to send with OTLP requests
	OtlpHeaders map[string]string

	// Environment identifies the deployment environment
	// Default: "default"
	Environment string

	// ApplicationName is the name of your application
	// Default: "default"
	ApplicationName string

	// SHIELD: Shield360URL is Shield360's base URL, for feature flags (Flags()) and
	// Prompt Hub. Default: SHIELD360_URL.
	Shield360URL string

	// Shield360APIKey is the environment's API key for Shield360URL.
	// Default: SHIELD360_API_KEY.
	Shield360APIKey string

	// TracerName is the name for the tracer provider
	// Default: "shield360"
	TracerName string

	// ServiceVersion is the version of your service
	ServiceVersion string

	// DisableTracing disables trace collection
	// Default: false
	DisableTracing bool

	// DisableMetrics disables metrics collection
	// Default: false
	DisableMetrics bool

	// DisableBatch disables batch processing for exports
	// Default: false
	DisableBatch bool

	// TraceExporterTimeout is the timeout for trace exports
	// Default: 10 seconds
	TraceExporterTimeout time.Duration

	// MetricExporterTimeout is the timeout for metric exports
	// Default: 10 seconds
	MetricExporterTimeout time.Duration

	// MetricExportInterval is the interval for metric exports
	// Default: 30 seconds
	MetricExportInterval time.Duration

	// PricingInfo contains custom pricing information for models
	PricingInfo map[string]ModelPricing

	// PricingEndpoint is the endpoint to fetch pricing information
	// Default: none; pricing is not fetched unless an endpoint is set
	PricingEndpoint string

	// DisablePricingFetch disables automatic pricing information fetching
	DisablePricingFetch bool

	// CaptureMessageContent records prompt/completion text as span attributes.
	// Default: false — no content is captured unless asked for, here or with
	// OTEL_INSTRUMENTATION_GENAI_CAPTURE_MESSAGE_CONTENT=true (matching the
	// Python and TypeScript SDKs). A Shield360 organisation stores content only
	// when its Data retention setting allows it, whatever is sent.
	CaptureMessageContent bool

	// DisableCaptureMessageContent prevents prompt/completion text from being
	// recorded, and wins over CaptureMessageContent and the environment.
	// Kept for compatibility; content is off by default.
	DisableCaptureMessageContent bool

	// DetailedTracing enables detailed component-level tracing.
	// Default: false
	DetailedTracing bool

	// IDGenerator overrides the default OTel ID generator. Use this when
	// callers need deterministic trace/span IDs (e.g. the shield360 CLI's
	// coding-agent hook deriving a stable TraceId from a session id so
	// every span emitted across separate hook invocations lands in the
	// same trace). When nil, OTel's random generator is used.
	IDGenerator sdktrace.IDGenerator

	// Sampler overrides the default head sampler. When nil, the SDK
	// uses AlwaysSample — every span emitted reaches the collector.
	// Callers wanting a head-sampling strategy (e.g. drop noisy
	// `coding_agent.tool.requested` events) can pass a
	// ParentBasedSampler or a custom span-name aware sampler here.
	// See cli/internal/otlp/sampler.go for an example.
	Sampler sdktrace.Sampler

	// ExtraResourceAttributes are merged into the OTel Resource set on
	// every span/metric this SDK emits. Callers use this to attach
	// stable identity (e.g. `gen_ai.user.name`, `host.name`) once at
	// startup rather than tagging each span individually.
	ExtraResourceAttributes map[string]string

	// CaptureCodeLocation records the application call site on GenAI spans
	// as code.function.name, code.file.path and code.line.number. Nil means
	// on unless SHIELD360_CAPTURE_CODE_LOCATION is false/0/no/off; a value
	// set here wins over the environment.
	CaptureCodeLocation *bool

	// CaptureCallLocation also records the call site on the app's outbound
	// calls: database, HTTP, RPC and messaging client (and producer) spans,
	// so Shield360 can price the costly code patterns shield360 scan finds.
	// Nil means on unless SHIELD360_CAPTURE_CALL_LOCATION is false/0/no/off;
	// it has no effect when CaptureCodeLocation is off.
	CaptureCallLocation *bool

	// CodeRoot is stripped from code.file.path to make it repo-relative.
	// Default: SHIELD360_CODE_ROOT, then the main module path (-trimpath
	// builds) or the working directory.
	CodeRoot string

	// CodeLocationIgnoreModules lists extra module path prefixes whose
	// frames are never reported as the call site (e.g. your own wrapper
	// around the instrumented client).
	CodeLocationIgnoreModules []string

	// SHIELD: CaptureLogs sends the application's own log/slog records to
	// Shield360 as OpenTelemetry logs, on the same endpoint and headers as
	// traces (signal path /v1/logs). Nil means off unless
	// SHIELD360_CAPTURE_LOGS is true/1/yes/on; a value set here wins. See
	// LogHandler and CaptureLogs.
	CaptureLogs *bool

	// LogLevel is the lowest level sent when CaptureLogs is on: trace,
	// debug, info, warn, error or fatal. Default: SHIELD360_LOG_LEVEL, then info.
	LogLevel string

	// SHIELD: Rasp turns on runtime application self-protection (the rasp
	// package) unless Rasp.Disabled is set. Nil leaves it off unless
	// SHIELD360_RASP=monitor|block; SHIELD360_RASP=off always wins. Events
	// and the signed config use Shield360URL and Shield360APIKey.
	Rasp *rasp.Options

	// SHIELD: DisableRuntimePackages stops the runtime package report: the
	// names and versions of the modules the binary was built with (never
	// paths), sent to Shield360URL so it can match them against
	// vulnerability data. On by default with a Shield360 URL and API key;
	// SHIELD360_RUNTIME_PACKAGES=off also turns it off.
	DisableRuntimePackages bool
}

// ModelPricing represents pricing information for a model
type ModelPricing struct {
	InputCostPerToken  float64
	OutputCostPerToken float64
}

// setDefaults sets default values for the configuration
func (c *Config) setDefaults() {
	c.resolveDestination(os.Getenv)
	if c.OtlpEndpoint == "" {
		c.OtlpEndpoint = "http://127.0.0.1:4318"
	}

	if c.Environment == "" {
		c.Environment = "default"
	}

	if c.ApplicationName == "" {
		c.ApplicationName = "default"
	}

	if c.TracerName == "" {
		c.TracerName = "shield360"
	}

	if c.TraceExporterTimeout == 0 {
		c.TraceExporterTimeout = 10 * time.Second
	}

	if c.MetricExporterTimeout == 0 {
		c.MetricExporterTimeout = 10 * time.Second
	}

	if c.MetricExportInterval == 0 {
		c.MetricExportInterval = 30 * time.Second
	}

	// SHIELD: no default pricing endpoint; fetch only when one is configured.
	if c.PricingEndpoint == "" {
		c.DisablePricingFetch = true
	}

	if c.PricingInfo == nil {
		c.PricingInfo = make(map[string]ModelPricing)
	}

	if c.OtlpHeaders == nil {
		c.OtlpHeaders = make(map[string]string)
	}
}

// IngestPath is the platform's authenticated OTLP ingest route.
const IngestPath = "/api/ingest/otlp"

// SHIELD: resolveDestination picks the OTLP endpoint when none was given, as
// the Python and TypeScript SDKs do: OTEL_EXPORTER_OTLP_ENDPOINT, else a
// Shield360 URL and API key resolve to the platform's ingest route with the
// key as the bearer token. An explicit endpoint always wins, and an explicit
// Authorization header is never overwritten.
func (c *Config) resolveDestination(getenv func(string) string) {
	if strings.TrimSpace(c.OtlpEndpoint) != "" {
		return
	}
	if env := strings.TrimSpace(getenv("OTEL_EXPORTER_OTLP_ENDPOINT")); env != "" {
		c.OtlpEndpoint = env
		return
	}
	url := strings.TrimRight(strings.TrimSpace(firstNonEmpty(c.Shield360URL, getenv("SHIELD360_URL"))), "/")
	key := strings.TrimSpace(firstNonEmpty(c.Shield360APIKey, getenv("SHIELD360_API_KEY")))
	if url == "" || key == "" {
		return
	}
	c.OtlpEndpoint = url + IngestPath
	for name := range c.OtlpHeaders {
		if strings.EqualFold(name, "Authorization") {
			return
		}
	}
	if c.OtlpHeaders == nil {
		c.OtlpHeaders = make(map[string]string)
	}
	c.OtlpHeaders["Authorization"] = "Bearer " + key
}
