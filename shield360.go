// Package shield360 provides OpenTelemetry-native observability for LLM applications in Go.
// It offers automatic instrumentation for popular LLM providers like OpenAI and Anthropic.
package shield360

import (
	"context"
	"fmt"
	"log"
	"os"
	"strings"
	"sync"

	"github.com/ThinkfleetAI/shield360-go/flags"
	"github.com/ThinkfleetAI/shield360-go/helpers"
	"github.com/ThinkfleetAI/shield360-go/rasp"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/otlp/otlplog/otlploghttp"
	"go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetrichttp"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/propagation"
	sdklog "go.opentelemetry.io/otel/sdk/log"
	"go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/resource"
	"go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.26.0"
)

var (
	globalConfig   *Config
	globalShutdown func(context.Context) error
	initMutex      sync.Mutex
	isInitialized  bool
	tracerProvider *trace.TracerProvider
	meterProvider  *metric.MeterProvider
	loggerProvider *sdklog.LoggerProvider // SHIELD: application logs
)

// Init initializes the Shield360 SDK with the provided configuration.
// This should be called once at application startup.
//
// Example:
//
//	err := shield360.Init(shield360.Config{
//	    OtlpEndpoint:    "http://127.0.0.1:4318",
//	    Environment:     "production",
//	    ApplicationName: "my-go-app",
//	})
//	if err != nil {
//	    log.Fatalf("Failed to initialize Shield360: %v", err)
//	}
//	defer shield360.Shutdown(context.Background())
func Init(cfg Config) error {
	initMutex.Lock()
	defer initMutex.Unlock()

	if isInitialized {
		return fmt.Errorf("Shield360 is already initialized")
	}

	// Set default values
	cfg.setDefaults()
	globalConfig = &cfg

	// Initialize pricing cache with user config
	customPricing := make(map[string]helpers.PricingInfo)
	for model, p := range cfg.PricingInfo {
		customPricing[model] = helpers.PricingInfo{
			InputCostPerToken:  p.InputCostPerToken,
			OutputCostPerToken: p.OutputCostPerToken,
		}
	}
	helpers.InitGlobalPricingCache(cfg.PricingEndpoint, cfg.DisablePricingFetch, customPricing)

	// Content is captured only when asked for (see Config.CaptureMessageContent).
	helpers.SetCaptureMessageContent(captureMessageContent(cfg))

	// SHIELD: feature flags fall back to these settings (see Flags()).
	flags.SetDefaults(flags.Defaults{URL: cfg.Shield360URL, APIKey: cfg.Shield360APIKey, ApplicationName: cfg.ApplicationName})

	// Create resource
	res, err := newResource(cfg)
	if err != nil {
		return fmt.Errorf("failed to create resource: %w", err)
	}

	// Initialize tracer provider
	if !cfg.DisableTracing {
		tp, err := newTracerProvider(res, cfg)
		if err != nil {
			return fmt.Errorf("failed to create tracer provider: %w", err)
		}
		tracerProvider = tp
		otel.SetTracerProvider(tp)
	}

	// Initialize meter provider
	if !cfg.DisableMetrics {
		mp, err := newMeterProvider(res, cfg)
		if err != nil {
			return fmt.Errorf("failed to create meter provider: %w", err)
		}
		meterProvider = mp
		otel.SetMeterProvider(mp)
	}

	// SHIELD: the LoggerProvider for application logs, on the same endpoint,
	// headers and resource as traces. Records are sent only once application
	// logs are on (Config.CaptureLogs, SHIELD360_CAPTURE_LOGS or CaptureLogs()).
	if lp, err := newLoggerProvider(res, cfg); err != nil {
		log.Printf("shield360: application logs unavailable: %v", err)
	} else {
		loggerProvider = lp
		setSDKLoggerProvider(lp)
		if resolveCaptureLogs(cfg) {
			enableAppLogs(lp, ResolveLogLevel(resolveLogLevel(cfg)), true)
		}
	}

	// Set global propagator
	otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(
		propagation.TraceContext{},
		propagation.Baggage{},
	))

	// SHIELD: runtime SCA — names and versions of the modules the binary
	// runs, on unless Config.DisableRuntimePackages or
	// SHIELD360_RUNTIME_PACKAGES=off. Started before RASP, which then leaves
	// its own components report to it.
	StartRuntimePackages(RuntimePackagesOptions{
		URL:             firstNonEmpty(cfg.Shield360URL, os.Getenv("SHIELD360_URL")),
		APIKey:          firstNonEmpty(cfg.Shield360APIKey, os.Getenv("SHIELD360_API_KEY")),
		ApplicationName: cfg.ApplicationName,
		Environment:     cfg.Environment,
		SDKVersion:      Version,
		Disabled:        cfg.DisableRuntimePackages,
	})

	// SHIELD: runtime protection (RASP); never fails Init.
	rasp.Init(cfg.Rasp, rasp.InitContext{
		ApplicationName: cfg.ApplicationName,
		Environment:     cfg.Environment,
		URL:             firstNonEmpty(cfg.Shield360URL, os.Getenv("SHIELD360_URL")),
		APIKey:          firstNonEmpty(cfg.Shield360APIKey, os.Getenv("SHIELD360_API_KEY")),
		SDKVersion:      Version,
		OtlpEndpoint:    cfg.OtlpEndpoint,
	})

	// Set up shutdown function
	globalShutdown = func(ctx context.Context) error {
		rasp.Shutdown(ctx)    // SHIELD: send queued RASP events
		StopRuntimePackages() // SHIELD: runtime SCA
		var err error
		// SHIELD: stop forwarding application logs, then send what is queued.
		StopCapturingLogs()
		setSDKLoggerProvider(nil)
		if loggerProvider != nil {
			if shutdownErr := loggerProvider.Shutdown(ctx); shutdownErr != nil {
				err = shutdownErr
			}
		}
		if tracerProvider != nil {
			if shutdownErr := tracerProvider.Shutdown(ctx); shutdownErr != nil {
				err = shutdownErr
			}
		}
		if meterProvider != nil {
			if shutdownErr := meterProvider.Shutdown(ctx); shutdownErr != nil {
				if err != nil {
					err = fmt.Errorf("%v; %w", err, shutdownErr)
				} else {
					err = shutdownErr
				}
			}
		}
		return err
	}

	isInitialized = true
	log.Printf("Shield360 initialized successfully (Environment: %s, Application: %s)", cfg.Environment, cfg.ApplicationName)

	return nil
}

// Shutdown gracefully shuts down the Shield360 SDK.
// It should be called before application exit to ensure all telemetry data is flushed.
func Shutdown(ctx context.Context) error {
	initMutex.Lock()
	defer initMutex.Unlock()

	if !isInitialized {
		return nil
	}

	if globalShutdown != nil {
		err := globalShutdown(ctx)
		if err != nil {
			return fmt.Errorf("failed to shutdown Shield360: %w", err)
		}
	}

	isInitialized = false
	globalConfig = nil
	tracerProvider = nil
	meterProvider = nil
	loggerProvider = nil
	globalShutdown = nil

	log.Println("Shield360 shut down successfully")
	return nil
}

// GetConfig returns the current global configuration.
// Returns nil if Shield360 is not initialized.
func GetConfig() *Config {
	initMutex.Lock()
	defer initMutex.Unlock()
	return globalConfig
}

// IsInitialized returns whether Shield360 has been initialized.
func IsInitialized() bool {
	initMutex.Lock()
	defer initMutex.Unlock()
	return isInitialized
}

// newResource creates a new resource with the application metadata
func newResource(cfg Config) (*resource.Resource, error) {
	attrs := []resource.Option{
		resource.WithAttributes(
			semconv.ServiceNameKey.String(cfg.ApplicationName),
			semconv.DeploymentEnvironmentKey.String(cfg.Environment),
			attribute.String("shield360.sdk.version", Version),
		),
	}

	// service.version and vcs.* resolved from config, build info, CI and
	// OTel env. Added after the base attributes so they win.
	if build := resolveBuildAttributes(cfg, os.Getenv, buildRevision()); len(build) > 0 {
		attrs = append(attrs, resource.WithAttributes(build...))
	}

	// Caller-supplied extras (e.g. `gen_ai.user.name`, `host.name`)
	// attach once at SDK init and then ride along on every span. Empty
	// keys/values are skipped so a missing field doesn't pollute the
	// resource map.
	if len(cfg.ExtraResourceAttributes) > 0 {
		extras := make([]attribute.KeyValue, 0, len(cfg.ExtraResourceAttributes))
		for k, v := range cfg.ExtraResourceAttributes {
			if k == "" || v == "" {
				continue
			}
			extras = append(extras, attribute.String(k, v))
		}
		if len(extras) > 0 {
			attrs = append(attrs, resource.WithAttributes(extras...))
		}
	}

	return resource.New(
		context.Background(),
		append(attrs, resource.WithTelemetrySDK())...,
	)
}

// newTracerProvider creates a new tracer provider with OTLP exporter
func newTracerProvider(res *resource.Resource, cfg Config) (*trace.TracerProvider, error) {
	// WithEndpointURL accepts the full URL including scheme, avoiding the
	// host-only limitation of WithEndpoint + WithInsecure.
	opts := []otlptracehttp.Option{
		otlptracehttp.WithEndpointURL(signalEndpointURL(cfg.OtlpEndpoint, "traces")),
		otlptracehttp.WithTimeout(cfg.TraceExporterTimeout),
	}

	if len(cfg.OtlpHeaders) > 0 {
		opts = append(opts, otlptracehttp.WithHeaders(cfg.OtlpHeaders))
	}

	exporter, err := otlptracehttp.New(context.Background(), opts...)
	if err != nil {
		return nil, fmt.Errorf("failed to create trace exporter: %w", err)
	}

	var spanProcessor trace.SpanProcessor
	if cfg.DisableBatch {
		spanProcessor = trace.NewSimpleSpanProcessor(exporter)
	} else {
		spanProcessor = trace.NewBatchSpanProcessor(exporter)
	}

	sampler := cfg.Sampler
	if sampler == nil {
		// Default beta posture: keep every span. Production
		// callers should set Config.Sampler to a head sampler
		// matching their volume budget. See D8 in the
		// coding-agents plan.
		sampler = trace.AlwaysSample()
	}
	tpOpts := []trace.TracerProviderOption{
		trace.WithResource(res),
		trace.WithSpanProcessor(spanProcessor),
		trace.WithSampler(sampler),
	}
	if p := NewCodeLocationProcessor(cfg); p != nil {
		tpOpts = append(tpOpts, trace.WithSpanProcessor(p))
	}
	if cfg.IDGenerator != nil {
		tpOpts = append(tpOpts, trace.WithIDGenerator(cfg.IDGenerator))
	}
	tp := trace.NewTracerProvider(tpOpts...)

	return tp, nil
}

// newLoggerProvider creates the application-logs LoggerProvider with an
// OTLP/HTTP exporter to <endpoint>/v1/logs. The batch processor's queue is
// bounded: when it is full, records are dropped rather than held.
func newLoggerProvider(res *resource.Resource, cfg Config) (*sdklog.LoggerProvider, error) {
	opts := []otlploghttp.Option{
		otlploghttp.WithEndpointURL(signalEndpointURL(cfg.OtlpEndpoint, "logs")),
		otlploghttp.WithTimeout(cfg.TraceExporterTimeout),
	}
	if len(cfg.OtlpHeaders) > 0 {
		opts = append(opts, otlploghttp.WithHeaders(cfg.OtlpHeaders))
	}
	exporter, err := otlploghttp.New(context.Background(), opts...)
	if err != nil {
		return nil, fmt.Errorf("failed to create log exporter: %w", err)
	}
	var processor sdklog.Processor
	if cfg.DisableBatch {
		processor = sdklog.NewSimpleProcessor(exporter)
	} else {
		processor = sdklog.NewBatchProcessor(exporter)
	}
	return sdklog.NewLoggerProvider(sdklog.WithResource(res), sdklog.WithProcessor(processor)), nil
}

// newMeterProvider creates a new meter provider with OTLP exporter
func newMeterProvider(res *resource.Resource, cfg Config) (*metric.MeterProvider, error) {
	opts := []otlpmetrichttp.Option{
		otlpmetrichttp.WithEndpointURL(signalEndpointURL(cfg.OtlpEndpoint, "metrics")),
		otlpmetrichttp.WithTimeout(cfg.MetricExporterTimeout),
	}

	if len(cfg.OtlpHeaders) > 0 {
		opts = append(opts, otlpmetrichttp.WithHeaders(cfg.OtlpHeaders))
	}

	exporter, err := otlpmetrichttp.New(context.Background(), opts...)
	if err != nil {
		return nil, fmt.Errorf("failed to create metric exporter: %w", err)
	}

	reader := metric.NewPeriodicReader(
		exporter,
		metric.WithInterval(cfg.MetricExportInterval),
	)

	mp := metric.NewMeterProvider(
		metric.WithResource(res),
		metric.WithReader(reader),
	)

	return mp, nil
}

// captureMessageContent decides whether prompt/completion text is recorded:
// off unless the config or OTEL_INSTRUMENTATION_GENAI_CAPTURE_MESSAGE_CONTENT
// asks for it, and always off with DisableCaptureMessageContent.
func captureMessageContent(cfg Config) bool {
	if cfg.DisableCaptureMessageContent {
		return false
	}
	env := strings.ToLower(strings.TrimSpace(os.Getenv("OTEL_INSTRUMENTATION_GENAI_CAPTURE_MESSAGE_CONTENT")))
	if env == "false" {
		return false
	}
	return cfg.CaptureMessageContent || env == "true"
}
