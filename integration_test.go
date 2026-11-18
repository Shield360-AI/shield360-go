package shield360

import (
	"context"
	"testing"
	"time"

	"github.com/ThinkfleetAI/shield360-go/helpers"
	"github.com/ThinkfleetAI/shield360-go/instrumentation/anthropic"
	"github.com/ThinkfleetAI/shield360-go/instrumentation/openai"
)

func TestSDKInitialization(t *testing.T) {
	err := Init(Config{
		OtlpEndpoint:    "http://localhost:4318",
		Environment:     "test",
		ApplicationName: "test-app",
		DisableTracing:  true,
		DisableMetrics:  true,
	})
	if err != nil {
		t.Fatalf("Failed to initialize: %v", err)
	}

	if !IsInitialized() {
		t.Error("Expected SDK to be initialized")
	}

	cfg := GetConfig()
	if cfg == nil {
		t.Fatal("Expected config to be available")
	}

	if cfg.Environment != "test" {
		t.Errorf("Expected environment 'test', got '%s'", cfg.Environment)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	err = Shutdown(ctx)
	if err != nil {
		t.Errorf("Failed to shutdown: %v", err)
	}

	if IsInitialized() {
		t.Error("Expected SDK to be shut down")
	}
}

func TestSDKDefaultCaptureMessageContent(t *testing.T) {
	err := Init(Config{
		OtlpEndpoint:   "http://localhost:4318",
		DisableTracing: true,
		DisableMetrics: true,
	})
	if err != nil {
		t.Fatalf("Failed to initialize: %v", err)
	}
	defer Shutdown(context.Background()) //nolint:errcheck

	cfg := GetConfig()
	// Content is off unless asked for.
	if cfg.CaptureMessageContent || helpers.GetCaptureMessageContent() {
		t.Error("Expected content capture to be off by default")
	}
}

func TestCaptureMessageContentWhenAskedFor(t *testing.T) {
	if !captureMessageContent(Config{CaptureMessageContent: true}) {
		t.Error("CaptureMessageContent: true should capture")
	}
	if captureMessageContent(Config{CaptureMessageContent: true, DisableCaptureMessageContent: true}) {
		t.Error("DisableCaptureMessageContent should win")
	}
	t.Setenv("OTEL_INSTRUMENTATION_GENAI_CAPTURE_MESSAGE_CONTENT", "true")
	if !captureMessageContent(Config{}) {
		t.Error("the OpenTelemetry variable should turn capture on")
	}
	t.Setenv("OTEL_INSTRUMENTATION_GENAI_CAPTURE_MESSAGE_CONTENT", "false")
	if captureMessageContent(Config{CaptureMessageContent: true}) {
		t.Error("the OpenTelemetry variable set to false should turn capture off")
	}
}

func TestMultipleInitialization(t *testing.T) {
	err := Init(Config{
		OtlpEndpoint:   "http://localhost:4318",
		DisableTracing: true,
		DisableMetrics: true,
	})
	if err != nil {
		t.Fatalf("First init failed: %v", err)
	}
	defer Shutdown(context.Background()) //nolint:errcheck

	// Second init should fail
	err = Init(Config{
		OtlpEndpoint: "http://localhost:4318",
	})
	if err == nil {
		t.Error("Expected error on second initialization")
	}
}

func TestInstrumentationIntegration(t *testing.T) {
	err := Init(Config{
		OtlpEndpoint:   "http://localhost:4318",
		DisableTracing: true,
		DisableMetrics: true,
	})
	if err != nil {
		t.Fatalf("Failed to initialize: %v", err)
	}
	defer Shutdown(context.Background()) //nolint:errcheck

	// Create clients (no actual API calls made)
	openaiClient := openai.NewClient("test-key")
	if openaiClient == nil {
		t.Error("Failed to create OpenAI client")
	}

	anthropicClient := anthropic.NewClient("test-key")
	if anthropicClient == nil {
		t.Error("Failed to create Anthropic client")
	}
}
