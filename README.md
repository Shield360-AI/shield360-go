# Shield360 Go SDK

OpenTelemetry-native observability SDK for LLM applications in Go. Monitor your AI applications with automatic instrumentation for popular LLM providers.

[![Go Reference](https://pkg.go.dev/badge/github.com/ThinkfleetAI/shield360-go.svg)](https://pkg.go.dev/github.com/ThinkfleetAI/shield360-go)
[![Go Report Card](https://goreportcard.com/badge/github.com/ThinkfleetAI/shield360-go)](https://goreportcard.com/report/github.com/ThinkfleetAI/shield360-go)

## Features

- 🚀 **One-line initialization** - Get started with minimal code
- 📊 **OpenTelemetry-native** - Built on OpenTelemetry standards
- 💰 **Cost tracking** - Automatic cost calculation for LLM requests
- 📈 **Metrics collection** - Token usage, latency, and performance metrics
- 🔄 **Streaming support** - Full support for streaming responses
- 🔌 **Flexible integration** - Works with multiple Go client libraries

## Supported Integrations

- ✅ **OpenAI** - Chat completions, embeddings, images, audio
- ✅ **Anthropic** - Messages API with tool calling support
- ✅ **vLLM** - OpenAI-compatible chat completions (local / self-hosted)

## Installation

```bash
go get github.com/ThinkfleetAI/shield360-go
```

## Quick Start

### 1. Initialize Shield360

```go
package main

import (
    "context"
    "log"
    
    "github.com/ThinkfleetAI/shield360-go"
)

func main() {
    // Initialize Shield360
    err := shield360.Init(shield360.Config{
        OtlpEndpoint:    "http://127.0.0.1:4318",
        Environment:     "production",
        ApplicationName: "my-go-app",
    })
    if err != nil {
        log.Fatalf("Failed to initialize Shield360: %v", err)
    }
    defer shield360.Shutdown(context.Background())
    
    // Your application code here
}
```

### 2. Instrument OpenAI

```go
import (
    "github.com/ThinkfleetAI/shield360-go/instrumentation/openai"
    openai_sdk "github.com/sashabaranov/go-openai"
)

// Create and instrument OpenAI client
client := openai_sdk.NewClient("your-api-key")
instrumentedClient := openai.Instrument(client)

// Use as normal - automatically traced!
resp, err := instrumentedClient.CreateChatCompletion(ctx, openai_sdk.ChatCompletionRequest{
    Model: openai_sdk.GPT4,
    Messages: []openai_sdk.ChatCompletionMessage{
        {
            Role:    openai_sdk.ChatMessageRoleUser,
            Content: "Hello!",
        },
    },
})
```

### 3. Instrument Anthropic

```go
import (
    "github.com/ThinkfleetAI/shield360-go/instrumentation/anthropic"
)

// Create and instrument Anthropic client
client := anthropic.NewClient("your-api-key")
instrumentedClient := anthropic.Instrument(client)

// Use as normal - automatically traced!
resp, err := instrumentedClient.CreateMessage(ctx, anthropic.MessageRequest{
    Model: "claude-3-5-sonnet-20241022",
    Messages: []anthropic.Message{
        {
            Role:    "user",
            Content: "Hello!",
        },
    },
    MaxTokens: 1024,
})
```

### 4. Instrument vLLM

vLLM exposes an OpenAI-compatible HTTP API. Point the instrumented client at your
vLLM server (default `http://127.0.0.1:8000/v1`). Spans use `gen_ai.system=vllm`
so they are distinct from OpenAI.

```go
import (
    "github.com/ThinkfleetAI/shield360-go/instrumentation/vllm"
)

client := vllm.NewClient("http://127.0.0.1:8000/v1") // optional: vllm.WithAPIKey("...")

resp, err := client.CreateChatCompletion(ctx, vllm.ChatCompletionRequest{
    Model: "meta-llama/Llama-3-8B-Instruct",
    Messages: []vllm.ChatMessage{
        {Role: "user", Content: "Hello!"},
    },
})
```

## Configuration Options

```go
config := shield360.Config{
    // Required
    OtlpEndpoint:    "http://127.0.0.1:4318",  // OTLP endpoint
    
    // Optional
    Environment:     "production",              // Deployment environment
    ApplicationName: "my-go-app",              // Application name
    ServiceVersion:  "1.0.0",                  // Service version
    
    // OTLP Configuration
    OtlpHeaders:     map[string]string{},      // Custom OTLP headers
    
    // Feature Flags
    DisableTracing:  false,                    // Disable tracing
    DisableMetrics:  false,                    // Disable metrics
    DisableBatch:    false,                    // Disable batch processing
    
    // Timeouts
    TraceExporterTimeout:  10 * time.Second,   // Trace export timeout
    MetricExporterTimeout: 10 * time.Second,   // Metric export timeout
    MetricExportInterval:  30 * time.Second,   // Metric export interval
    
    // Pricing
    PricingEndpoint:    "",                    // Custom pricing endpoint
    DisablePricingFetch: false,                // Disable pricing fetch
    PricingInfo:        map[string]ModelPricing{}, // Custom pricing
}
```

## Streaming Support

OpenAI, Anthropic, and vLLM integrations support streaming responses:

### OpenAI Streaming

```go
stream, err := instrumentedClient.CreateChatCompletionStream(ctx, request)
if err != nil {
    log.Fatal(err)
}
defer stream.Close()

for {
    response, err := stream.Recv()
    if errors.Is(err, io.EOF) {
        break
    }
    if err != nil {
        log.Fatal(err)
    }
    
    fmt.Printf(response.Choices[0].Delta.Content)
}
```

### Anthropic Streaming

```go
stream, err := instrumentedClient.CreateMessageStream(ctx, request)
if err != nil {
    log.Fatal(err)
}
defer stream.Close()

for {
    event, err := stream.Recv()
    if errors.Is(err, io.EOF) {
        break
    }
    if err != nil {
        log.Fatal(err)
    }
    
    // Handle event
}
```

### vLLM Streaming

```go
stream, err := client.CreateChatCompletionStream(ctx, vllm.ChatCompletionRequest{
    Model:    "meta-llama/Llama-3-8B-Instruct",
    Messages: []vllm.ChatMessage{{Role: "user", Content: "Hello!"}},
})
if err != nil {
    log.Fatal(err)
}
defer stream.Close()

for {
    chunk, err := stream.Recv()
    if errors.Is(err, io.EOF) {
        break
    }
    if err != nil {
        log.Fatal(err)
    }
    if len(chunk.Choices) > 0 {
        fmt.Print(chunk.Choices[0].Delta.Content)
    }
}
```

## Collected Telemetry

### Traces

- Operation name and type (chat, embedding, etc.)
- Request and response models
- Input/output messages
- Token usage (input, output, total)
- Cost calculations
- Response times
- Error details

### Metrics

- `gen_ai.client.token.usage` - Token usage counter
- `gen_ai.client.operation.duration` - Operation duration histogram
- `gen_ai.server.time_to_first_token` - TTFT for streaming
- `gen_ai.server.time_per_output_token` - TBT for streaming

### Attributes

All traces include standard OpenTelemetry semantic conventions:
- `gen_ai.operation.name`
- `gen_ai.system`
- `gen_ai.request.model`
- `gen_ai.response.model`
- `gen_ai.usage.input_tokens`
- `gen_ai.usage.output_tokens`
- `server.address`
- `server.port`

## Advanced Usage

### Custom Pricing

Provide custom pricing information for models:

```go
config := shield360.Config{
    PricingInfo: map[string]shield360.ModelPricing{
        "gpt-4-custom": {
            InputCostPerToken:  0.00003,
            OutputCostPerToken: 0.00006,
        },
    },
}
```

### Custom Headers

Add custom headers to OTLP exports:

```go
config := shield360.Config{
    OtlpHeaders: map[string]string{
        "Authorization": "Bearer token",
        "X-Custom-Header": "value",
    },
}
```

## Integration with Shield360 Dashboard

The Go SDK works seamlessly with the [Shield360 Dashboard](https://shield360.ai):

1. Start Shield360 stack:
```bash
docker compose up -d
```

2. Configure SDK to send data:
```go
shield360.Init(shield360.Config{
    OtlpEndpoint: "http://localhost:4318",
})
```

3. View your traces at http://localhost:3000

## Examples

See the [examples/](examples/) directory for complete working examples:
- [OpenAI Chat Completion](examples/openai/chat/)
- [OpenAI Streaming](examples/openai/streaming/)
- [Anthropic Messages](examples/anthropic/messages/)
- [Anthropic Streaming](examples/anthropic/streaming/)

## Rule Engine - `shield360.EvaluateRule()`

Evaluate trace attributes against the Shield360 Rule Engine to retrieve matching rules and associated entities (contexts, prompts, evaluation configurations). This function does **not** require `shield360.Init()` — it is a standalone HTTP call.

### Parameters (`EvaluateRuleOptions`)

| Field              | Type                    | Description                                                                 |
|--------------------|-------------------------|-----------------------------------------------------------------------------|
| `URL`              | `string`                | Shield360 dashboard URL. Falls back to `SHIELD360_URL` env, then `http://127.0.0.1:3000`. |
| `APIKey`           | `string`                | Bearer token. Falls back to `SHIELD360_API_KEY` env.                          |
| `EntityType`       | `RuleEntityType`        | `RuleEntityContext`, `RuleEntityPrompt`, or `RuleEntityEvaluation`.         |
| `Fields`           | `map[string]interface{}`| Trace attributes to evaluate against rules.                                 |
| `IncludeEntityData`| `bool`                  | If true, include full entity data in response.                              |
| `EntityInputs`     | `map[string]interface{}`| Optional inputs for entity resolution (e.g. prompt variables).              |
| `Timeout`          | `time.Duration`         | HTTP timeout. Default: 30s.                                                 |

### Example

```go
result, err := shield360.EvaluateRule(ctx, shield360.EvaluateRuleOptions{
    EntityType: shield360.RuleEntityContext,
    Fields: map[string]interface{}{
        "gen_ai.system":        "openai",
        "gen_ai.request.model": "gpt-4",
        "service.name":         "my-app",
    },
    IncludeEntityData: true,
})
if err != nil {
    log.Fatal(err)
}
fmt.Println("Matching rules:", result.MatchingRuleIDs)
fmt.Println("Entities:", result.Entities)
```

## Requirements

- Go 1.21 or higher
- OpenTelemetry Collector or compatible backend

## Contributing

We welcome contributions! See [CONTRIBUTING.md](../../CONTRIBUTING.md) for details.

## License

Apache License 2.0 - see [LICENSE](../../LICENSE)

## Support

- 📚 [Documentation](https://shield360.ai)
- 💬 [Slack Community](https://join.slack.com/t/shield360/shared_invite/zt-2etnfttwg-TjP_7BZXfYg84oAukY8QRQ)
- 🐛 [Issue Tracker](https://github.com/ThinkfleetAI/shield360-go/issues)
