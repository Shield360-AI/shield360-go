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
go get github.com/Shield360-AI/shield360-go
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
    OtlpEndpoint:    "http://127.0.0.1:4318",  // OTLP endpoint; default OTEL_EXPORTER_OTLP_ENDPOINT, else <Shield360URL>/api/ingest/otlp with the API key as bearer, else this
    
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
    CaptureMessageContent: false,              // Record prompt/completion text (off by default)
    CaptureLogs:     nil,                      // *bool: send slog records to Shield360 (off by default)
    LogLevel:        "",                       // Lowest level sent when CaptureLogs is on (info)
    
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

> **Message content is off by default.** Prompt and completion text is recorded only with `CaptureMessageContent: true` (or `OTEL_INSTRUMENTATION_GENAI_CAPTURE_MESSAGE_CONTENT=true`); `DisableCaptureMessageContent` still turns it off. Even then, Shield360 stores it only if your organization's [Data retention](https://shield360.ai) setting allows it. Before this release the default was on.

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

### Code location and build attributes

Every GenAI span records where in your code the model call was made:

- `code.function.name`: the fully qualified Go function, for example `github.com/acme/api/billing.Summarise`
- `code.file.path`: the file, relative to your repository
- `code.line.number`: the line of the call

Frames inside this SDK, OpenTelemetry, the Go runtime and standard library, and the provider client libraries are skipped. Only names, paths and line numbers are recorded, never argument values or source text.

File paths are made repo-relative in this order: `Config.CodeRoot` (or `SHIELD360_CODE_ROOT`), the main module path in `-trimpath` builds, then the working directory at `Init`. A home directory prefix is always removed, and so is a CI workspace prefix (such as `/home/runner/work/<repo>/<repo>/`) left in a binary built without `-trimpath`. Add your own wrapper packages to `Config.CodeLocationIgnoreModules` to report their callers instead.

Turn it off with `SHIELD360_CAPTURE_CODE_LOCATION=false` (or `0`, `no`, `off`) or `CaptureCodeLocation: &off` in `Config`. The config field wins over the environment variable.

The same call site is also recorded on the app's outbound calls: database, HTTP, RPC and messaging client and producer spans. Shield360 uses it to price the costly code patterns `shield360 scan` finds, such as a query inside a loop. Turn just that off with `SHIELD360_CAPTURE_CALL_LOCATION=false` or `CaptureCallLocation: &off`; model calls keep their location.

`Init` also sets these resource attributes, so every span carries the release it came from:

| Attribute | Sources, highest precedence first |
| --- | --- |
| `service.version` | `Config.ServiceVersion`, `SHIELD360_SERVICE_VERSION`, `OTEL_SERVICE_VERSION`, `OTEL_RESOURCE_ATTRIBUTES` |
| `vcs.ref.head.revision` | `SHIELD360_GIT_COMMIT`, `OTEL_RESOURCE_ATTRIBUTES`, the `vcs.revision` that `go build` embeds, CI variables |
| `vcs.repository.url.full` | `SHIELD360_GIT_REPOSITORY_URL`, `OTEL_RESOURCE_ATTRIBUTES`, CI variables |
| `vcs.ref.head.name` | `SHIELD360_GIT_BRANCH`, `OTEL_RESOURCE_ATTRIBUTES`, CI variables |

CI variables are read from GitHub Actions, GitLab CI, Vercel, Netlify, Render, Railway, Heroku, AWS CodeBuild, Buildkite, CircleCI, Bitbucket Pipelines, Azure Pipelines and Jenkins. An explicit `OTEL_RESOURCE_ATTRIBUTES` value beats CI auto-detection. Only the first provider with a commit set is used. Commits must be 7 to 64 hex characters. Repository URLs are normalized to `https://host/owner/repo`, with credentials, query strings and a trailing `.git` removed.

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

## Request tracing

After `shield360.Init`, wrap the server, the HTTP client and the database once, and each request becomes a trace with its outgoing calls and SQL inside:

```go
mux := http.NewServeMux()
mux.HandleFunc("GET /orders/{id}", getOrder)
http.ListenAndServe(":8080", shield360.Handler(mux, "orders-api"))

client := shield360.HTTPClient()            // or &http.Client{Transport: shield360.Transport(base)}
db, err := shield360.OpenDB("postgres", dsn) // instead of sql.Open
```

- Requests are named by their `ServeMux` route (`GET /orders/{id}`), with `http.route` set.
- Health probes (Kubernetes, load balancers, uptime checks, `/healthz`-style paths) are not traced, and neither are calls to `SHIELD360_URL`.
- SQL is recorded as the statement text, never its arguments.

Caches, document stores, RPC, messaging and AWS each have a one-line hook in its own package, so an app compiles only the client libraries it uses:

| Library | Package | Hook |
|---|---|---|
| go-redis v9 | `instrumentation/goredis` | `goredis.Instrument(rdb)` |
| MongoDB driver v2 | `instrumentation/mongodb` | `options.Client().ApplyURI(uri).SetMonitor(mongodb.Monitor())` |
| gRPC | `instrumentation/grpctrace` | `grpc.NewClient(addr, grpctrace.DialOption())`, `grpc.NewServer(grpctrace.ServerOption())` |
| segmentio/kafka-go | `instrumentation/kafkago` | `kafkago.WriteMessages(ctx, writer, msgs...)`, `ctx, span := kafkago.StartProcess(ctx, msg, group)` |
| AWS SDK v2 | `instrumentation/awstrace` | `awstrace.Instrument(&cfg)` before building clients |

Values stay out: a Redis command is recorded by name only (`set`, never its key or value), a MongoDB command without its document and a failure by error name only, gRPC and Kafka without messages, keys or payloads (the trace context travels in Kafka headers), and AWS calls without request or response bodies. gRPC health checks are not traced. Spans follow the OpenTelemetry database, RPC and messaging conventions. For the MongoDB driver v1, use `otelmongo` from OpenTelemetry contrib, which keeps commands out by default. Sarama has no maintained OpenTelemetry instrumentation and is not covered yet.

To trace a Go service without changing its code, use eBPF on the host (the Shield360 controller).

## Application logs

Off by default. Set `SHIELD360_CAPTURE_LOGS=true` (or the init option, `Config.CaptureLogs`) to send the application's own log records to Shield360, on the same endpoint and key as traces. `SHIELD360_LOG_LEVEL` (or `Config.LogLevel`) sets the lowest level sent (`info` by default; `trace`, `debug`, `info`, `warn`, `error`, `fatal`). Records carry the active trace and span ids, `service.name` and `deployment.environment`; credentials and opaque tokens in messages and attributes are masked before they leave the process; at most 500 records a second per bridge are sent, in batches, and a failure to send never reaches the application.

The bridge is a `log/slog` handler. With capture on, `Init` makes `slog.Default()` (and through it the `log` package) forward as well, while its output still goes where it went before; `Shutdown` puts it back.

```go
on := true
_ = shield360.Init(shield360.Config{ApplicationName: "checkout-api", CaptureLogs: &on})
defer shield360.Shutdown(context.Background())

slog.InfoContext(ctx, "order placed", "order_id", id) // linked to the span in ctx

// Your own slog.Logger: a no-op until application logs are on.
logger := slog.New(shield360.LogHandler("checkout"))
logger.Error("payment failed", "err", err) // exception.type, exception.message
```

- **Records**: body is the message; severity `TRACE` (below Debug), `DEBUG`, `INFO`, `WARN`, `ERROR`, `FATAL` (above Error); the scope is the handler's name (`app` by default); attributes keep their keys, with groups as dotted keys; `code.file.path`, `code.function.name` and `code.line.number` give the call site; the first `error` value becomes `exception.type` and `exception.message`.
- **Masking**: the contract every SDK shares (`sdk/rasp/README.md`, "Masking"; also used for RASP snippets). Credentials and opaque tokens are masked: credential pairs (`password=…`, `"api_key": "…"`, `Authorization: Bearer …`), bearer credentials, and opaque runs such as keys, hashes, base64, JWTs and UUIDs. Readable identifiers survive: class names, package and file paths, URLs. An attribute named like a credential (`password`, `x-api-key`, `user.sessionId`) is masked whole, whatever its value, and string lists are masked item by item. `code.*` and `exception.type` are never masked. Masking runs before the cut: messages are cut to 16,384 characters and attributes to 4,096.
- **Never sent**: records from handlers named `shield360…` or `opentelemetry…`, the SDK's own `log` lines, and anything logged while a record is being exported.
- `shield360.CaptureLogs(level)` and `shield360.StopCapturingLogs()` turn it on and off after `Init`; `shield360.NewLogHandler(shield360.LogHandlerOptions{...})` takes your own OpenTelemetry `LoggerProvider`, level and rate.

## Feature flags - `shield360.Flags()`

Fetch an environment's feature flags and evaluate them locally, with the same engine as the Shield360 server and the other SDKs (the `flags` package). The client polls `GET /api/flags/rules` every 30 seconds (with ±10% jitter, at least every 5 seconds if you set `PollInterval`, sending the last `ETag` so an unchanged environment costs a 304) and starts on first use. It never panics or returns errors: until rules arrive, for an unknown flag, for a flag scoped to another app, for a value of the wrong kind, or on any error, you get your default.

The destination is `Config.Shield360URL` and `Config.Shield360APIKey` from `shield360.Init`, then `SHIELD360_URL` and `SHIELD360_API_KEY`. A flag scoped to an app is served only when its app is `Config.ApplicationName` (service.name).

```go
shield360.Init(shield360.Config{ApplicationName: "checkout-api", Shield360URL: "https://shield360.example.com", Shield360APIKey: apiKey})
ff := shield360.Flags()
ff.WaitUntilReady(2 * time.Second) // optional: block startup until the first fetch

user := map[string]any{"key": userID, "plan": "pro", "groups": []string{"beta"}}
if ff.IsEnabled(ctx, "new-checkout", user) { /* ... */ }
limit := ff.GetNumber(ctx, "daily-limit", user, 100)
detail := ff.GetFlagDetail(ctx, "new-checkout", user, false) // Value, Variation, Reason

// AI helpers
model := ff.Model(ctx, "model-choice", user, "openai/gpt-4o-mini")
if ff.KillSwitch(ctx, "ai-assistant", user) { return errAssistantOff } // engaged when the flag serves false
p := ff.Prompt(ctx, "support-prompt", user, flags.PromptRef{Name: "support-reply"},
    flags.PromptOptions{Compile: true, Variables: map[string]any{"name": "Ana"}})
// p.Name, p.Version, p.Variation, p.Prompt (Prompt Hub's data), p.Err
```

| Method | Returns |
|--------|---------|
| `GetFlagDetail(ctx, key, evalCtx, def)` | `flags.Detail{Value, Variation, Reason}` |
| `GetFlag` / `GetJSON` | `any` (decoded JSON) |
| `GetBool`, `GetString`, `GetNumber` | `bool`, `string`, `float64` |
| `IsEnabled(ctx, key, evalCtx)` | `GetBool(..., false)` |
| `Model(ctx, key, evalCtx, def)` | a provider/model id from a string flag |
| `KillSwitch(ctx, key, evalCtx)` | `true` when the switch is engaged (`!GetBool(..., true)`), so it stays off when rules are unavailable |
| `Prompt(ctx, key, evalCtx, def, opts)` | the Prompt Hub prompt the flag names (`{"name", "version"}` or `"name@version"`), else `def`, fetched from `/api/prompt/get-compiled` |

When a variation is served, `shield360.flag.<key>` is set to its key on the recording span in `ctx`, so cost, latency and evals can be compared per variant (`Options.DisableSpanAttributes` turns this off). Rules that name segments (`in_segment`, `not_in_segment`) use the environment's segments from the same feed.

For your own client, `flags.New(flags.Options{URL, APIKey, ApplicationName, PollInterval, Timeout, HTTPClient})`; `Start`, `Refresh`, `WaitUntilReady` and `Close` control polling. `flags.Evaluate(flag, context, segments)`, `flags.ValidateFlag` and `flags.ValidateSegment` expose the engine, which is held to the shared vectors in `sdk/flags-core/testdata/vectors.json`.

## Runtime packages

With a Shield360 URL and API key, the SDK reports the modules the binary runs so Shield360 can match them against vulnerability data (Security → Code, as a "runtime" target): the Go version and the modules the binary was built with (`runtime/debug.ReadBuildInfo`; a replaced module reports its replacement's version). Each is a name and a version; no path, file or other field leaves the process, and at most 500 are sent. The report goes to `/api/guard/events` with the app's API key, about 15 seconds after start and then once a day, off the call path; it never panics and a report that cannot be delivered is dropped. When runtime protection is on it uses this report instead of sending its own.

Turn it off with `Config.DisableRuntimePackages: true` or `SHIELD360_RUNTIME_PACKAGES=off`.

## Runtime protection (RASP)

Runtime application self-protection, opt-in, in the `rasp` package. It keeps the untrusted input of the request being served (and the model output the LLM instrumentation sees) in the request's `context.Context` and checks it where it reaches a dangerous sink. It follows the shared contract in [`sdk/rasp/README.md`](../rasp/README.md), with the same detection algorithms, rule ids, events and signed config as the other SDKs, and it fails open: the only error it returns on purpose is the block error, `rasp.ErrBlocked`.

```go
shield360.Init(shield360.Config{
    ApplicationName: "orders-api",
    Shield360URL:    "https://shield360.example.com", // events and the signed config
    Shield360APIKey: apiKey,
    Rasp: &rasp.Options{
        ConfigPublicKey: os.Getenv("SHIELD360_CONFIG_PUBLIC_KEY"), // from the app's Runtime protection settings
    },
})
http.ListenAndServe(":8080", rasp.Middleware(mux))
```

`SHIELD360_RASP=monitor|block` turns it on without `Config.Rasp`; `SHIELD360_RASP=off` always wins. Everything runs in **monitor** mode unless an attack type is set to block (`Options.Mode`, `Options.Attacks`, or the platform's per-app settings in the signed config). `rasp.Disable()` and `rasp.Enable()` are the runtime kill switch; the env switch and the signed config's `killSwitch` rank above them.

`rasp.Middleware` is a plain `func(http.Handler) http.Handler`, so it works with `http.ServeMux`, chi and gorilla/mux (`r.Use(rasp.Middleware)`), echo (`e.Use(echo.WrapMiddleware(rasp.Middleware))`) and gin through any standard-middleware adapter, with no framework dependency. It records query values, route parameters (from the ServeMux pattern, or `rasp.RecordRoute` for other routers), cookies, the `user-agent`, `referer` and `x-forwarded-for` headers, and the body of POST, PUT, PATCH and DELETE requests (buffered up to 1 MiB and replayed to the handler in full). It runs the virtual patches before the handler and answers a blocking one with the contract's 403 JSON. Where a sink returns the block error, `if rasp.WriteBlocked(w, err) { return }` writes the same 403.

Deception (decoy paths): when the app's Runtime protection settings on the platform list decoy paths (none by default), `rasp.Middleware` answers a request to one with `http.NotFound`, never calling the handler, and marks the client's peer address (never `X-Forwarded-For`) suspicious for the configured time. Later requests from that address are reported as `deception.suspicious`, and get the contract's 403 when the action is block (capped by `attacks.deception`, and at monitor without a pinned key). Marks live in memory in this process only, at most 10,000 addresses (oldest dropped first), so each instance keeps its own. Matching follows `sdk/rasp/README.md` "Deception"; any error lets the request through.

Model output from the OpenAI, Anthropic and vLLM instrumentation (completion text, tool-call arguments) joins the request's inputs. A worker that acts on a model's answer outside a request wraps its job in `ctx = rasp.WithScope(ctx)`.

The signed config is used only under a pinned key: `Options.ConfigPublicKey` or `SHIELD360_CONFIG_PUBLIC_KEY` (a JWK, a JWKS for rotation, or the bare base64url Ed25519 `x`). Without a pin the config is not fetched and RASP runs its built-in defaults in monitor mode, logging one warning. Trust on first use (`Options.AllowUnpinnedConfig` or `SHIELD360_CONFIG_TOFU=dev`) is for development only and is ignored when the environment is production. The last verified config is cached in `os.TempDir()/shield360-rasp` and verified again when loaded; polling never blocks start-up.

Events (`shield360.rasp.event`, batched, at most 100 a minute, repeats folded) and a components report (the Go runtime and the binary's modules, from `runtime/debug.ReadBuildInfo`) go to `POST /api/guard/events`. Events name where an input was found (`query.id`), never its value.

### Sinks

Go has no runtime patching, so the sinks are opt-in: the app calls RASP's drop-in for each dangerous call. Each one checks before the underlying call, returns the block error instead of making it (in block mode), reports once and lets the call through in monitor mode, and fails open on anything else. Pass the request's `context.Context`: that is where the inputs live.

```go
// database/sql: a drop-in for sql.Open. Every Query, Exec and Prepare (DB, Conn and Tx)
// is checked once, with the dialect from the driver name.
db, err := rasp.OpenSQL("postgres", dsn)
rows, err := db.QueryContext(r.Context(), query) // use the Context variants

// os/exec: drop-ins for exec.Command / exec.CommandContext. A blocked command gets the
// block error in cmd.Err, so Run, Start and Output return it without starting anything.
out, err := rasp.CommandContext(r.Context(), "convert", name, "out.png").Output()

// HTTP client: SSRF and the outbound allow-list before sending, and the address the
// connection actually dials (DNS rebinding).
client := rasp.WrapClient(http.DefaultClient) // or &http.Client{Transport: rasp.NewTransport(nil)}
resp, err := client.Do(req.WithContext(r.Context()))

// Files: the os functions with a context first.
data, err := rasp.ReadFile(r.Context(), filepath.Join(uploads, name))

if rasp.WriteBlocked(w, err) { return } // the contract's 403
```

| Sink | API | Rules |
|---|---|---|
| `database/sql` | `rasp.OpenSQL`, `rasp.OpenSQLDB`, `rasp.WrapDriver` (for `sql.Register`), `rasp.WrapConnector`, `rasp.SQLDialectOf` | `sqli.*`. A statement a driver declines with `driver.ErrSkip` itself (not an error wrapping it) is not checked again when `database/sql` prepares it. The connection has the driver's own optional interfaces, `SessionResetter` and `Validator` included, and no others. `db.Query` without a context has no request in scope. |
| SQL Server, Oracle, Db2 (through `database/sql`) | `rasp.OpenSQL("sqlserver", dsn)`, `rasp.OpenSQL("godror", dsn)`, `rasp.OpenSQL("go_ibm_db", dsn)`, or `WrapDriver`/`WrapConnector` with that name | `sqli.*`, lexed per driver name: `sqlserver`, `mssql`, `azuresql` → `mssql`; `godror`, `oracle` (go-ora), `oci8` → `oracle`; `go_ibm_db` and names containing `db2` → `db2`. Events use the sink `db.<driver name>.query`. |
| MongoDB | `rasp.CheckMongo(ctx, "find", filter)` before the driver call | `nosqli.operator`, `nosqli.where`. Reads `bson.D`, `bson.M`, `mongo.Pipeline`, maps and slices without importing the driver. |
| Processes | `rasp.Command`, `rasp.CommandContext`, `rasp.CheckCommand(ctx, argv)`, `rasp.CheckShellCommand(ctx, line)` | `cmdi.*` on argv and on `sh -c` / `bash -c` / `cmd /c` scripts, `shell_spawn.*` with `allow.commands`. `rasp.Command` has no request in scope, so only `shell_spawn.download_exec` applies; prefer `CommandContext`. Changes to `cmd.Path` or `cmd.Args` after the call are not checked. |
| HTTP client | `rasp.NewTransport(base)`, `rasp.WrapClient(c)` | `outbound.not_allowed` (inside or outside requests; the Shield360 and OTLP hosts always allowed), then `ssrf.*`, on every redirect hop. Internationalized hosts are matched in their percent-encoded, Unicode and IDNA ASCII forms. A request whose host name comes from an input and that goes direct is sent through a clone of the base `*http.Transport` that resolves the name, checks every address, and connects to exactly those addresses (TLS keeps the URL's server name), without keep-alive. A custom TLS dialer (`DialTLSContext`, legacy `DialTLS`) keeps doing its own connecting: its name is resolved and checked first, and the address it actually connected to is checked before any byte of the request is written. Through a proxy (`Proxy`, `HTTP_PROXY`) the target is resolved locally and checked before sending: best effort, since the proxy resolves the name itself. Keep `NewTransport` directly around the `*http.Transport` (tracing outside it); around another RoundTripper only the checks before sending (with a local lookup of a tainted name) run. |
| Files | `rasp.Open`, `Create`, `OpenFile`, `ReadFile`, `WriteFile`, `Remove`, `RemoveAll`, `Rename` (both paths), `ReadDir`, `rasp.CheckPath(ctx, path, op)` | `path.*` with `allow.fileRoots`, `file_write.script`, `file_write.ntfs`. Outside a RASP context only `file_write.ntfs` applies. |
| Code | `rasp.CheckCode(ctx, sink, src)` before an expression or script engine evaluates text | `code.eval` |
| Templates | `rasp.ParseTextTemplate(ctx, t, src)` and `rasp.ParseHTMLTemplate(ctx, t, src)` for `text/template` and `html/template` `(*Template).Parse` (sinks `text/template.Parse`, `html/template.Parse`), `rasp.CheckTemplate(ctx, sink, engine, src)` for any engine of the shared table (`rasp.TemplateEngines`) | `code.template_injection` on the template source only; data passed to `Execute` is never checked. An unknown engine name is not checked. |
| Deserialization | `rasp.CheckDeserialization(ctx, sink, format, data)` before a third-party decoder of one of the contract's formats | `deser.*` |
| XML | `rasp.UnmarshalXML(ctx, data, v)`, `rasp.CheckXML(ctx, sink, data, resolvesExternal)` | `xxe.*`. `encoding/xml` never fetches external entities, so its findings are `xxe.doctype`. |
| HTML responses | `rasp.CheckResponses(handler)` inside `rasp.Middleware`, or `rasp.WrapResponseWriter(w, r)` | `xss.reflected`, monitor only: the response is never changed or delayed; a copy of at most 1 MiB is judged in the background after the handler returns (at most 8 at once; a response that finds every slot busy is not checked). The wrapper has exactly the writer's `Flusher`, `Hijacker` and `Pusher`, and `Unwrap` for `http.ResponseController`. |

Event sinks name the call (`db.postgres.query`, `exec.CommandContext`, `http.Transport`, `os.ReadFile`, `http.response`). The contract's sink rules are for Node and Python; Go ignores them.

Uploads: `rasp.Middleware` reads the file names of `multipart/form-data` uploads from the part headers of the body it buffers, with `mime/multipart` and the request's boundary, so the names are those the handler's parser sees (at most 32 names, from the first 1 MiB; part bodies are skipped and the handler still reads the whole body). `rasp.RecordRequestBody` takes a parsed `*multipart.Form`, also after the middleware buffered the body, and adds any names not seen yet; each name is checked once. Detection reads the whole name, although the recorded input is cut at 4096 characters. The names are request input (`body.<field>.filename`), and an upload named like a script (`.php`, `.jsp`, `.sh`, `.exe`…) is reported at sink `request.upload` (`file_write.upload`; blocks when `file_write` blocks). A later `rasp.WriteFile` or `rasp.Create` named after the upload is caught by `file_write.script`.

Security baseline: once per process, in the background after `Init`, RASP reports risky set-up as `baseline` events (report only, never blocks): `InsecureSkipVerify` on `http.DefaultTransport`, `net/http/pprof` on `http.DefaultServeMux` in production, `GIN_MODE=debug` under a production environment, running as root, an unpinned config key in production, and a Go release line past its end of life. See "Security baseline" in [`sdk/rasp/README.md`](../rasp/README.md).

`code.include` (loading a module named by input) does not apply to Go: a Go binary has no runtime module loading beyond `plugin.Open`.

### Custom rules

The organization's own rules, written in the platform's rules editor, arrive in the signed config and are applied by the Go SDK as the contract's "Custom rules" section says ([`sdk/rasp/README.md`](../rasp/README.md)). Each expression is parsed and type-checked once when the config arrives and evaluated as data, never as code; a rule that fails validation is skipped with one log line and the rest of the config applies. The language, its limits and error codes are those of the TypeScript SDK and the platform, and the regex subset is matched by a port of the same Pike VM (linear time, with the same 4,000,000-step budget per request), so `testdata/custom-rules.json` passes unchanged.

- **Request rules** run with the virtual patches in two phases. `rasp.Middleware` judges the head (query, cookies, input headers, `request.ip`) before it reads the body, then the body phase once the body is buffered (rules that read `request.body`, and `input.*` rules that did not match at head). A request without a body (a `GET`, an empty `POST`) has a known, empty body, so the body phase still runs; a body the app still hands to `rasp.RecordRequestBody` becomes input for the built-in checks, without running the body phase again. A body the middleware does not read (a `GET` or other non-`POST`/`PUT`/`PATCH`/`DELETE` request that has one) stays unknown until `rasp.RecordRequestBody` adds it. A blocking match answers with the contract's 403.
- **Finding rules** (those that read `sink.*` or `attack.*`) run whenever a built-in check reports a finding, and can block a call the built-in attack type only monitors.
- `request.ip` is the peer address from `http.Request.RemoteAddr`; `X-Forwarded-For` is only `request.headers["x-forwarded-for"]`. `request.route` is the ServeMux pattern or the template given to `rasp.RecordRoute`.
- A rule's `action` is capped by the `custom_rule` mode (`Options.Attacks[rasp.CustomRuleAttack]` or the platform's per-app setting): it blocks only when both say block. Events report `custom.<id>`.

`rasp.CompileRuleExpr` and `rasp.EvaluateRuleExpr` expose the evaluator for tests of your own rules.

### Passive IAST

Off by default. `Options.Iast` (or `SHIELD360_IAST=on`, or the platform's per-app switch) turns on vulnerability reporting: where a request input reaches a sink verbatim and unparameterized during normal traffic, even when nothing attacked it (`GET /api/orders/:id builds SQL from query.email`). It never blocks, runs whatever the attack modes say, and adds work only to sink checks that already run with request input in scope. `SHIELD360_IAST=off` always wins. Checks are sampled: `SHIELD360_IAST_SAMPLE_RATE`, the signed config's rate, then `Options.IastSampleRate`, else every check (1 in 10 in production).

The rules reuse the tokens the attack checks already lexed, at the drop-in sinks above: `database/sql` (`vuln.sql_concat`), `CommandContext` / `CheckCommand` / `CheckShellCommand` (`vuln.cmd_shell`, `vuln.cmd_arg`), the file functions (`vuln.path_from_input`), the HTTP client's check before sending (`vuln.ssrf_host`), `CheckCode`, `CheckDeserialization` and `CheckXML` with `resolvesExternal` (`vuln.code_eval`, `vuln.deser_input`, `vuln.xml_external`). `vuln.include_from_input` has no Go sink. Each finding is reported as `shield360.rasp.vulnerability` at most once per process per hour per fingerprint (route, sink, input key, rule), with the count seen since, and never carries the input value. Its code location is the first stack frame (`runtime.Callers`) outside this SDK, the standard library and the module cache, relative to the working directory. Without a route template, path segments that are not short lower-case words become `:id`.

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
- 🐛 [Issue Tracker](https://github.com/Shield360-AI/shield360-go/issues)
