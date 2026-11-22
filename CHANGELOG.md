# Changelog

All notable changes to the Shield360 Go SDK will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Fixed
- Protection triangle: Edge's signed context is trusted only when the request carries Edge's own `X-Request-Id` and it equals the signed rid. A missing header no longer skips the check (`sdk/rasp/testdata/triangle.json` since #1078).

### Added
- Upload protection, all four layers (TypeScript parity): the deep scan (`deepScan` in the signed `uploads` block or `Options.Uploads`): the customer's own ClamAV over TCP or a Unix socket (`zINSTREAM`, streamed as the part is read), the hash-only reputation lookup (`POST /api/rasp/upload-reputation`, only the SHA-256 leaves the app, cached an hour), sync or async (`UploadSaved` scans the saved file in the background), quarantine (`QuarantineDir`, renamed to the SHA-256, `0600`), `failMode: closed` (`upload.scan_unavailable`), engine tests (`testId`) and `shield360.rasp.scanner` status records. Backdoor checks (`upload_backdoor`): saved upload locations (at most 10,000, 24 h) from `UploadSaved`, `InspectUploadFile` and writes holding an upload's bytes or name; `WriteFile`, `Create`, `OpenFile` and `Rename` refuse a server-script name or a served folder, the new `Chmod` an execute bit, `CommandContext`, `CheckCommand` and `CheckShellCommand` running one (directly, by an interpreter, or in `sh -c`), `CheckLoad` and `CheckExtract` plugin loads and archive extraction.
- Defend (`defend` package, TypeScript parity): `defend.New` decides in the app whether a request may go on, from a signed policy (`GET /api/defend/policy`, typ `shield360-defend+jws`, pinned like the RASP config): the full decision order (kill switch, deny list, agent policy, trap hit, challenge list, rules on paths, methods, countries, ASNs, client types, prompt injection and rates, then sensitive data), the decisions feed (a block made anywhere arrives within about 5 s), shared rate limits (`SharedRateLimits`), batched reporting to `/api/defend/report`, client type (`clienttype` package, the shared signatures), Edge's verified context, honeypot decoys and crumbs byte for byte Shield360 Edge's, the content check (the shared prompt-injection detector and sensitive-data shapes), and `net/http` middleware. Passes the injection golden corpus and the crumb spec vector; keeps byte-identical copies of `injection-rules.json`, the detector, the crumb code and the client-type signatures.
- Protection triangle (`agent-guides/edge-deception-spec.md`, "Protection triangle"): `rasp.Middleware` verifies Shield360 Edge's signed `X-Shield360-Edge-Context` header with the signed config's `edgeContext` keys, cross-checked against Edge's own `X-Request-Id`. A client Edge marked (flagged, trap level 2+, risk 70+, unless a verified crawler or agent) is blocked for injection-class attacks the app only monitors (`shield360.rasp.tightened_by_edge`); events carry `shield360.edge.request_id`; the first finding is answered with a signed `X-Shield360-Verdict` response header. Passes `sdk/rasp/testdata/triangle.json`.
- Request correlation: Edge's request id (verified context, else an id-shaped `X-Request-Id`) goes on the server span (`shield360.Handler` and the RASP capture) and on every slog record handed the request's context as `shield360.edge.request_id`, with the trace id of the request's `traceparent` as `shield360.edge.trace_id` when no span is active. Passes `sdk/rasp/testdata/request-correlation.json`.
- Code cost: the code-location processor also records the call site (`code.function.name`, `code.file.path`, `code.line.number`) on database, HTTP, RPC and messaging client and producer spans, so Shield360 can price the costly code patterns `shield360 scan` finds. `Config.CaptureCallLocation` or `SHIELD360_CAPTURE_CALL_LOCATION=false` turns just that off.
- One-line tracing hooks for caches, document stores, RPC, messaging and AWS, each in its own package so an app compiles only what it uses: `instrumentation/goredis` (go-redis v9, command name only), `instrumentation/mongodb` (MongoDB driver v2 command monitor: operation, namespace, collection, server; never the command document or a failure's message), `instrumentation/grpctrace` (client and server stats handlers, health checks left out), `instrumentation/kafkago` (segmentio/kafka-go producer and consumer spans, trace context in message headers, never keys or values) and `instrumentation/awstrace` (AWS SDK v2 middleware, no bodies).
- RASP deception: `rasp.Middleware` answers the decoy paths of the signed config's `deception` block with `http.NotFound` before the handler, marks the client address suspicious (in memory, per process, at most 10,000) and reports `deception.hit` / `deception.suspicious`, blocking a marked client when the action is block. Passes the shared `sdk/rasp/testdata/deception.json`.
- `rasp.MaskSnippet` follows the shared masking contract (`sdk/rasp/README.md`, "Masking"): quoted credentials and authorization schemes are masked, readable identifiers survive, and masking runs before the 64-character cut.
- With no `OtlpEndpoint`, telemetry goes to `OTEL_EXPORTER_OTLP_ENDPOINT`, else, with a Shield360 URL and API key (`Shield360URL` / `SHIELD360_URL`, `Shield360APIKey` / `SHIELD360_API_KEY`), to `<url>/api/ingest/otlp` with the key as bearer, as in the Python and TypeScript SDKs. An explicit endpoint or Authorization header always wins; `http://127.0.0.1:4318` stays the last resort.
- Application logs, opt-in: `Config.CaptureLogs` / `SHIELD360_CAPTURE_LOGS=true` send `log/slog` records (and, through `slog.Default()`, the `log` package) to Shield360 as OpenTelemetry logs on the traces endpoint and key (`/v1/logs`), at `Config.LogLevel` / `SHIELD360_LOG_LEVEL` and above (`info` by default). `shield360.LogHandler(name)` for your own loggers, `CaptureLogs` / `StopCapturingLogs`, `NewLogHandler`. Records carry the active trace and span ids and the call site; credentials and opaque tokens are masked by the shared contract (`sdk/rasp/README.md`, "Masking"; attributes named like credentials masked whole, readable identifiers kept, masked before cutting); at most 500 records a second per handler, batched; sending never fails the application. Matches the Python SDK.
- RASP allow-list targets: with the signed config's `reportTargets: true`, `shell_spawn.shell`, `outbound.not_allowed` and `path.outside_root` events carry the masked destination as `shield360.rasp.target` (`rasp.MaskTarget`, `rasp.TargetDirectory`); `sql_injection` events from the SQL check carry `shield360.rasp.sql.dialect`. Passes the shared `sdk/rasp/testdata/targets.json`.
- RASP SQL lexer dialects `rasp.DialectOracle` (`oracle`) and `rasp.DialectDB2` (`db2`): Oracle `q'[…]'` / `nq'…'` alternative quoting, `:1` binds and `#` in identifiers, no backslash escapes; Db2 `X'…'`, `G'…'`, `GX'…'`, `UX'…'` and `BX'…'` strings. SQL Server `[…]` identifiers now honor the `]]` escape, and block comments nest in Db2, PostgreSQL and SQL Server. The Oracle `q'…'` delimiter may be any non-whitespace character, multibyte included. Passes the shared `sdk/rasp/testdata/sql-lexer.json`.
- Runtime protection (RASP), opt-in: the `rasp` package and `Config.Rasp` (or `SHIELD360_RASP=monitor|block`). `rasp.Middleware` for `net/http` (chi, gorilla, echo and gin through their standard adapters) records request input in the request context and runs virtual patches before the handler; model output from the OpenAI, Anthropic and vLLM instrumentation counts as untrusted input; every detector and lexer of the shared contract (`sdk/rasp/README.md`) with the same rule ids; a signed config verified against a pinned Ed25519 key; events and a components report to `/api/guard/events`.
- RASP sink wrappers, opt-in: `rasp.OpenSQL` / `rasp.WrapDriver` / `rasp.WrapConnector` check every `database/sql` statement once (DB, Conn and Tx); `rasp.CheckMongo` for MongoDB documents; `rasp.Command` / `rasp.CommandContext` in place of `exec.Command`; `rasp.NewTransport` / `rasp.WrapClient` check SSRF and the outbound allow-list before sending and the address actually dialed (DNS rebinding); file helpers (`rasp.Open`, `ReadFile`, `WriteFile`, `Rename`, ...); `rasp.CheckCode`, `rasp.CheckDeserialization`, `rasp.UnmarshalXML` / `rasp.CheckXML`; and `rasp.CheckResponses` for reflected XSS (monitor only).
- RASP upload file names: `rasp.Middleware` reads multipart file names from the body it buffers (and `rasp.RecordRequestBody` from a `*multipart.Form`) as input `body.<field>.filename`; a script-named upload is reported as `file_write.upload` at sink `request.upload`, and a later write named after it is caught by `file_write.script`.
- RASP security baseline: once per process, in the background, risky set-up (TLS checks off on `http.DefaultTransport`, `net/http/pprof` on the default mux in production, `GIN_MODE=debug` under production, root, an unpinned config key in production, an end-of-life Go line) is reported as monitor-only `baseline` events.
- RASP for gateways: `rasp.CaptureRequest`, `rasp.AppEngine` (one app's modes, signed config, events and request checks: virtual patches and `file_write.upload` on upload file names, plus `CheckResponse` for reflected XSS) and `rasp.StartApp`, so one process in front of several apps (Shield360 Edge) can protect each under its own application name.
- GenAI spans record their call site as `code.function.name`, `code.file.path` and `code.line.number`. Turn off with `SHIELD360_CAPTURE_CODE_LOCATION=false` or `Config.CaptureCodeLocation`; set the path root with `Config.CodeRoot` or `SHIELD360_CODE_ROOT`.
- Resource attributes `service.version`, `vcs.ref.head.revision`, `vcs.repository.url.full` and `vcs.ref.head.name`, resolved from config and `SHIELD360_*` env, then OTel env, then the binary's build info, then CI variables.
- Instrumentations set `gen_ai.operation.name` when the span starts.
- Feature flags: `shield360.Flags()` and the `flags` package poll an environment's flags and segments from `/api/flags/rules` (ETag, 30 s with jitter) and evaluate them locally with a port of the shared engine, held to `sdk/flags-core/testdata/vectors.json`. Typed getters, `GetFlagDetail`, `IsEnabled`, and AI helpers `Model`, `KillSwitch` and `Prompt` (a flag choosing a Prompt Hub prompt). Served variations are stamped on the active span as `shield360.flag.<key>`. New `Config.Shield360URL` and `Config.Shield360APIKey`, falling back to `SHIELD360_URL` and `SHIELD360_API_KEY`.

### Fixed
- RASP custom request rules: `rasp.Middleware` judges the head before it reads the body, so head rules no longer see body inputs or upload file names, and a request without a body has a known, empty body, so body-phase rules (such as `request.body["x"] == null`) run.

### Changed
- Message content is no longer captured by default. `Config.CaptureMessageContent` (new) or `OTEL_INSTRUMENTATION_GENAI_CAPTURE_MESSAGE_CONTENT=true` turns it on; `DisableCaptureMessageContent` still wins. A Shield360 organization stores content only when its Data retention setting allows it.

## [0.2.0] - 2026-03-25

### Added
- `EvaluateRule()` — Rule Engine SDK function to evaluate trace attributes against Shield360 rules and retrieve matching contexts, prompts, and evaluation configs
- `RuleEntityType` constants: `RuleEntityContext`, `RuleEntityPrompt`, `RuleEntityEvaluation`
- `EvaluateRuleOptions` and `EvaluateRuleResult` types for structured request/response
- Environment variable fallbacks: `SHIELD360_URL` and `SHIELD360_API_KEY`
- Standalone HTTP call — does not require `shield360.Init()`
- Unit tests with `httptest` for all success/error/timeout paths
- Documentation in README with usage examples and parameter reference

## [0.1.0] - 2026-02-26

### Added
- Initial release of the Shield360 Go SDK
- OpenTelemetry-native instrumentation for OpenAI (chat completions, streaming, embeddings, image generation)
- OpenTelemetry-native instrumentation for Anthropic (messages, streaming, tool use)
- Automatic token usage tracking with `gen_ai.client.token.usage` histogram
- Operation duration metric `gen_ai.client.operation.duration`
- Streaming metrics: `gen_ai.server.time_to_first_token`, `gen_ai.server.time_per_output_token`, `gen_ai.client.operation.time_to_first_chunk`, `gen_ai.client.operation.time_per_output_chunk`, `gen_ai.server.request.duration`
- Error-path metrics with `error.type` dimension on all non-streaming operations
- Automatic cost calculation using built-in pricing data
- Prompt cache token tracking for Anthropic (`cache_creation_input_tokens`, `cache_read_input_tokens`)
- `DisableCaptureMessageContent` flag for privacy-sensitive workloads
- Configurable OTLP endpoint, headers, export interval, and timeouts
- `shield360.sdk.version` resource attribute on all telemetry
- OTel semantic conventions alignment with Python and TypeScript SDKs
