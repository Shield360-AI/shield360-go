package shield360

import (
	"context"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"runtime/debug"
	"strings"
	"sync"

	"github.com/ThinkfleetAI/shield360-go/semconv"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
)

// Code location attributes (OTel semantic conventions 1.30+).
const (
	attrCodeFunctionName = "code.function.name"
	attrCodeFilePath     = "code.file.path"
	attrCodeLineNumber   = "code.line.number"

	sdkModulePath     = "github.com/ThinkfleetAI/shield360-go"
	maxCodeCacheSize  = 4096
	maxCallerFrames   = 64
	envCaptureCodeLoc = "SHIELD360_CAPTURE_CODE_LOCATION"
	// SHIELD: code cost — outbound calls carry their call site too.
	envCaptureCallLoc = "SHIELD360_CAPTURE_CALL_LOCATION"
	envCodeRoot       = "SHIELD360_CODE_ROOT"
)

// skippedModules are never treated as application code: the SDK itself,
// OpenTelemetry and the provider client libraries it wraps.
var skippedModules = []string{
	sdkModulePath,
	"go.opentelemetry.io/",
	"github.com/openai/",
	"github.com/anthropics/",
	"github.com/sashabaranov/",
}

// codeLocation is the cached result for one program counter.
type codeLocation struct {
	function string
	file     string
	line     int
	found    bool
}

// codeLocationProcessor adds code.function.name, code.file.path and
// code.line.number to GenAI spans. OnStart runs synchronously on the
// goroutine that starts the span, so the caller's stack is still visible.
type codeLocationProcessor struct {
	codeRoot   string
	cwd        string
	home       string
	modulePath string
	ignore     []string
	calls      bool

	mu    sync.RWMutex
	cache map[uintptr]codeLocation
}

// NewCodeLocationProcessor returns the span processor that records the
// application call site on GenAI spans, or nil when capture is disabled by
// Config.CaptureCodeLocation or SHIELD360_CAPTURE_CODE_LOCATION. Init
// registers it automatically; use it directly only with your own
// TracerProvider.
func NewCodeLocationProcessor(cfg Config) sdktrace.SpanProcessor {
	if !captureCodeLocation(cfg) {
		return nil
	}
	p := &codeLocationProcessor{
		codeRoot: cleanRoot(firstNonEmpty(cfg.CodeRoot, os.Getenv(envCodeRoot))),
		ignore:   cfg.CodeLocationIgnoreModules,
		calls:    captureCallLocation(cfg),
		cache:    make(map[uintptr]codeLocation),
	}
	if wd, err := os.Getwd(); err == nil {
		p.cwd = cleanRoot(wd)
	}
	if home, err := os.UserHomeDir(); err == nil {
		p.home = cleanRoot(home)
	}
	if bi, ok := debug.ReadBuildInfo(); ok {
		p.modulePath = bi.Main.Path
	}
	return p
}

// captureCodeLocation: the config field wins, then the env var; on by default.
func captureCodeLocation(cfg Config) bool {
	if cfg.CaptureCodeLocation != nil {
		return *cfg.CaptureCodeLocation
	}
	switch strings.ToLower(strings.TrimSpace(os.Getenv(envCaptureCodeLoc))) {
	case "false", "0", "no", "off":
		return false
	}
	return true
}

// captureCallLocation: the config field wins, then the env var; on by default.
func captureCallLocation(cfg Config) bool {
	if cfg.CaptureCallLocation != nil {
		return *cfg.CaptureCallLocation
	}
	switch strings.ToLower(strings.TrimSpace(os.Getenv(envCaptureCallLoc))) {
	case "false", "0", "no", "off":
		return false
	}
	return true
}

// callAttributes make a client span an outbound call worth locating.
var callAttributes = map[attribute.Key]bool{
	"db.system": true, "db.system.name": true, "http.request.method": true, "http.method": true,
	"url.full": true, "rpc.system": true, "messaging.system": true,
}

func (p *codeLocationProcessor) OnStart(_ context.Context, s sdktrace.ReadWriteSpan) {
	defer func() { _ = recover() }() // never break the caller

	isGenAI, isCall := false, false
	for _, kv := range s.Attributes() {
		switch {
		case kv.Key == attrCodeFunctionName || kv.Key == attrCodeFilePath || kv.Key == attrCodeLineNumber:
			return // never overwrite a location someone else set
		case kv.Key == semconv.GenAIOperationName:
			isGenAI = true
		case callAttributes[kv.Key]:
			isCall = true
		}
	}
	if kind := s.SpanKind(); kind != trace.SpanKindClient && kind != trace.SpanKindProducer {
		isCall = false
	}
	if !isGenAI && !(p.calls && isCall) {
		return
	}

	var pcs [maxCallerFrames]uintptr
	n := runtime.Callers(2, pcs[:])
	for _, pc := range pcs[:n] {
		loc := p.locate(pc)
		if !loc.found {
			continue
		}
		s.SetAttributes(
			attribute.String(attrCodeFunctionName, loc.function),
			attribute.String(attrCodeFilePath, loc.file),
			attribute.Int(attrCodeLineNumber, loc.line),
		)
		return
	}
}

// locate classifies one return PC (including any frames inlined into it),
// caching the result.
func (p *codeLocationProcessor) locate(pc uintptr) codeLocation {
	p.mu.RLock()
	loc, ok := p.cache[pc]
	p.mu.RUnlock()
	if ok {
		return loc
	}

	frames := runtime.CallersFrames([]uintptr{pc})
	for {
		f, more := frames.Next()
		if f.Function != "" && !p.skipFrame(f) {
			loc = codeLocation{function: f.Function, file: p.normalisePath(f.File), line: f.Line, found: true}
			break
		}
		if !more {
			break
		}
	}

	p.mu.Lock()
	if len(p.cache) < maxCodeCacheSize {
		p.cache[pc] = loc
	}
	p.mu.Unlock()
	return loc
}

// skipFrame reports whether a frame belongs to the runtime, the standard
// library, the SDK, OpenTelemetry, a provider library or an ignored module.
func (p *codeLocationProcessor) skipFrame(f runtime.Frame) bool {
	pkg := packagePath(f.Function)
	if hasModulePrefix(pkg, sdkModulePath) {
		// The SDK's own tests act as application code.
		return !strings.HasSuffix(f.File, "_test.go")
	}
	if pkg == "main" || hasModulePrefix(pkg, p.modulePath) {
		return false
	}
	first, _, _ := strings.Cut(pkg, "/")
	if !strings.Contains(first, ".") {
		return true // runtime and standard library
	}
	for _, mods := range [][]string{skippedModules, p.ignore} {
		for _, m := range mods {
			if hasModulePrefix(pkg, m) {
				return true
			}
		}
	}
	return false
}

// packagePath extracts the import path from a runtime function name such as
// "github.com/acme/api/billing.(*Cart).Total".
func packagePath(function string) string {
	slash := strings.LastIndex(function, "/")
	if dot := strings.Index(function[slash+1:], "."); dot >= 0 {
		return function[:slash+1+dot]
	}
	return function
}

func hasModulePrefix(pkg, module string) bool {
	module = strings.TrimSuffix(module, "/")
	return module != "" && (pkg == module || strings.HasPrefix(pkg, module+"/"))
}

// normalisePath makes a file path repo-relative: explicit code root first,
// then the main module path (-trimpath builds), the working directory and
// the home directory. A binary built without -trimpath carries the build
// host's paths, which match none of those at run time, so an absolute path
// left over loses any home directory or CI workspace prefix
// (anonymiseAbsPath). No user's home directory is emitted.
func (p *codeLocationProcessor) normalisePath(file string) string {
	file = filepath.ToSlash(file)
	if rel, ok := trimRoot(file, p.codeRoot); ok {
		return rel
	}
	if !isAbsPath(file) {
		if rel, ok := trimRoot(file, p.modulePath); ok {
			return rel
		}
		return strings.TrimPrefix(file, "./")
	}
	if rel, ok := trimRoot(file, p.cwd); ok {
		return rel
	}
	if rel, ok := trimRoot(file, p.home); ok {
		return rel
	}
	return anonymiseAbsPath(file)
}

// buildHostPrefixes are CI workspace and home directory prefixes, CI first
// (a runner's workspace sits under its home). Matching is on forward slashes.
var buildHostPrefixes = []*regexp.Regexp{
	regexp.MustCompile(`^/home/runner/work/[^/]+/[^/]+/`),                     // GitHub Actions
	regexp.MustCompile(`^/github/workspace/`),                                 // GitHub container actions
	regexp.MustCompile(`^/home/vsts/work/[^/]+/s/`),                           // Azure Pipelines
	regexp.MustCompile(`^/builds/[^/]+/[^/]+/`),                               // GitLab CI
	regexp.MustCompile(`^/var/lib/buildkite-agent/builds/[^/]+/[^/]+/[^/]+/`), // Buildkite
	regexp.MustCompile(`^/(?:var/lib/jenkins|var/jenkins_home)/workspace/[^/]+/`),
	regexp.MustCompile(`^/opt/atlassian/pipelines/agent/build/`), // Bitbucket Pipelines
	regexp.MustCompile(`^/codebuild/output/src[^/]*/src/`),       // AWS CodeBuild
	regexp.MustCompile(`^/home/[^/]+/`),
	regexp.MustCompile(`^/Users/[^/]+/`),
	regexp.MustCompile(`^[A-Za-z]:/Users/[^/]+/`),
	regexp.MustCompile(`^/root/`),
}

// anonymiseAbsPath drops the first home directory or CI workspace prefix of
// an absolute path; other absolute paths (/srv/app/...) are kept.
func anonymiseAbsPath(file string) string {
	for _, re := range buildHostPrefixes {
		if loc := re.FindStringIndex(file); loc != nil {
			return file[loc[1]:]
		}
	}
	return file
}

func trimRoot(file, root string) (string, bool) {
	if root == "" || !strings.HasPrefix(file, root+"/") {
		return "", false
	}
	return file[len(root)+1:], true
}

func cleanRoot(dir string) string {
	if strings.TrimSpace(dir) == "" {
		return ""
	}
	return strings.TrimSuffix(filepath.ToSlash(filepath.Clean(dir)), "/")
}

func isAbsPath(file string) bool {
	return strings.HasPrefix(file, "/") || (len(file) > 2 && file[1] == ':' && file[2] == '/')
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}

func (p *codeLocationProcessor) OnEnd(sdktrace.ReadOnlySpan)      {}
func (p *codeLocationProcessor) Shutdown(context.Context) error   { return nil }
func (p *codeLocationProcessor) ForceFlush(context.Context) error { return nil }
