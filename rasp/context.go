package rasp

import (
	"context"
	"net/http"
	"strings"
	"sync"
)

// Context is the RASP context of the request (or worker job) being served,
// carried in a context.Context. Inputs live here, in memory, for the life of
// the request only; nothing in this package sends or stores them anywhere
// else. It is safe for concurrent use: a handler may fan out goroutines that
// share it.
type Context struct {
	mu     sync.Mutex
	inputs []Input
	// trees are the parsed body and query (for nosql_injection).
	trees []any

	inRequest bool
	method    string
	path      string
	route     string
	framework string
	// ip is the client address as the server reports it (custom rules'
	// request.ip): the peer address, never X-Forwarded-For.
	ip string
	// ruleSt is the custom rule state of the request (customrules.go).
	ruleSt *ruleState

	vp *vpState
	// uploads are the upload names recorded (field, name), so each is
	// checked once.
	uploads map[string]bool

	// req is the request the middleware handed on: a ServeMux sets its
	// Pattern when it routes it, after capture.
	req         *http.Request
	patternDone bool
}

// vpState is the virtual-patch state of a request: the request as the rules
// see it, and which phases have run.
type vpState struct {
	req       VpRequest
	bodyKnown bool
	ranHead   bool
	ranBody   bool
	// bodyAssumed: the body is known only because the request had none
	// (markEmptyBody); a body the app still records adds its inputs.
	bodyAssumed bool
}

type ctxKey struct{}

// FromContext returns the RASP context in ctx, or nil.
func FromContext(ctx context.Context) *Context {
	if ctx == nil {
		return nil
	}
	c, _ := ctx.Value(ctxKey{}).(*Context)
	return c
}

func withContext(ctx context.Context, c *Context) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	return context.WithValue(ctx, ctxKey{}, c)
}

// WithScope returns ctx carrying a fresh RASP context that is not a request:
// a worker acting on a model's answer wraps its job in it, so model output
// the LLM instrumentation records is checked at the job's sinks.
func WithScope(ctx context.Context) context.Context {
	return withContext(ctx, &Context{})
}

// WithInputs returns ctx carrying a RASP context that holds the given inputs
// (workers, tests). Inputs are taken as given, not normalized; AddInput and
// AddModelOutput build normalized lists.
func WithInputs(ctx context.Context, inputs []Input) context.Context {
	c := &Context{inputs: append([]Input(nil), inputs...)}
	return withContext(ctx, c)
}

// Inputs returns the inputs recorded so far. The slice must not be modified.
func (c *Context) Inputs() []Input {
	if c == nil {
		return nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.fromPatternLocked()
	return c.inputs[:len(c.inputs):len(c.inputs)]
}

// Trees returns the parsed body and query trees.
func (c *Context) Trees() []any {
	if c == nil {
		return nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.trees[:len(c.trees):len(c.trees)]
}

// InRequest reports whether the context is an HTTP request's.
func (c *Context) InRequest() bool { return c != nil && c.inRequest }

// Method returns the request method ("" outside a request).
func (c *Context) Method() string {
	if c == nil {
		return ""
	}
	return c.method
}

// Path returns the request path ("" outside a request).
func (c *Context) Path() string {
	if c == nil {
		return ""
	}
	return c.path
}

// Route returns the route template, when known.
func (c *Context) Route() string {
	if c == nil {
		return ""
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.fromPatternLocked()
	return c.route
}

// Framework returns the framework name ("net/http" for Middleware).
func (c *Context) Framework() string {
	if c == nil {
		return ""
	}
	return c.framework
}

// add appends inputs under the lock with fn.
func (c *Context) add(fn func(list *[]Input)) {
	c.mu.Lock()
	defer c.mu.Unlock()
	fn(&c.inputs)
}

// RecordRoute gives the current request its route template and route
// parameters, for routers whose templates the middleware cannot see (chi,
// gorilla/mux, gin, echo). Parameters become params.<name> inputs. A no-op
// outside a request.
func RecordRoute(ctx context.Context, route string, params map[string]string) {
	c := FromContext(ctx)
	if c == nil || !c.inRequest {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if route != "" {
		c.route = route
	}
	if len(params) > 0 {
		flatten(&c.inputs, params, "params", 0)
	}
}

func isHexLower(c byte) bool { return isDigitByte(c) || (c >= 'a' && c <= 'f') }

// isIDSegment: all digits, a UUID, or at least 8 hex characters with a digit
// (case-insensitive).
func isIDSegment(s string) bool {
	if s == "" {
		return false
	}
	l := strings.ToLower(s)
	digits, hex := true, true
	hasDigit := false
	for i := 0; i < len(l); i++ {
		c := l[i]
		if !isDigitByte(c) {
			digits = false
		} else {
			hasDigit = true
		}
		if !isHexLower(c) {
			hex = false
		}
	}
	if digits {
		return true
	}
	if hex && len(l) >= 8 && hasDigit {
		return true
	}
	if len(l) == 36 {
		for i := 0; i < 36; i++ {
			c := l[i]
			if i == 8 || i == 13 || i == 18 || i == 23 {
				if c != '-' {
					return false
				}
			} else if !isHexLower(c) {
				return false
			}
		}
		return true
	}
	return false
}

// RouteOf is the route fallback: all-digit, UUID and hex (8+, with a digit)
// segments become :id.
func RouteOf(p string) string {
	if i := strings.IndexByte(p, '?'); i >= 0 {
		p = p[:i]
	}
	segs := strings.Split(p, "/")
	for i, s := range segs {
		if isIDSegment(s) {
			segs[i] = ":id"
		}
	}
	return strings.Join(segs, "/")
}

// isKeptSegment: a short lower-case word (^[a-z][a-z_.-]{0,15}$) or an API
// version (^v\d{1,2}$).
func isKeptSegment(s string) bool {
	if s == "" || len(s) > 16 {
		return false
	}
	if s[0] == 'v' && len(s) <= 3 && len(s) > 1 {
		allDigits := true
		for i := 1; i < len(s); i++ {
			if !isDigitByte(s[i]) {
				allDigits = false
			}
		}
		if allDigits {
			return true
		}
	}
	if s[0] < 'a' || s[0] > 'z' {
		return false
	}
	for i := 1; i < len(s); i++ {
		c := s[i]
		if !(c >= 'a' && c <= 'z') && c != '_' && c != '.' && c != '-' {
			return false
		}
	}
	return true
}

// EventRouteOf is the route every event carries when the framework gave no
// template (README "Event route"): the route fallback, then every segment
// that is not a short lower-case word (or an API version such as v2) becomes
// :id, so a token, name or other value in the path never reaches an event.
func EventRouteOf(p string) string {
	segs := strings.Split(RouteOf(p), "/")
	for i, s := range segs {
		if s != "" && s != ":id" && !isKeptSegment(s) {
			segs[i] = ":id"
		}
	}
	return strings.Join(segs, "/")
}
