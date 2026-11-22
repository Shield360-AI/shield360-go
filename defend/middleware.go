package defend

import (
	"context"
	"net/http"
)

// net/http middleware: each request is decided before the handler. A denied
// one gets Defend's 403 (401 for require_sign_in), a honeypot decoy gets its
// fake file, and an allowed one goes on with the Result in its context
// (ResultFrom) and, with honeypots on, the crumb header (X-Debug-Trace) on
// its response.
//
// The client address is the connection's peer (r.RemoteAddr);
// X-Forwarded-For is read only with FactsOptions.TrustProxy. With
// SharedRateLimits on, a decision may wait on Shield360 for up to its
// timeout.

type resultKey struct{}

// MiddlewareOptions configure the middleware.
type MiddlewareOptions struct {
	// Content reads text to check from the request (the prompt in a
	// header or query; read the body in the handler and call Defend
	// yourself for body content).
	Content func(*http.Request) []string
}

// ResultFrom is the Defend result the middleware stored in the request's
// context.
func ResultFrom(ctx context.Context) (Result, bool) {
	r, ok := ctx.Value(resultKey{}).(Result)
	return r, ok
}

// Middleware wraps a handler.
func (d *Defend) Middleware(next http.Handler) http.Handler {
	return d.MiddlewareWith(MiddlewareOptions{}, next)
}

// MiddlewareWith wraps a handler with options.
func (d *Defend) MiddlewareWith(o MiddlewareOptions, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var call Call
		if o.Content != nil {
			func() {
				defer func() { _ = recover() }()
				call.Content = o.Content(r)
			}()
		}
		res := d.Defend(RequestOf(r), call)
		if answer := ResponseFor(res); answer != nil {
			for _, h := range answer.Headers {
				w.Header().Set(h[0], h[1])
			}
			w.WriteHeader(answer.Status)
			if r.Method != http.MethodHead {
				_, _ = w.Write([]byte(answer.Body))
			}
			return
		}
		if res.CrumbHeader != "" {
			w.Header().Set("X-Debug-Trace", res.CrumbHeader)
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), resultKey{}, res)))
	})
}
