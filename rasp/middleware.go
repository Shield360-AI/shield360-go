package rasp

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
)

// net/http middleware. It records the request's inputs (query, route
// parameters, body, cookies, the contract's input headers) in a RASP context
// carried by the request's context.Context, runs the virtual patches before
// the handler, and maps the block error to the contract's 403.
//
// It is a plain func(http.Handler) http.Handler, so it works with
// http.ServeMux, chi (r.Use(rasp.Middleware)), gorilla/mux
// (r.Use(rasp.Middleware)), echo (e.Use(echo.WrapMiddleware(rasp.Middleware)))
// and anything else that adapts standard middleware. While RASP is not active
// it passes the request straight through.

// Framework is the framework name events carry for Middleware.
const Framework = "net/http"

// maxBodyRead is how much of a request body the middleware buffers to judge
// it (the rest is streamed to the handler untouched).
const maxBodyRead = 1024 * 1024

var bodyMethods = map[string]bool{http.MethodPost: true, http.MethodPut: true, http.MethodPatch: true, http.MethodDelete: true}

// WriteBlocked writes the contract's 403 for a block error and reports
// whether err was one. Handlers use it where a sink returned an error:
//
//	if rasp.WriteBlocked(w, err) { return }
func WriteBlocked(w http.ResponseWriter, err error) bool {
	b := AsBlocked(err)
	if b == nil {
		return false
	}
	defer func() { _ = recover() }() // the response is already gone
	body, _ := json.Marshal(BodyOf(b))
	h := w.Header()
	h.Set("Content-Type", "application/json")
	h.Set("Cache-Control", "no-store")
	h.Del("Content-Length")
	w.WriteHeader(http.StatusForbidden)
	_, _ = w.Write(body)
	return true
}

// errReader returns err on every read: the error the buffered read hit,
// replayed to the handler after the bytes read before it.
type errReader struct{ err error }

func (e errReader) Read([]byte) (int, error) { return 0, e.err }

// bufferedBody replays the bytes read to judge the body, then the rest.
type bufferedBody struct {
	io.Reader
	closer io.Closer
}

func (b *bufferedBody) Close() error { return b.closer.Close() }

// readBody buffers at most maxBodyRead bytes of the request body and puts
// them back in front of the rest, so the handler reads the whole body. A
// read error (a body that ends early) is not swallowed: the handler reads
// the bytes that arrived, then the same error.
func readBody(r *http.Request) []byte {
	if r.Body == nil || r.Body == http.NoBody || !bodyMethods[strings.ToUpper(r.Method)] {
		return nil
	}
	buf, err := io.ReadAll(io.LimitReader(r.Body, maxBodyRead))
	var rest io.Reader = r.Body
	if err != nil {
		rest = errReader{err}
	}
	r.Body = &bufferedBody{Reader: io.MultiReader(bytes.NewReader(buf), rest), closer: r.Body}
	return buf
}

// begin captures the request. It returns the RASP context, or the block
// error when a virtual patch blocks; a nil context means capture failed
// (fail open).
func begin(r *http.Request) (c *Context, blocked error) {
	defer func() {
		if recover() != nil {
			c, blocked = nil, nil
		}
	}()
	c = captureRequest(r, Framework)
	// The head phase runs before the body is read, so its rules see only
	// the inputs known before the body (README "When rules run").
	if err := runVirtualPatches(c); err != nil {
		return nil, err
	}
	if body := readBody(r); body != nil {
		// Upload file names are read from the buffered bytes; the handler
		// still reads the whole body.
		if err := checkUploads(c, c.captureBody(body, r.Header.Get("Content-Type"))); err != nil {
			return nil, err
		}
	} else if r.Body == nil || r.Body == http.NoBody {
		// No body: a known, empty one, so the body phase still runs.
		c.markEmptyBody()
	}
	if err := runVirtualPatches(c); err != nil {
		return nil, err
	}
	return c, nil
}

// Middleware wraps a handler with RASP request capture. The request body of
// POST, PUT, PATCH and DELETE requests is buffered up to 1 MiB to judge it
// before the handler, and replayed to the handler in full.
//
// A sink that blocks returns the block error to the code that called it;
// the handler maps it with WriteBlocked. A handler that panics with a block
// error gets the 403 from the middleware; every other panic propagates.
func Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !Active() {
			next.ServeHTTP(w, r)
			return
		}
		// Deception first: a decoy never reaches the handler and gets the
		// standard library's not-found answer (README "Deception").
		switch v, b := checkDeception(r.Context(), r, Framework); v {
		case deceptionNotFound:
			http.NotFound(w, r)
			return
		case deceptionBlocked:
			WriteBlocked(w, b)
			return
		}
		c, blocked := begin(r)
		if blocked != nil {
			WriteBlocked(w, blocked)
			return
		}
		if c == nil {
			next.ServeHTTP(w, r)
			return
		}
		r2 := r.WithContext(withContext(r.Context(), c))
		c.mu.Lock()
		c.req = r2
		c.mu.Unlock()
		defer func() {
			if v := recover(); v != nil {
				if err, ok := v.(error); ok && WriteBlocked(w, err) {
					return
				}
				panic(v)
			}
		}()
		next.ServeHTTP(w, r2)
	})
}

// RecordRequestBody adds a body the app read itself (or a parsed value) to
// the current request's inputs and runs the virtual patches that read the
// body. It returns the block error when one blocks; otherwise nil. A no-op
// when the body is already known (Middleware buffered it) or outside a
// request. On a request Middleware saw without a body (a known, empty one)
// the body still becomes input for the built-in checks, once; the body
// phase already ran and does not run again.
func RecordRequestBody(ctx context.Context, body any, contentType string) (err error) {
	if !Active() {
		return nil
	}
	c := FromContext(ctx)
	if c == nil || !c.inRequest {
		return nil
	}
	defer func() {
		if recover() != nil {
			err = nil
		}
	}()
	c.mu.Lock()
	known := c.vp != nil && c.vp.bodyKnown
	assumed := known && c.vp.bodyAssumed
	c.mu.Unlock()
	if assumed {
		// Known only because the request had none: the body the app read
		// still becomes input for the built-in checks. The custom body
		// phase already ran on the empty body and does not run again.
		return checkUploads(c, c.captureBody(body, contentType))
	}
	if known {
		// The body was captured already; a parsed form can still name
		// uploads the raw scan did not find.
		return checkUploads(c, c.recordFormUploads(body))
	}
	// Judge the head first when nothing has yet (a context from
	// CaptureRequest), so head rules never see the body inputs.
	if err := runVirtualPatches(c); err != nil {
		return err
	}
	if err := checkUploads(c, c.captureBody(body, contentType)); err != nil {
		return err
	}
	return runVirtualPatches(c)
}
