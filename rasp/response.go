package rasp

import (
	"bufio"
	"net"
	"net/http"
	"strings"
	"sync"
)

// Response sink (README "XSS"): HTML responses are checked for reflected
// input (xss.reflected). Monitor only: the response is never changed,
// delayed or blocked. Bytes go to the client first and a copy (at most
// 1 MiB; larger bodies are not checked) is judged when the handler returns.

// CheckResponses wraps a handler so its HTML responses are checked for
// reflected input. Put it inside Middleware, so the request's inputs are in
// scope:
//
//	http.ListenAndServe(":8080", rasp.Middleware(rasp.CheckResponses(mux)))
func CheckResponses(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rw, done := WrapResponseWriter(w, r)
		defer done()
		next.ServeHTTP(rw, r)
	})
}

// WrapResponseWriter returns w wrapped to copy an HTML body, and the
// function to call once the response is complete; it hands the copy to a
// background check and returns at once. Outside a RASP context, or with RASP
// off, it returns w itself. The wrapper has exactly the underlying writer's
// http.Flusher, http.Hijacker and http.Pusher, and Unwrap for
// http.ResponseController.
func WrapResponseWriter(w http.ResponseWriter, r *http.Request) (http.ResponseWriter, func()) {
	if !Active() || r == nil || FromContext(r.Context()) == nil || ModeFor(XSS) == ModeOff {
		return w, func() {}
	}
	x := &xssWriter{ResponseWriter: w, r: r}
	f, isF := w.(http.Flusher)
	h, isH := w.(http.Hijacker)
	p, isP := w.(http.Pusher)
	var hj http.Hijacker
	if isH {
		hj = xssHijacker{x, h}
	}
	switch {
	case isF && isH && isP:
		return struct {
			*xssWriter
			http.Flusher
			http.Hijacker
			http.Pusher
		}{x, f, hj, p}, x.finish
	case isF && isH:
		return struct {
			*xssWriter
			http.Flusher
			http.Hijacker
		}{x, f, hj}, x.finish
	case isF && isP:
		return struct {
			*xssWriter
			http.Flusher
			http.Pusher
		}{x, f, p}, x.finish
	case isH && isP:
		return struct {
			*xssWriter
			http.Hijacker
			http.Pusher
		}{x, hj, p}, x.finish
	case isF:
		return struct {
			*xssWriter
			http.Flusher
		}{x, f}, x.finish
	case isH:
		return struct {
			*xssWriter
			http.Hijacker
		}{x, hj}, x.finish
	case isP:
		return struct {
			*xssWriter
			http.Pusher
		}{x, p}, x.finish
	}
	return x, x.finish
}

type xssWriter struct {
	http.ResponseWriter
	r        *http.Request
	decided  bool
	collect  bool
	ctype    string
	buf      []byte
	finished bool
}

// xssHijacker hands the connection over; the response is then not checked.
type xssHijacker struct {
	x *xssWriter
	h http.Hijacker
}

func (j xssHijacker) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	j.x.collect, j.x.buf = false, nil
	return j.h.Hijack()
}

func (x *xssWriter) decide(first []byte) {
	if x.decided {
		return
	}
	x.decided = true
	defer func() { _ = recover() }()
	ct := x.Header().Get("Content-Type")
	if ct == "" && len(first) > 0 {
		ct = http.DetectContentType(first) // what net/http will send
	}
	x.ctype = ct
	x.collect = strings.Contains(strings.ToLower(ct), "html")
}

func (x *xssWriter) Write(p []byte) (int, error) {
	n, err := x.ResponseWriter.Write(p)
	if !x.decided {
		x.decide(p)
	}
	if x.collect && n > 0 {
		if len(x.buf)+n > MaxXSSBody {
			x.collect, x.buf = false, nil
		} else {
			x.buf = append(x.buf, p[:n]...)
		}
	}
	return n, err
}

// Unwrap returns the underlying writer (http.ResponseController).
func (x *xssWriter) Unwrap() http.ResponseWriter { return x.ResponseWriter }

// xssSlots bounds the response checks running at once; a response that
// finds every slot busy is not checked (monitoring never queues or waits).
var xssSlots = make(chan struct{}, 8)

// xssPending tracks the background checks (tests wait on it).
var xssPending sync.WaitGroup

func (x *xssWriter) finish() {
	if x.finished {
		return
	}
	x.finished = true
	body := x.buf
	x.buf = nil
	if !x.collect || len(body) == 0 {
		return
	}
	ctx := x.r.Context()
	inputs := inputsOf(ctx)
	if len(inputs) == 0 {
		return
	}
	select {
	case xssSlots <- struct{}{}:
	default:
		return
	}
	ctype := x.ctype
	xssPending.Add(1)
	// The body is this writer's own copy; the request's context keeps its
	// values after the handler returns. XSS never blocks, so the result is
	// only reported.
	go func() {
		defer func() {
			<-xssSlots
			xssPending.Done()
		}()
		_ = checkSink(ctx, "http.response", func(*iastSlot) *Finding { return DetectXSS(ctype, string(body), inputs) })
	}()
}
