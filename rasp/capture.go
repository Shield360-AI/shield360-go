package rasp

import (
	"bytes"
	"context"
	"encoding/json"
	"mime"
	"mime/multipart"
	"net"
	"net/http"
	"sort"
	"strings"
)

// Request capture: turns a request into the context's inputs (README
// "Sources of untrusted input") and runs the virtual patches. Inputs stay in
// memory, in the request's context only.

// InputHeaders are the headers the contract treats as input (OpenRASP's
// headerInjection).
var InputHeaders = []string{"user-agent", "referer", "x-forwarded-for"}

// VpSink is the sink name of virtual-patch events.
const VpSink = "server.request"

// UploadSink is the sink name of file_write.upload events.
const UploadSink = "request.upload"

// Upload file names (README "Path", file_write.upload): at most maxUploads
// names per request, read from the part headers in the first maxUploadScan
// bytes of a raw multipart body, or from a parsed *multipart.Form.
const (
	maxUploadScan = 1024 * 1024
	maxUploads    = 32
)

type upload struct{ field, name string }

// partUploads returns the uploads named in the part headers of a raw
// multipart/form-data body. It walks the parts with mime/multipart over a
// copy of the first maxUploadScan bytes, using the boundary from the content
// type, so only real part headers count (parameters quoted or not, in any
// order) and part bodies are skipped; the names are what the handler's
// parser will see (multipart.FileHeader.Filename).
func partUploads(raw []byte, contentType string) (out []upload) {
	defer func() {
		if recover() != nil {
			out = nil
		}
	}()
	mt, params, err := mime.ParseMediaType(contentType)
	if err != nil || !strings.EqualFold(mt, "multipart/form-data") || params["boundary"] == "" || len(raw) == 0 {
		return nil
	}
	if len(raw) > maxUploadScan {
		raw = raw[:maxUploadScan]
	}
	mr := multipart.NewReader(bytes.NewReader(raw), params["boundary"])
	for len(out) < maxUploads {
		p, err := mr.NextRawPart()
		if err != nil {
			break // the end, a malformed body, or the scan cap
		}
		if name := p.FileName(); name != "" {
			field := p.FormName()
			if field == "" {
				field = "file"
			}
			out = append(out, upload{field: field, name: name})
		}
	}
	return out
}

// formUploads returns the uploads of a parsed *multipart.Form, fields in
// sorted order.
func formUploads(form *multipart.Form) []upload {
	if form == nil || len(form.File) == 0 {
		return nil
	}
	var out []upload
	fields := make([]string, 0, len(form.File))
	for k := range form.File {
		fields = append(fields, k)
	}
	sort.Strings(fields)
	for _, field := range fields {
		for _, fh := range form.File[field] {
			if len(out) >= maxUploads {
				return out
			}
			if fh != nil && fh.Filename != "" {
				out = append(out, upload{field: field, name: fh.Filename})
			}
		}
	}
	return out
}

// recordUploadsLocked records upload names as input body.<field>.filename,
// skipping names the request already recorded and keeping at most
// maxUploads per request. It returns the new ones for checkUploads. Called
// with c.mu held.
func (c *Context) recordUploadsLocked(ups []upload) []upload {
	var fresh []upload
	for _, u := range ups {
		if len(c.uploads) >= maxUploads {
			break
		}
		k := u.field + "\x00" + u.name
		if c.uploads[k] {
			continue
		}
		if c.uploads == nil {
			c.uploads = map[string]bool{}
		}
		c.uploads[k] = true
		addInput(&c.inputs, u.name, "body."+u.field+".filename", SourceRequest)
		fresh = append(fresh, u)
	}
	return fresh
}

// checkUploads runs file_write.upload on each uploaded file name, at sink
// request.upload. Detection reads the whole name (the input entry is
// truncated; the extension must not be lost). It returns only the block
// error.
func checkUploads(c *Context, uploads []upload) error {
	if len(uploads) == 0 {
		return nil
	}
	ctx := withContext(context.Background(), c)
	for _, u := range uploads {
		err := checkSink(ctx, UploadSink, func(*iastSlot) *Finding { return uploadFinding(u) })
		if err != nil {
			return err
		}
	}
	return nil
}

// uploadFinding runs file_write.upload on one upload. Detection reads the
// whole name (the input entry is truncated; the extension must not be lost).
// Middleware and the gateway engine (gateway.go) both use it.
func uploadFinding(u upload) *Finding {
	f := DetectUpload(Input{Value: u.name, Key: "body." + u.field + ".filename", Source: SourceRequest})
	if f != nil && f.Input != nil {
		f.Input.Value = truncChars(f.Input.Value, MaxValue)
	}
	return f
}

// patternRoute returns the path part of a ServeMux pattern
// ("GET example.com/items/{id}" -> "/items/{id}") and its wildcard names.
func patternRoute(pattern string) (string, []string) {
	p := pattern
	if i := strings.IndexAny(p, " \t"); i >= 0 {
		p = strings.TrimLeft(p[i:], " \t")
	}
	if i := strings.IndexByte(p, '/'); i > 0 {
		p = p[i:]
	} else if i < 0 {
		return "", nil
	}
	var names []string
	rest := p
	for {
		open := strings.IndexByte(rest, '{')
		if open < 0 {
			break
		}
		end := strings.IndexByte(rest[open:], '}')
		if end < 0 {
			break
		}
		name := strings.TrimSuffix(rest[open+1:open+end], "...")
		if name != "" && name != "$" {
			names = append(names, name)
		}
		rest = rest[open+end+1:]
	}
	return p, names
}

// fromPatternLocked takes the route template and path parameters from the
// request's ServeMux pattern once the mux has matched it. Called with c.mu
// held.
func (c *Context) fromPatternLocked() {
	if c.req == nil || c.patternDone || c.req.Pattern == "" {
		return
	}
	c.patternDone = true
	route, names := patternRoute(c.req.Pattern)
	if c.route == "" && route != "" {
		c.route = route
	}
	for _, n := range names {
		addInput(&c.inputs, c.req.PathValue(n), "params."+n, SourceRequest)
	}
}

func headerValue(h http.Header, name string) string {
	return strings.Join(h.Values(name), ", ")
}

// captureRequest builds the request's context: query, route parameters (when
// the ServeMux pattern is known), cookies and the input headers.
func captureRequest(r *http.Request, framework string) *Context {
	path := r.URL.EscapedPath()
	if path == "" {
		path = "/"
	}
	rawQuery := r.URL.RawQuery
	c := &Context{inRequest: true, method: r.Method, path: path, framework: framework, ip: peerIP(r.RemoteAddr)}
	if rawQuery != "" {
		tree := map[string]any{}
		for _, kv := range parseQuery(rawQuery) {
			addInput(&c.inputs, kv[1], "query."+kv[0], SourceRequest)
			switch prev := tree[kv[0]].(type) {
			case nil:
				tree[kv[0]] = kv[1]
			case string:
				tree[kv[0]] = []any{prev, kv[1]}
			case []any:
				tree[kv[0]] = append(prev, kv[1])
			}
		}
		c.trees = append(c.trees, tree)
	}
	cookie := strings.Join(r.Header.Values("Cookie"), "; ")
	for _, kv := range parseCookies(cookie) {
		addInput(&c.inputs, kv[1], "cookie."+kv[0], SourceRequest)
	}
	for _, h := range InputHeaders {
		if v := headerValue(r.Header, h); v != "" {
			addInput(&c.inputs, v, "header."+h, SourceRequest)
		}
	}
	headers := make(map[string]string, len(r.Header))
	for k, v := range r.Header {
		headers[strings.ToLower(k)] = strings.Join(v, ", ")
	}
	if r.Host != "" {
		if _, ok := headers["host"]; !ok {
			headers["host"] = r.Host
		}
	}
	c.vp = &vpState{req: VpRequest{Method: r.Method, Path: path, Query: rawQuery, Headers: headers, Cookie: cookie}}
	c.req = r
	c.fromPatternLocked()
	return c
}

// peerIP is the client address of a request's RemoteAddr ("ip:port", or a
// bare address), without the port or IPv6 brackets.
func peerIP(remote string) string {
	if host, _, err := net.SplitHostPort(remote); err == nil {
		return host
	}
	return strings.TrimSuffix(strings.TrimPrefix(remote, "["), "]")
}

func isFormType(ct string) bool { return strings.Contains(ct, "application/x-www-form-urlencoded") }

// captureBody adds the body to the context: string leaves of a parsed body
// (body.a.b), form fields, or the raw text when it is text, unparsed and at
// most 8 KiB. It also gives the virtual patches the body text. body is raw
// bytes or text ([]byte, string), a *multipart.Form, or an already parsed
// value. The names of uploaded files are recorded as body.<field>.filename
// and returned for checkUploads.
func (c *Context) captureBody(body any, contentType string) (uploads []upload) {
	if body == nil {
		return nil
	}
	ct := strings.ToLower(contentType)
	raw := ""
	c.mu.Lock()
	defer c.mu.Unlock()
	var data []byte
	isRaw := true
	switch b := body.(type) {
	case []byte:
		data = b
	case string:
		data = []byte(b)
	case json.RawMessage:
		data = b
	default:
		isRaw = false
	}
	var form *multipart.Form
	switch f := body.(type) {
	case *multipart.Form:
		form = f
	case multipart.Form:
		form = &f
	}
	if isRaw {
		raw = string(data)
		parsed := false
		if strings.Contains(ct, "json") {
			trimmed := strings.TrimLeft(raw, " \t\r\n")
			if (strings.HasPrefix(trimmed, "{") || strings.HasPrefix(trimmed, "[")) && flattenJSON(&c.inputs, data, "body") {
				var tree any
				if json.Unmarshal(data, &tree) == nil {
					c.trees = append(c.trees, tree)
				}
				parsed = true
			}
		} else if isFormType(ct) {
			formText := raw
			if len(formText) > 1024*1024 {
				formText = formText[:1024*1024]
			}
			// URLSearchParams into an object: the last value wins, in the
			// position of the key's first occurrence.
			tree := map[string]any{}
			var order []string
			for _, kv := range parseQuery(formText) {
				if _, ok := tree[kv[0]]; !ok {
					order = append(order, kv[0])
				}
				tree[kv[0]] = kv[1]
			}
			for _, k := range order {
				addInput(&c.inputs, tree[k].(string), "body."+k, SourceRequest)
			}
			c.trees = append(c.trees, tree)
			parsed = true
		}
		if !parsed && len(raw) <= MaxRawBody {
			addInput(&c.inputs, raw, "body", SourceRequest)
		}
	} else if form != nil {
		if form.Value != nil {
			flatten(&c.inputs, form.Value, "body", 0)
			c.trees = append(c.trees, form.Value)
			if b, err := json.Marshal(form.Value); err == nil {
				raw = string(b)
			}
		}
	} else {
		flatten(&c.inputs, body, "body", 0)
		c.trees = append(c.trees, body)
		if b, err := json.Marshal(body); err == nil {
			raw = string(b)
		}
	}
	if c.vp != nil {
		c.vp.req.Body = capText(raw)
		c.vp.bodyKnown = true
		c.vp.bodyAssumed = false
	}
	if isRaw {
		return c.recordUploadsLocked(partUploads(data, contentType))
	}
	return c.recordUploadsLocked(formUploads(form))
}

// markEmptyBody makes the body known and empty (a request without one), so
// the body phase runs with no body inputs. A body the app records later
// still adds its inputs for the built-in checks (RecordRequestBody).
func (c *Context) markEmptyBody() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.vp != nil {
		c.vp.bodyKnown = true
		c.vp.bodyAssumed = true
	}
}

// recordFormUploads records and returns the upload names of a parsed form
// that the request has not recorded yet (a form given after Middleware
// buffered the body).
func (c *Context) recordFormUploads(body any) []upload {
	var form *multipart.Form
	switch f := body.(type) {
	case *multipart.Form:
		form = f
	case multipart.Form:
		form = &f
	default:
		return nil
	}
	ups := formUploads(form)
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.recordUploadsLocked(ups)
}

// runVirtualPatches runs the virtual patches the request can be judged by so
// far: rules that do not read the body at once, rules that do once the body
// is known. Each set runs once, followed by the custom request rules of the
// same phase (README "Custom rules"). It returns the block error when a
// blocking rule matches; any other failure lets the request through.
func runVirtualPatches(c *Context) error {
	c.mu.Lock()
	vp := c.vp
	if vp == nil {
		c.mu.Unlock()
		return nil
	}
	var phases []VpPhase
	if !vp.ranHead {
		vp.ranHead = true
		phases = append(phases, PhaseHead)
	}
	if vp.bodyKnown && !vp.ranBody {
		vp.ranBody = true
		phases = append(phases, PhaseBody)
	}
	req := vp.req
	c.mu.Unlock()
	rules := VirtualPatches()
	extra := FindingExtra{Framework: c.framework, Method: c.method, Path: c.path, Route: c.Route()}
	ctx := withContext(context.Background(), c)
	for _, phase := range phases {
		f := safeMatch(&req, rules, phase)
		// A monitored match is reported and the next phase still runs; a
		// blocked one returns.
		if f != nil {
			if _, err := handleFindingSafe(ctx, f, extra); err != nil {
				return err
			}
		}
		if err := runRequestRules(c, phase, extra); err != nil {
			return err
		}
	}
	return nil
}

func safeMatch(req *VpRequest, rules []VirtualPatchRule, phase VpPhase) (f *Finding) {
	defer func() {
		if recover() != nil {
			f = nil
		}
	}()
	return MatchVirtualPatches(req, rules, phase, Runtime, RuntimeVersion())
}

func handleFindingSafe(ctx context.Context, f *Finding, extra FindingExtra) (d Decision, err error) {
	defer func() {
		if recover() != nil {
			d, err = DecisionNone, nil
		}
	}()
	return HandleFinding(ctx, f, VpSink, extra)
}
