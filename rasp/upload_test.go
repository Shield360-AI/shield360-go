package rasp

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
)

// Upload file names: read from raw multipart bodies and from a parsed
// *multipart.Form, recorded as request input, checked by file_write.upload,
// and then seen by file_write.script when the app writes a file named after
// them.

type part struct{ name, filename, body string }

const testBoundary = "----shield360test"

func multipartBody(parts ...part) (string, string) {
	var b strings.Builder
	for _, p := range parts {
		b.WriteString("--" + testBoundary + "\r\nContent-Disposition: form-data; name=\"" + p.name + "\"")
		if p.filename != "" {
			b.WriteString("; filename=\"" + p.filename + "\"")
		}
		b.WriteString("\r\n\r\n" + p.body + "\r\n")
	}
	b.WriteString("--" + testBoundary + "--\r\n")
	return b.String(), "multipart/form-data; boundary=" + testBoundary
}

// scriptName builds a fixture file name with a script extension.
func scriptName(base, ext string) string { return strings.Join([]string{base, ext}, ".") }

func uploadCtx() *Context {
	return captureRequest(httptest.NewRequest(http.MethodPost, "/upload", nil), Framework)
}

func TestUploadNames(t *testing.T) {
	t.Run("reads file names from raw multipart part headers, not plain fields", func(t *testing.T) {
		body, ct := multipartBody(part{"title", "", "Quarterly report"}, part{"attachment", "report.pdf", "fixture"})
		got := partUploads([]byte(body), ct)
		if !reflect.DeepEqual(got, []upload{{field: "attachment", name: "report.pdf"}}) {
			t.Errorf("got %v", got)
		}
	})

	t.Run("only for multipart/form-data", func(t *testing.T) {
		body, _ := multipartBody(part{"attachment", "report.pdf", "fixture"})
		if got := partUploads([]byte(body), "text/plain"); len(got) != 0 {
			t.Errorf("got %v", got)
		}
	})

	t.Run("reads a parsed *multipart.Form", func(t *testing.T) {
		form := &multipart.Form{File: map[string][]*multipart.FileHeader{
			"docs":   {{Filename: "a.txt"}, {Filename: "b.txt"}},
			"avatar": {{Filename: "me.png"}},
		}}
		want := []upload{{"avatar", "me.png"}, {"docs", "a.txt"}, {"docs", "b.txt"}}
		if got := formUploads(form); !reflect.DeepEqual(got, want) {
			t.Errorf("got %v", got)
		}
	})

	t.Run("caps the number of names read", func(t *testing.T) {
		var parts []part
		for i := 0; i < 40; i++ {
			parts = append(parts, part{fmt.Sprintf("f%d", i), fmt.Sprintf("x%d.txt", i), "1"})
		}
		body, ct := multipartBody(parts...)
		if got := partUploads([]byte(body), ct); len(got) != maxUploads {
			t.Errorf("names %d", len(got))
		}
	})

	t.Run("reads only the first 1 MiB", func(t *testing.T) {
		body, ct := multipartBody(part{"pad", "", strings.Repeat("a", maxUploadScan)}, part{"attachment", "late.txt", "1"})
		if got := partUploads([]byte(body), ct); len(got) != 0 {
			t.Errorf("got %v", got)
		}
	})
}

func TestDetectUpload(t *testing.T) {
	in := func(v string) Input { return Input{Value: v, Key: "body.file.filename", Source: SourceRequest} }
	for _, name := range []string{scriptName("page", "php"), scriptName("run", "sh"), scriptName("handler", "JSP"), "x/../" + scriptName("y", "py"), scriptName("tool", "exe")} {
		if f := DetectUpload(in(name)); f == nil || f.Rule != "file_write.upload" || f.Attack != FileWrite || f.Input == nil || f.Input.Key != "body.file.filename" {
			t.Errorf("%s: %+v", name, f)
		}
	}
	for _, name := range []string{"report.pdf", "photo.jpeg", "notes.txt", "archive.tar.gz", "php.txt"} {
		if f := DetectUpload(in(name)); f != nil {
			t.Errorf("%s: %+v", name, f)
		}
	}
}

func TestCapturedUploads(t *testing.T) {
	page := scriptName("page", "php")

	t.Run("records the file name as input and reports a script upload in monitor", func(t *testing.T) {
		log := setupEngine(t, engineSettings{})
		c := uploadCtx()
		body, ct := multipartBody(part{"attachment", page, "fixture"})
		if err := checkUploads(c, c.captureBody([]byte(body), ct)); err != nil {
			t.Fatal(err)
		}
		found := false
		for _, i := range c.Inputs() {
			found = found || (i.Key == "body.attachment.filename" && i.Value == page)
		}
		if !found {
			t.Errorf("inputs %v", c.Inputs())
		}
		ev := log.all()
		if len(ev) != 1 || ev[0].Attrs["shield360.rasp.rule"] != "file_write.upload" || ev[0].Attrs["shield360.rasp.sink"] != "request.upload" ||
			ev[0].Attrs["shield360.rasp.input_key"] != "body.attachment.filename" || ev[0].Attrs["shield360.rasp.decision"] != "monitored" {
			t.Errorf("events %v", ev)
		}
	})

	t.Run("lets an ordinary upload through without a report", func(t *testing.T) {
		log := setupEngine(t, engineSettings{})
		c := uploadCtx()
		body, ct := multipartBody(part{"attachment", "report.pdf", "fixture"})
		if err := checkUploads(c, c.captureBody([]byte(body), ct)); err != nil || len(log.all()) != 0 {
			t.Errorf("err %v events %v", err, log.all())
		}
	})

	t.Run("a later write named after the upload is caught by file_write.script", func(t *testing.T) {
		setupEngine(t, engineSettings{})
		c := uploadCtx()
		c.captureBody(&multipart.Form{File: map[string][]*multipart.FileHeader{"f": {{Filename: page}}}}, "")
		f := DetectPath("/srv/app/public/"+page, OpWrite, c.Inputs(), nil, true)
		if f == nil || f.Rule != "file_write.script" || f.Input == nil || f.Input.Key != "body.f.filename" {
			t.Errorf("finding %+v", f)
		}
	})

	t.Run("Middleware blocks a script upload when file_write blocks; the handler never runs", func(t *testing.T) {
		log := setupEngine(t, engineSettings{attacks: map[AttackType]Mode{FileWrite: ModeBlock}})
		ran := false
		h := Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { ran = true }))
		body, ct := multipartBody(part{"attachment", page, "fixture"})
		w := do(t, h, http.MethodPost, "/upload", body, map[string]string{"Content-Type": ct})
		if w.Code != 403 || ran {
			t.Fatalf("status %d ran %v", w.Code, ran)
		}
		if got := decode(t, w); got["rule"] != "file_write.upload" || got["attack"] != "file_write" {
			t.Errorf("body %v", got)
		}
		if ev := log.all(); len(ev) != 1 || ev[0].Attrs["shield360.rasp.framework"] != "net/http" || ev[0].Attrs["shield360.rasp.route"] != "/upload" {
			t.Errorf("events %v", ev)
		}
	})

	t.Run("Middleware leaves the multipart body whole for the handler", func(t *testing.T) {
		setupEngine(t, engineSettings{attacks: map[AttackType]Mode{FileWrite: ModeBlock}})
		content := strings.Repeat("fixture-", 1000)
		body, ct := multipartBody(part{"title", "", "Quarterly report"}, part{"attachment", "report.pdf", content})
		var gotName, gotContent, gotKey string
		h := Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			for _, i := range FromContext(r.Context()).Inputs() {
				if strings.HasSuffix(i.Key, ".filename") {
					gotKey = i.Key
				}
			}
			if err := r.ParseMultipartForm(1 << 20); err != nil {
				t.Errorf("parse: %v", err)
				return
			}
			fh := r.MultipartForm.File["attachment"][0]
			f, _ := fh.Open()
			b, _ := io.ReadAll(f)
			gotName, gotContent = fh.Filename, string(b)
		}))
		if w := do(t, h, http.MethodPost, "/upload", body, map[string]string{"Content-Type": ct}); w.Code != 200 {
			t.Fatalf("status %d", w.Code)
		}
		if gotName != "report.pdf" || gotContent != content || gotKey != "body.attachment.filename" {
			t.Errorf("name %q key %q content intact %v", gotName, gotKey, gotContent == content)
		}
	})

	t.Run("RecordRequestBody with a parsed form checks its uploads", func(t *testing.T) {
		setupEngine(t, engineSettings{attacks: map[AttackType]Mode{FileWrite: ModeBlock}})
		c := uploadCtx()
		ctx := withContext(context.Background(), c)
		form := &multipart.Form{Value: map[string][]string{"title": {"Quarterly report"}}, File: map[string][]*multipart.FileHeader{"f": {{Filename: page}}}}
		if b := AsBlocked(RecordRequestBody(ctx, form, "multipart/form-data")); b == nil || b.Rule != "file_write.upload" {
			t.Errorf("not blocked: %v", b)
		}
		found := false
		for _, i := range c.Inputs() {
			found = found || (i.Key == "body.title" && i.Value == "Quarterly report")
		}
		if !found {
			t.Errorf("form values not recorded: %v", c.Inputs())
		}
	})

	t.Run("a panic in the upload check fails open", func(t *testing.T) {
		setupEngine(t, engineSettings{attacks: map[AttackType]Mode{FileWrite: ModeBlock}})
		hook := func(sink string) {
			if sink == UploadSink {
				panic("boom")
			}
		}
		testHookDetect.Store(&hook)
		t.Cleanup(func() { testHookDetect.Store(nil) })
		ran := false
		h := Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { ran = true }))
		body, ct := multipartBody(part{"attachment", page, "fixture"})
		r := httptest.NewRequest(http.MethodPost, "/upload", bytes.NewReader([]byte(body)))
		r.Header.Set("Content-Type", ct)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if !ran || w.Code != 200 {
			t.Errorf("status %d ran %v", w.Code, ran)
		}
	})
}

// uploadEvents runs a multipart request through Middleware and returns the
// file_write.upload events and whether the handler ran.
func uploadEvents(t *testing.T, log *eventLog, body, ct string, handler func(*http.Request)) ([]Event, int) {
	t.Helper()
	h := Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if handler != nil {
			handler(r)
		}
	}))
	w := do(t, h, http.MethodPost, "/upload", body, map[string]string{"Content-Type": ct})
	var out []Event
	for _, e := range log.all() {
		if e.Attrs["shield360.rasp.rule"] == "file_write.upload" {
			out = append(out, e)
		}
	}
	return out, w.Code
}

func TestUploadPartHeaders(t *testing.T) {
	page := scriptName("page", "php")

	t.Run("unquoted parameters in either order are read as the handler's parser reads them", func(t *testing.T) {
		log := setupEngine(t, engineSettings{})
		body := "--" + testBoundary + "\r\nContent-Disposition: form-data; filename=" + page + "; name=attachment\r\n\r\nfixture\r\n--" + testBoundary + "--\r\n"
		var parsed string
		ev, code := uploadEvents(t, log, body, "multipart/form-data; boundary="+testBoundary, func(r *http.Request) {
			if err := r.ParseMultipartForm(1 << 20); err == nil && len(r.MultipartForm.File["attachment"]) == 1 {
				parsed = r.MultipartForm.File["attachment"][0].Filename
			}
		})
		if parsed != page {
			t.Fatalf("fixture not parsed by mime/multipart: %q", parsed)
		}
		if code != 200 || len(ev) != 1 || ev[0].Attrs["shield360.rasp.input_key"] != "body.attachment.filename" {
			t.Errorf("code %d events %v", code, ev)
		}
	})

	t.Run("a header quoted inside a text attachment's content is not a part header", func(t *testing.T) {
		log := setupEngine(t, engineSettings{attacks: map[AttackType]Mode{FileWrite: ModeBlock}})
		quoted := "Notes on uploads.\r\nContent-Disposition: form-data; name=\"x\"; filename=\"" + page + "\"\r\nEnd of notes."
		body, ct := multipartBody(part{"attachment", "notes.txt", quoted})
		ran := false
		ev, code := uploadEvents(t, log, body, ct, func(*http.Request) { ran = true })
		if code != 200 || !ran || len(ev) != 0 {
			t.Errorf("code %d ran %v events %v", code, ran, ev)
		}
	})

	t.Run("a long directory-qualified name keeps its extension for detection", func(t *testing.T) {
		log := setupEngine(t, engineSettings{})
		long := strings.Repeat("dir/", 1100) + page // longer than MaxValue
		body, ct := multipartBody(part{"attachment", long, "fixture"})
		if ev, _ := uploadEvents(t, log, body, ct, nil); len(ev) != 1 {
			t.Errorf("events %v", ev)
		}
	})

	t.Run("a parsed form with a long name is judged on the whole name", func(t *testing.T) {
		log := setupEngine(t, engineSettings{})
		c := uploadCtx()
		ctx := withContext(context.Background(), c)
		long := strings.Repeat("a", MaxValue+10) + "." + "php"
		form := &multipart.Form{File: map[string][]*multipart.FileHeader{"f": {{Filename: long}}}}
		_ = RecordRequestBody(ctx, form, "multipart/form-data")
		if n := len(log.all()); n != 1 {
			t.Errorf("events %d", n)
		}
		for _, i := range c.Inputs() {
			if i.Key == "body.f.filename" && len(i.Value) > MaxValue {
				t.Errorf("taint entry not truncated: %d", len(i.Value))
			}
		}
	})

	t.Run("a form given after Middleware buffered the body adds names the scan did not find, once each", func(t *testing.T) {
		log := setupEngine(t, engineSettings{})
		body, ct := multipartBody(part{"attachment", page, "fixture"})
		other := scriptName("tool", "sh")
		var recErr error
		ev, _ := uploadEvents(t, log, body, ct, func(r *http.Request) {
			form := &multipart.Form{File: map[string][]*multipart.FileHeader{
				"attachment": {{Filename: page}},
				"extra":      {{Filename: other}},
			}}
			recErr = RecordRequestBody(r.Context(), form, ct)
			_ = RecordRequestBody(r.Context(), form, ct)
		})
		if recErr != nil {
			t.Fatal(recErr)
		}
		keys := map[string]int{}
		for _, e := range ev {
			keys[e.Attrs["shield360.rasp.input_key"]]++
		}
		if len(ev) != 2 || keys["body.attachment.filename"] != 1 || keys["body.extra.filename"] != 1 {
			t.Errorf("events by key %v", keys)
		}
	})

	t.Run("a late form blocks when file_write blocks", func(t *testing.T) {
		setupEngine(t, engineSettings{attacks: map[AttackType]Mode{FileWrite: ModeBlock}})
		body, ct := multipartBody(part{"attachment", "report.pdf", "fixture"})
		var got *BlockedError
		uploadEvents(t, &eventLog{}, body, ct, func(r *http.Request) {
			form := &multipart.Form{File: map[string][]*multipart.FileHeader{"extra": {{Filename: page}}}}
			got = AsBlocked(RecordRequestBody(r.Context(), form, ct))
		})
		if got == nil || got.Rule != "file_write.upload" {
			t.Errorf("blocked %v", got)
		}
	})
}
