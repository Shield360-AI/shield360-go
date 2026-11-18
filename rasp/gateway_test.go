package rasp

import (
	"bytes"
	"context"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

func gwNoEnv(string) string { return "" }

type gwLog struct {
	mu     sync.Mutex
	events []Event
}

func (l *gwLog) add(_ context.Context, e Event) {
	l.mu.Lock()
	l.events = append(l.events, e)
	l.mu.Unlock()
}

func (l *gwLog) all() []Event {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]Event(nil), l.events...)
}

func gwMultipart(t *testing.T, field, filename string) ([]byte, string) {
	t.Helper()
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	_ = mw.WriteField("title", "quarterly notes")
	fw, err := mw.CreateFormFile(field, filename)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = fw.Write([]byte("hello"))
	_ = mw.Close()
	return buf.Bytes(), mw.FormDataContentType()
}

func TestCaptureRequestInputs(t *testing.T) {
	r := httptest.NewRequest("POST", "/orders/42?q=blue+shoes&page=2", strings.NewReader(""))
	r.Header.Set("User-Agent", "test-agent/1.0")
	r.Header.Set("Cookie", "theme=dark")
	r.Header.Set("Content-Type", "application/json")
	c := CaptureRequest(r, []byte(`{"user":{"name":"Ada Lovelace"}}`), "")
	keys := map[string]string{}
	for _, in := range c.Inputs() {
		keys[in.Key] = in.Value
	}
	for k, v := range map[string]string{"query.q": "blue shoes", "query.page": "2", "cookie.theme": "dark", "header.user-agent": "test-agent/1.0", "body.user.name": "Ada Lovelace"} {
		if keys[k] != v {
			t.Errorf("input %s = %q, want %q (all: %v)", k, keys[k], v, keys)
		}
	}
	if c.Framework() != GatewayFramework || c.Method() != "POST" || c.Path() != "/orders/42" {
		t.Errorf("context = %s %s %s", c.Framework(), c.Method(), c.Path())
	}
	if vp := c.VpRequest(); vp.Query != "q=blue+shoes&page=2" || vp.Body == "" {
		t.Errorf("vp request = %+v", vp)
	}
}

func TestAppEngineUploadNames(t *testing.T) {
	body, ct := gwMultipart(t, "attachment", "build.sh")
	r := httptest.NewRequest("POST", "/upload", bytes.NewReader(body))
	r.Header.Set("Content-Type", ct)
	log := &gwLog{}
	e := NewAppEngine(AppOptions{App: "files-api", Getenv: gwNoEnv, OnEvent: log.add})
	c, blocked := e.InspectRequest(r, body, "")
	if blocked != nil {
		t.Fatalf("monitor mode blocked: %v", blocked)
	}
	found := false
	for _, in := range c.Inputs() {
		found = found || (in.Key == "body.attachment.filename" && in.Value == "build.sh")
	}
	if !found {
		t.Errorf("upload name not recorded: %v", c.Inputs())
	}
	ev := log.all()
	if len(ev) != 1 || ev[0].Attrs["shield360.rasp.rule"] != "file_write.upload" || ev[0].Attrs["shield360.rasp.sink"] != UploadSink || ev[0].Attrs["shield360.rasp.decision"] != "monitored" {
		t.Fatalf("events = %+v", ev)
	}
	if ev[0].Attrs["shield360.rasp.app"] != "files-api" || ev[0].Attrs["shield360.rasp.input_key"] != "body.attachment.filename" {
		t.Errorf("attrs = %v", ev[0].Attrs)
	}

	// A picture is not a script.
	body, ct = gwMultipart(t, "attachment", "photo.png")
	r = httptest.NewRequest("POST", "/upload", bytes.NewReader(body))
	r.Header.Set("Content-Type", ct)
	log2 := &gwLog{}
	e2 := NewAppEngine(AppOptions{App: "files-api", Getenv: gwNoEnv, OnEvent: log2.add, Attacks: map[AttackType]Mode{FileWrite: ModeBlock}})
	if _, b := e2.InspectRequest(r, body, ""); b != nil || len(log2.all()) != 0 {
		t.Errorf("benign upload: blocked=%v events=%v", b, log2.all())
	}
}

func TestAppEngineVirtualPatchModes(t *testing.T) {
	req := func() *httptestRequest { return newTestRequest("x-shield360-rasp-test", "exploit") }

	log := &gwLog{}
	mon := NewAppEngine(AppOptions{App: "shop", Getenv: gwNoEnv, OnEvent: log.add})
	if _, b := mon.InspectRequest(req().r, nil, ""); b != nil {
		t.Fatal("monitor blocked")
	}
	if ev := log.all(); len(ev) != 1 || ev[0].Attrs["shield360.rasp.rule"] != "vp.example-test-header" || ev[0].Attrs["shield360.rasp.mode"] != "monitor" {
		t.Fatalf("events = %+v", ev)
	}

	blk := NewAppEngine(AppOptions{App: "shop", Getenv: gwNoEnv, Attacks: map[AttackType]Mode{VirtualPatch: ModeBlock}})
	_, b := blk.InspectRequest(req().r, nil, "")
	if b == nil || b.Rule != "vp.example-test-header" || len(b.EventID) != 32 {
		t.Fatalf("block = %+v", b)
	}

	// No pinned key while a signed config was expected: monitor only.
	capped := NewAppEngine(AppOptions{App: "shop", Getenv: gwNoEnv, Mode: ModeBlock, MonitorOnly: true})
	if _, b := capped.InspectRequest(req().r, nil, ""); b != nil {
		t.Error("monitor-only engine blocked")
	}

	// The signed config wins over local options; its kill switch stops checks.
	blk.SetRemote(&Claims{Version: "v7", Mode: ModeMonitor})
	if _, b := blk.InspectRequest(req().r, nil, ""); b != nil {
		t.Error("remote monitor still blocked")
	}
	blk.SetRemote(&Claims{Version: "v8", KillSwitch: true, Mode: ModeBlock})
	if blk.Active() || blk.ModeFor(VirtualPatch) != ModeOff {
		t.Error("kill switch ignored")
	}

	// SHIELD360_RASP=off always wins.
	off := NewAppEngine(AppOptions{App: "shop", Mode: ModeBlock, Getenv: func(k string) string {
		if k == "SHIELD360_RASP" {
			return "off"
		}
		return ""
	}})
	if off.Active() {
		t.Error("env kill switch ignored")
	}

	// Benign request: nothing.
	quiet := &gwLog{}
	q := NewAppEngine(AppOptions{App: "shop", Getenv: gwNoEnv, OnEvent: quiet.add, Mode: ModeBlock})
	if _, b := q.InspectRequest(newTestRequest("x-trace", "abc").r, nil, ""); b != nil || len(quiet.all()) != 0 {
		t.Errorf("benign: %v %v", b, quiet.all())
	}
}

func TestAppEngineRuntimeScopedRules(t *testing.T) {
	// A node-only rule applies when the runtime is unknown or node, not go.
	r := newTestRequest("x-middleware-subrequest", "1").r
	for rt, want := range map[string]bool{"": true, "node": true, "go": false} {
		e := NewAppEngine(AppOptions{App: "a", Getenv: gwNoEnv, Runtime: rt, RuntimeVersion: "22.1.0", Attacks: map[AttackType]Mode{VirtualPatch: ModeBlock}})
		_, b := e.InspectRequest(r, nil, "")
		if (b != nil) != want {
			t.Errorf("runtime %q: blocked=%v want %v", rt, b != nil, want)
		}
	}
}

func TestAppEngineXSSNeverBlocks(t *testing.T) {
	val := "<b onclick=x>hello world</b>"
	r := httptest.NewRequest("GET", "/search?q="+strings.ReplaceAll(val, " ", "%20"), nil)
	log := &gwLog{}
	e := NewAppEngine(AppOptions{App: "web", Getenv: gwNoEnv, Mode: ModeBlock, OnEvent: log.add})
	c, _ := e.InspectRequest(r, nil, "")
	e.CheckResponse(context.Background(), c, "text/html; charset=utf-8", []byte("<p>You searched "+val+"</p>"))
	ev := log.all()
	if len(ev) != 1 || ev[0].Attrs["shield360.rasp.rule"] != "xss.reflected" || ev[0].Attrs["shield360.rasp.decision"] != "monitored" {
		t.Fatalf("events = %+v", ev)
	}
	e.CheckResponse(context.Background(), c, "application/json", []byte(val))
	if len(log.all()) != 1 {
		t.Error("non-HTML response checked")
	}
}

type httptestRequest struct{ r *http.Request }

func newTestRequest(header, value string) *httptestRequest {
	r := httptest.NewRequest("GET", "/", nil)
	r.Header.Set(header, value)
	return &httptestRequest{r: r}
}

func TestAppEngineDeception(t *testing.T) {
	r := httptest.NewRequest("GET", "/wp-admin/setup", nil)
	log := &gwLog{}
	e := NewAppEngine(AppOptions{App: "web", Getenv: gwNoEnv, OnEvent: log.add})
	if d, b := e.ReportDeception(context.Background(), r, "deception.hit", false); d != DecisionMonitored || b != nil {
		t.Fatalf("monitor: %v %v", d, b)
	}
	d, b := e.ReportDeception(context.Background(), r, "deception.suspicious", true)
	if d != DecisionBlocked || b == nil || b.Attack != Deception {
		t.Fatalf("block: %v %v", d, b)
	}
	ev := log.all()
	if len(ev) != 2 || ev[0].Attrs["shield360.rasp.attack"] != "deception" || ev[0].Attrs["shield360.rasp.rule"] != "deception.hit" || ev[0].Attrs["shield360.rasp.sink"] != DeceptionSink || ev[1].Attrs["shield360.rasp.decision"] != "blocked" || ev[0].Attrs["shield360.rasp.route"] != "/wp-admin/setup" {
		t.Fatalf("events = %+v", ev)
	}
	// No pinned key while a signed config was expected: monitor only.
	capped := NewAppEngine(AppOptions{App: "web", Getenv: gwNoEnv, MonitorOnly: true})
	if d, _ := capped.ReportDeception(context.Background(), r, "deception.suspicious", true); d != DecisionMonitored {
		t.Errorf("monitor-only engine: %v", d)
	}
	// The signed config's attacks.deception caps the gateway's action, as
	// for every attack type: off reports nothing, monitor lowers block, and
	// block never raises a monitoring gateway.
	e.SetRemote(&Claims{Version: "v2", Attacks: map[AttackType]Mode{Deception: ModeOff}})
	if d, _ := e.ReportDeception(context.Background(), r, "deception.hit", true); d != DecisionNone {
		t.Errorf("remote off: %v", d)
	}
	e.SetRemote(&Claims{Version: "v3", Attacks: map[AttackType]Mode{Deception: ModeBlock}})
	if d, _ := e.ReportDeception(context.Background(), r, "deception.suspicious", false); d != DecisionMonitored {
		t.Errorf("remote block raised a monitoring gateway: %v", d)
	}
	if d, _ := e.ReportDeception(context.Background(), r, "deception.suspicious", true); d != DecisionBlocked {
		t.Errorf("remote block, gateway block: %v", d)
	}
	e.SetRemote(&Claims{Version: "v4", Attacks: map[AttackType]Mode{Deception: ModeMonitor}})
	if d, b := e.ReportDeception(context.Background(), r, "deception.suspicious", true); d != DecisionMonitored || b != nil {
		t.Errorf("remote monitor did not cap: %v %v", d, b)
	}
	// The default mode does not decide deception: the gateway's action does.
	e.SetRemote(&Claims{Version: "v5", Mode: ModeMonitor})
	if d, _ := e.ReportDeception(context.Background(), r, "deception.suspicious", true); d != DecisionBlocked {
		t.Errorf("default mode capped deception: %v", d)
	}
}

// Upload names go through the package's own capture: recorded once per
// request (a name repeated in the body is one input and one check), and
// checked with DetectUpload.
func TestAppEngineUploadNamesRecordedOnce(t *testing.T) {
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	for i := 0; i < 2; i++ {
		fw, _ := mw.CreateFormFile("attachment", "build.sh")
		_, _ = fw.Write([]byte("hello"))
	}
	_ = mw.Close()
	body := buf.Bytes()
	r := httptest.NewRequest("POST", "/upload", bytes.NewReader(body))
	r.Header.Set("Content-Type", mw.FormDataContentType())
	log := &gwLog{}
	e := NewAppEngine(AppOptions{App: "files-api", Getenv: gwNoEnv, OnEvent: log.add})
	c, _ := e.InspectRequest(r, body, "")
	n := 0
	for _, in := range c.Inputs() {
		if in.Key == "body.attachment.filename" {
			n++
		}
	}
	if n != 1 {
		t.Errorf("upload name recorded %d times", n)
	}
	if ev := log.all(); len(ev) != 1 || ev[0].Attrs["shield360.rasp.sink"] != UploadSink {
		t.Errorf("events = %+v", ev)
	}
}

func TestAppEngineBaselineNeverBlocks(t *testing.T) {
	e := NewAppEngine(AppOptions{App: "a", Getenv: gwNoEnv, Mode: ModeBlock})
	if e.ModeFor(Baseline) != ModeMonitor || e.ModeFor(XSS) != ModeMonitor || e.ModeFor(VirtualPatch) != ModeBlock {
		t.Errorf("modes: baseline %s xss %s vp %s", e.ModeFor(Baseline), e.ModeFor(XSS), e.ModeFor(VirtualPatch))
	}
}
