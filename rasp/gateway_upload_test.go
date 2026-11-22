package rasp

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestAppEngineInspectUpload(t *testing.T) {
	log := &gwLog{}
	e := NewAppEngine(AppOptions{App: "files-api", Getenv: gwNoEnv, OnEvent: log.add})
	polyglot := append(append([]byte{}, jpegFixture...), shellFixture...)
	extra := FindingExtra{Framework: GatewayFramework, Method: "POST", Path: "/api/avatar", Route: "/api/avatar"}
	v, d, b := e.InspectUpload(context.Background(), bytes.NewReader(polyglot), "me.jpg", "image/jpeg", UploadOptions{Field: "avatar"}, extra)
	if b != nil || d != DecisionMonitored || v.Type != "jpeg" {
		t.Fatalf("monitor: %v %v %+v", d, b, v)
	}
	ev := log.all()
	if len(ev) != 1 {
		t.Fatalf("events %v", ev)
	}
	a := ev[0].Attrs
	if a["shield360.rasp.sink"] != EdgeUploadSink || a["shield360.rasp.rule"] != "upload.webshell" || a["shield360.rasp.attack"] != "malicious_upload" ||
		a["shield360.rasp.upload.signature"] != "php.eval_request" || a["shield360.rasp.upload.type"] != "jpeg" || a["shield360.rasp.input_key"] != "body.avatar.filename" ||
		len(a["shield360.rasp.upload.sha256"]) != 64 || a["shield360.rasp.route"] != "/api/avatar" {
		t.Errorf("attrs %v", a)
	}
	for _, val := range a {
		if strings.Contains(val, "me.jpg") || strings.Contains(val, "eval(") {
			t.Errorf("an attribute carries the name or content: %q", val)
		}
	}

	// The route's mode blocks; a capped rule never does; a clean file says nothing.
	if _, d, b := e.InspectUpload(context.Background(), bytes.NewReader(shellFixture), "a.jpg", "", UploadOptions{Mode: ModeBlock}, extra); b == nil || d != DecisionBlocked || b.Rule != "upload.webshell" {
		t.Errorf("route block: %v %v", d, b)
	}
	if _, d, b := e.InspectUpload(context.Background(), bytes.NewReader(zipFixture(t, zipEntryFixture{name: "a.txt", data: []byte("a")})), "a.jpg", "", UploadOptions{Mode: ModeBlock}, extra); b != nil || d != DecisionMonitored {
		t.Errorf("capped mismatch: %v %v", d, b)
	}
	n := len(log.all())
	if _, d, b := e.InspectUpload(context.Background(), bytes.NewReader(pngFixture), "a.png", "image/png", UploadOptions{Mode: ModeBlock}, extra); b != nil || d != DecisionNone || len(log.all()) != n {
		t.Errorf("clean: %v %v", d, b)
	}

	// A local off for malicious_upload wins over a route's block; the kill switch reports nothing.
	off := NewAppEngine(AppOptions{App: "a", Getenv: gwNoEnv, Attacks: map[AttackType]Mode{MaliciousUpload: ModeOff}})
	if _, d, b := off.InspectUpload(context.Background(), bytes.NewReader(shellFixture), "a.jpg", "", UploadOptions{Mode: ModeBlock}, extra); b != nil || d != DecisionNone {
		t.Errorf("local off: %v %v", d, b)
	}
	// No pinned key: a route's block is lowered to monitor.
	mo := NewAppEngine(AppOptions{App: "a", Getenv: gwNoEnv, MonitorOnly: true})
	if _, d, b := mo.InspectUpload(context.Background(), bytes.NewReader(shellFixture), "a.jpg", "", UploadOptions{Mode: ModeBlock}, extra); b != nil || d != DecisionMonitored {
		t.Errorf("monitor only: %v %v", d, b)
	}
	e.Disable()
	if _, d, _ := e.InspectUpload(context.Background(), bytes.NewReader(shellFixture), "a.jpg", "", UploadOptions{Mode: ModeBlock}, extra); d != DecisionNone {
		t.Errorf("disabled: %v", d)
	}
}

func TestAppEngineUploadOptionsFor(t *testing.T) {
	e := NewAppEngine(AppOptions{App: "a", Getenv: gwNoEnv})
	if o := e.UploadOptionsFor("/api/avatar"); o.Mode != "" || o.Allow != nil {
		t.Errorf("no config: %+v", o)
	}
	exp := float64(time.Now().Add(time.Hour).Unix())
	e.SetRemote(&Claims{Version: "v", Exp: exp, Attacks: map[AttackType]Mode{}, Uploads: json.RawMessage(`{"allow":["image"],"routes":[{"route":"/api/*","allow":["pdf"],"mode":"block"}]}`)})
	if o := e.UploadOptionsFor("/api/avatar"); o.Mode != ModeBlock || o.Allow[0] != "pdf" {
		t.Errorf("route: %+v", o)
	}
	if o := e.UploadOptionsFor("/other"); o.Mode != "" || o.Allow[0] != "image" {
		t.Errorf("app: %+v", o)
	}
	v := InspectUploadBytes(pdfFixture, "a.pdf", "application/pdf")
	if _, b := e.ReportUpload(context.Background(), v, e.UploadOptionsFor("/other"), EdgeUploadSink, FindingExtra{}); b != nil {
		t.Errorf("app policy is monitor by default: %v", b)
	}
	if _, b := e.ReportUpload(context.Background(), InspectUploadBytes(pngFixture, "a.png", ""), e.UploadOptionsFor("/api/x"), EdgeUploadSink, FindingExtra{}); b == nil || b.Rule != "upload.type_not_allowed" {
		t.Errorf("route allow list: %v", b)
	}
}

func TestUploadEventAttrs(t *testing.T) {
	v := InspectUploadBytes(append(append([]byte{}, jpegFixture...), shellFixture...), "x.jpg", "")
	a := UploadEventAttrs(v, v.Findings[0])
	if a["shield360.rasp.upload.type"] != "jpeg" || a["shield360.rasp.upload.signature"] != "php.eval_request" || a["shield360.rasp.upload.engine"] != "builtin" || a["shield360.rasp.upload.ext"] != "jpg" {
		t.Errorf("%v", a)
	}
}

// A ';' without a dot used to panic HasDoubleExtension (found by Edge's FuzzUploadPart).
func TestUploadNameWithoutDotNeverPanics(t *testing.T) {
	for _, name := range []string{";", "a;b", ";;", "x;.", "dir/;"} {
		_ = HasDoubleExtension(name)
		_ = InspectUploadBytes([]byte("0"), name, "0")
	}
	if !HasDoubleExtension("shell.asp;.jpg") || HasDoubleExtension("a;b") {
		t.Error("semicolon names")
	}
}
