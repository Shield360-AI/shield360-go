package rasp

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// Deep scan and backdoor checks against a stand-in clamd (TCP and Unix
// socket) and a stand-in reputation endpoint. Never real malware: the
// stand-in flags a marker string.

const clamMarker = "SHIELD360-TEST-MALWARE-MARKER"

type fakeClamd struct {
	ln     net.Listener
	scans  atomic.Int32
	pings  atomic.Int32
	stall  atomic.Bool
	addr   ClamAddress
	closed sync.Once
}

func startClamd(t *testing.T, network string) *fakeClamd {
	t.Helper()
	var ln net.Listener
	var err error
	addr := ClamAddress{Network: network}
	if network == "unix" {
		dir, derr := os.MkdirTemp("", "cl")
		if derr != nil {
			t.Fatal(derr)
		}
		t.Cleanup(func() { _ = os.RemoveAll(dir) })
		addr.Address = filepath.Join(dir, "s")
		ln, err = net.Listen("unix", addr.Address)
	} else {
		ln, err = net.Listen("tcp", "127.0.0.1:0")
		if err == nil {
			addr.Address = ln.Addr().String()
		}
	}
	if err != nil {
		t.Fatal(err)
	}
	c := &fakeClamd{ln: ln, addr: addr}
	t.Cleanup(func() { c.close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go c.serve(conn)
		}
	}()
	return c
}

func (c *fakeClamd) close() { c.closed.Do(func() { _ = c.ln.Close() }) }

// settledScans is the scan count once it has stopped changing for 50ms.
func (c *fakeClamd) settledScans() int32 {
	n := c.scans.Load()
	for i := 0; i < 40; i++ {
		time.Sleep(50 * time.Millisecond)
		m := c.scans.Load()
		if m == n {
			return m
		}
		n = m
	}
	return n
}

func (c *fakeClamd) serve(conn net.Conn) {
	defer conn.Close()
	cmd := make([]byte, 0, 16)
	b := make([]byte, 1)
	for {
		if _, err := io.ReadFull(conn, b); err != nil {
			return
		}
		if b[0] == 0 {
			break
		}
		cmd = append(cmd, b[0])
	}
	switch string(cmd) {
	case "zPING":
		c.pings.Add(1)
		_, _ = conn.Write([]byte("PONG\x00"))
	case "zINSTREAM":
		c.scans.Add(1)
		var data []byte
		for {
			var n [4]byte
			if _, err := io.ReadFull(conn, n[:]); err != nil {
				return
			}
			size := binary.BigEndian.Uint32(n[:])
			if size == 0 {
				break
			}
			if size > clamChunk {
				_, _ = conn.Write([]byte("INSTREAM size limit exceeded. ERROR\x00"))
				return
			}
			part := make([]byte, size)
			if _, err := io.ReadFull(conn, part); err != nil {
				return
			}
			data = append(data, part...)
		}
		if c.stall.Load() {
			time.Sleep(2 * time.Second)
			return
		}
		if bytes.Contains(data, []byte(clamMarker)) {
			_, _ = conn.Write([]byte("stream: Shield360.Test-Marker FOUND\x00"))
		} else {
			_, _ = conn.Write([]byte("stream: OK\x00"))
		}
	}
}

func deepSetup(t *testing.T, s engineSettings) *eventLog {
	t.Helper()
	log := setupEngine(t, s)
	resetScanner()
	resetUploadLocations()
	setQuarantineDir(t.TempDir())
	t.Cleanup(func() {
		resetScanner()
		resetUploadLocations()
		setQuarantineDir("")
		setUploadEnv("", "", nil)
	})
	return log
}

func eventsNamed(log *eventLog, name string) []Event {
	var out []Event
	for _, e := range log.all() {
		if e.Name == name {
			out = append(out, e)
		}
	}
	return out
}

func TestParseClamAddressAndPolicy(t *testing.T) {
	for in, want := range map[string]*ClamAddress{
		"tcp:clamav.internal:3310": {"tcp", "clamav.internal:3310"},
		"tcp:[::1]:3310":           {"tcp", "[::1]:3310"},
		"unix:/run/clamd.sock":     {"unix", "/run/clamd.sock"},
		"unix:relative.sock":       nil,
		"tcp:host:0":               nil,
		"tcp:host:70000":           nil,
		"http://x":                 nil,
	} {
		got := ParseClamAddress(in)
		if (got == nil) != (want == nil) || (got != nil && *got != *want) {
			t.Errorf("%s: %+v", in, got)
		}
	}
	if a := ParseClamAddress(map[string]any{"address": "tcp:h:1"}); a == nil || a.Address != "h:1" {
		t.Error("object form")
	}
	p := ParseUploadPolicy(json.RawMessage(`{"servedDirs":["/srv/public","rel"],"deepScan":{"mode":"block","scan":"async","timeoutMs":50,"failMode":"closed","clamav":{"address":"tcp:c:3310"},"reputation":true,"testId":"t1"},
		"routes":[{"route":"/api/avatar","deepScan":"monitor","scan":"sync","timeoutMs":99999,"failMode":"open"}]}`))
	if p.DeepScanMode != ModeBlock || !p.DeepScan.Async || p.DeepScan.Timeout != 100*time.Millisecond || !p.DeepScan.FailClosed || p.DeepScan.ClamAV == nil || !p.DeepScan.Reputation || p.DeepScan.TestID != "t1" {
		t.Fatalf("%+v", p.DeepScan)
	}
	if len(p.ServedDirs) != 1 || p.ServedDirs[0] != "/srv/public" {
		t.Fatal(p.ServedDirs)
	}
	o := uploadOptionsFrom(&RemoteConfig{Uploads: p}, "/api/avatar")
	if o.DeepScanMode != ModeMonitor || o.DeepScan.Async || o.DeepScan.Timeout != time.Minute || o.DeepScan.FailClosed {
		t.Fatalf("route override %+v", o.DeepScan)
	}
	if d := ParseUploadPolicy(json.RawMessage(`{}`)); d.DeepScanMode != ModeOff || d.DeepScan.Timeout != 5*time.Second {
		t.Fatalf("defaults %+v", d.DeepScan)
	}
}

func TestClamScanOverTCPAndUnixSocket(t *testing.T) {
	for _, network := range []string{"tcp", "unix"} {
		c := startClamd(t, network)
		name, err := ClamScan(c.addr, strings.NewReader("x "+clamMarker+" y"), time.Second)
		if err != nil || name != "Shield360.Test-Marker" {
			t.Fatalf("%s: %q %v", network, name, err)
		}
		// Large files go in 64 KiB frames.
		big := bytes.Repeat([]byte("a"), 3*clamChunk+5)
		if name, err := ClamScan(c.addr, bytes.NewReader(big), time.Second); err != nil || name != "" {
			t.Fatalf("%s clean: %q %v", network, name, err)
		}
		if ok, err := ClamPing(c.addr, time.Second); !ok || err != nil {
			t.Fatalf("%s ping %v", network, err)
		}
	}
	c := startClamd(t, "tcp")
	c.stall.Store(true)
	var ee *EngineError
	if _, err := ClamScan(c.addr, strings.NewReader("x"), 200*time.Millisecond); !errors.As(err, &ee) || ee.Status != "timeout" {
		t.Fatalf("stall: %v", err)
	}
	c.close()
	if _, err := ClamScan(c.addr, strings.NewReader("x"), time.Second); !errors.As(err, &ee) || ee.Status != "unreachable" {
		t.Fatalf("closed: %v", err)
	}
}

func TestReputationLookupSendsOnlyTheHashAndCaches(t *testing.T) {
	deepSetup(t, engineSettings{})
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		raw, _ := io.ReadAll(r.Body)
		var b map[string]string
		_ = json.Unmarshal(raw, &b)
		if r.URL.Path != reputationPath || r.Header.Get("Authorization") != "Bearer k" || len(b) != 1 {
			w.WriteHeader(400)
			return
		}
		v := "clean"
		if strings.HasPrefix(b["sha256"], "bad") {
			v = "malicious"
		}
		_, _ = w.Write([]byte(`{"verdict":"` + v + `"}`))
	}))
	defer srv.Close()
	setUploadEnv(srv.URL, "k", srv.Client())
	if v, err := UploadReputation(context.Background(), "bad1", time.Second); err != nil || v != "malicious" {
		t.Fatal(v, err)
	}
	if v, _ := UploadReputation(context.Background(), "bad1", time.Second); v != "malicious" || calls.Load() != 1 {
		t.Fatal("cached", calls.Load())
	}
	setUploadEnv("", "", nil)
	var ee *EngineError
	if _, err := UploadReputation(context.Background(), "other", time.Second); !errors.As(err, &ee) || ee.Status != "unreachable" {
		t.Fatal(err)
	}
}

func TestSyncDeepScanBlocksMalwareAndFailsClosedWhenAsked(t *testing.T) {
	log := deepSetup(t, engineSettings{})
	c := startClamd(t, "tcp")
	o := UploadOptions{Field: "doc", DeepScanMode: ModeBlock, DeepScan: DeepScanOptions{ClamAV: &c.addr, Timeout: time.Second}}
	v, err := InspectUpload(context.Background(), strings.NewReader("hello "+clamMarker), "a.txt", "text/plain", o)
	var blocked *BlockedError
	if !errors.As(err, &blocked) || blocked.Rule != "upload.malware" {
		t.Fatalf("%v %+v", err, v)
	}
	ev := eventsNamed(log, "shield360.rasp.event")
	a := ev[len(ev)-1].Attrs
	if a["shield360.rasp.upload.engine"] != "clamav" || a["shield360.rasp.upload.signature"] != "Shield360.Test-Marker" || a["shield360.rasp.sink"] != DeepScanSink || a["shield360.rasp.input_key"] != "body.doc.filename" {
		t.Fatalf("attrs %v", a)
	}
	if st := eventsNamed(log, ScannerEvent); len(st) != 1 || st[0].Attrs["shield360.rasp.scanner.status"] != "ok" {
		t.Fatalf("scanner status %v", st)
	}
	if _, err := InspectUpload(context.Background(), strings.NewReader("hello"), "a.txt", "", o); err != nil {
		t.Fatal("clean", err)
	}
	// Trusted hashes skip the engines' answer; deep scan off runs nothing.
	sum := InspectUploadBytes([]byte("hello "+clamMarker), "a.txt", "").SHA256
	trusted := o
	trusted.Trusted = map[string]bool{sum: true}
	if _, err := InspectUpload(context.Background(), strings.NewReader("hello "+clamMarker), "a.txt", "", trusted); err != nil {
		t.Fatal("trusted", err)
	}
	// The fake server counts a scan when it reads the command, which can land
	// after InspectUpload returned: wait for the count to settle first.
	before := c.settledScans()
	off := o
	off.DeepScanMode = ModeOff
	if _, err := InspectUpload(context.Background(), strings.NewReader(clamMarker), "a.txt", "", off); err != nil || c.settledScans() != before {
		t.Fatal("off", err)
	}
	// An engine that cannot answer: open lets the file through and reports
	// the status; closed raises upload.scan_unavailable.
	c.close()
	if _, err := InspectUpload(context.Background(), strings.NewReader("x"), "a.txt", "", o); err != nil {
		t.Fatal("fail open", err)
	}
	st := eventsNamed(log, ScannerEvent)
	if last := st[len(st)-1].Attrs; last["shield360.rasp.scanner.status"] != "unreachable" || last["shield360.rasp.scanner.fail_mode"] != "open" {
		t.Fatalf("status %v", last)
	}
	closed := o
	closed.DeepScan.FailClosed = true
	if _, err := InspectUpload(context.Background(), strings.NewReader("x"), "a.txt", "", closed); !errors.As(err, &blocked) || blocked.Rule != "upload.scan_unavailable" {
		t.Fatal("fail closed", err)
	}
	// Repeated failures are not reported again within 5 minutes.
	if n := len(eventsNamed(log, ScannerEvent)); n != len(st) {
		t.Fatalf("repeated status: %d vs %d", n, len(st))
	}
}

func TestConnectionTestAnswersEachTestIDOnce(t *testing.T) {
	log := deepSetup(t, engineSettings{})
	c := startClamd(t, "unix")
	d := DeepScanOptions{ClamAV: &c.addr, TestID: "test-1"}
	testEngines(d)
	testEngines(d)
	st := eventsNamed(log, ScannerEvent)
	if len(st) != 1 || st[0].Attrs["shield360.rasp.scanner.test_id"] != "test-1" || c.pings.Load() != 1 {
		t.Fatalf("%v pings %d", st, c.pings.Load())
	}
}

func TestAsyncDeepScanQuarantinesASavedFileTheModeBlocks(t *testing.T) {
	log := deepSetup(t, engineSettings{})
	c := startClamd(t, "tcp")
	dir := t.TempDir()
	saved := filepath.Join(dir, "report.txt")
	if err := os.WriteFile(saved, []byte("data "+clamMarker), 0o600); err != nil {
		t.Fatal(err)
	}
	o := UploadOptions{DeepScanMode: ModeBlock, DeepScan: DeepScanOptions{Async: true, ClamAV: &c.addr, Timeout: time.Second}}
	v, err := InspectUploadFile(context.Background(), saved, "report.txt", "", o)
	if err != nil {
		t.Fatal(err)
	}
	waitFor(t, func() bool { _, err := os.Stat(saved); return os.IsNotExist(err) })
	q := filepath.Join(QuarantineDir(), v.SHA256+".quarantined")
	if st, err := os.Stat(q); err != nil || st.Mode().Perm() != 0o600 {
		t.Fatalf("quarantine %v", err)
	}
	waitFor(t, func() bool { return len(eventsNamed(log, "shield360.rasp.event")) > 0 })
	a := eventsNamed(log, "shield360.rasp.event")[0].Attrs
	if a["shield360.rasp.upload.action"] != "quarantined" || a["shield360.rasp.rule"] != "upload.malware" {
		t.Fatalf("attrs %v", a)
	}
}

func waitFor(t *testing.T, ok func() bool) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for !ok() {
		if time.Now().After(deadline) {
			t.Fatal("timed out")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

var phpShell = []byte("<?php echo 'hi'; ?>")

func TestBackdoorChecksThroughTheDropIns(t *testing.T) {
	log := deepSetup(t, engineSettings{attacks: map[AttackType]Mode{UploadBackdoor: ModeBlock}})
	root := t.TempDir()
	public := filepath.Join(root, "public")
	if err := os.MkdirAll(public, 0o755); err != nil {
		t.Fatal(err)
	}
	var blocked *BlockedError
	ctx := WithScope(context.Background())

	// Saved as a server script: refused, and the file goes to quarantine.
	v := InspectUploadBytes(phpShell, "avatar.png", "image/png")
	saved := filepath.Join(root, "uploads", "a.php")
	_ = os.MkdirAll(filepath.Dir(saved), 0o755)
	_ = os.WriteFile(saved, phpShell, 0o600)
	if err := UploadSaved(ctx, saved, v, UploadOptions{}); !errors.As(err, &blocked) || blocked.Rule != "backdoor.write_executable" {
		t.Fatalf("write_executable: %v", err)
	}
	if _, err := os.Stat(saved); !os.IsNotExist(err) {
		t.Fatal("not quarantined")
	}
	a := eventsNamed(log, "shield360.rasp.event")[0].Attrs
	if a["shield360.rasp.attack"] != "upload_backdoor" || a["shield360.rasp.upload.dest"] == "" || strings.Contains(a["shield360.rasp.upload.dest"], "a.php") {
		t.Fatalf("attrs %v", a)
	}

	// Active content saved into a served directory.
	img := filepath.Join(public, "x.png")
	_ = os.WriteFile(img, phpShell, 0o600)
	if err := UploadSaved(ctx, img, v, UploadOptions{}); !errors.As(err, &blocked) || blocked.Rule != "backdoor.write_served" {
		t.Fatalf("write_served: %v", err)
	}

	// A harmless location is remembered; then chmod +x, exec, a shell line
	// and a plugin load of it are refused.
	plain := filepath.Join(root, "store", "f.bin")
	_ = os.MkdirAll(filepath.Dir(plain), 0o755)
	_ = os.WriteFile(plain, phpShell, 0o600)
	if err := UploadSaved(ctx, plain, v, UploadOptions{}); err != nil {
		t.Fatal(err)
	}
	if err := Chmod(ctx, plain, 0o644); err != nil {
		t.Fatal("no execute bit", err)
	}
	if err := Chmod(ctx, plain, 0o755); !errors.As(err, &blocked) || blocked.Rule != "backdoor.chmod" {
		t.Fatalf("chmod: %v", err)
	}
	if err := CheckCommand(ctx, []string{"php", "-f", plain}); !errors.As(err, &blocked) || blocked.Rule != "backdoor.exec" {
		t.Fatalf("exec: %v", err)
	}
	if err := CommandContext(ctx, "sh", "-c", "cd /tmp && php '"+plain+"'").Err; !errors.As(err, &blocked) || blocked.Rule != "backdoor.exec" {
		t.Fatalf("sh -c: %v", err)
	}
	if err := CheckShellCommand(ctx, "echo hi; "+plain+" --run"); !errors.As(err, &blocked) || blocked.Rule != "backdoor.exec" {
		t.Fatalf("shell line: %v", err)
	}
	if err := CheckLoad(ctx, plain); !errors.As(err, &blocked) || blocked.Rule != "backdoor.include" {
		t.Fatalf("load: %v", err)
	}
	// Renamed to a script name: refused before the rename.
	if err := Rename(ctx, plain, filepath.Join(root, "store", "f.php")); !errors.As(err, &blocked) || blocked.Rule != "backdoor.write_executable" {
		t.Fatalf("rename: %v", err)
	}
	if err := CheckCommand(ctx, []string{"ls", root}); err != nil {
		t.Fatal("unrelated command", err)
	}
}

func TestBackdoorChecksFollowTheRequestsUploadsIntoWrites(t *testing.T) {
	deepSetup(t, engineSettings{attacks: map[AttackType]Mode{UploadBackdoor: ModeBlock}})
	root := t.TempDir()
	ctx := WithScope(context.Background())
	if _, err := InspectUpload(ctx, bytes.NewReader(phpShell), "Shell Upload.php", "", UploadOptions{}); err != nil {
		t.Fatal(err)
	}
	var blocked *BlockedError
	// The upload's bytes written anywhere served or executable.
	if err := WriteFile(ctx, filepath.Join(root, "public", "copy.txt"), phpShell, 0o600); !errors.As(err, &blocked) || blocked.Rule != "backdoor.write_served" {
		t.Fatalf("data: %v", err)
	}
	// A file named after the upload (sanitized) opened for writing.
	if _, err := Create(ctx, filepath.Join(root, "shell_upload.php")); !errors.As(err, &blocked) || blocked.Rule != "backdoor.write_executable" {
		t.Fatalf("name: %v", err)
	}
	if _, err := os.Stat(filepath.Join(root, "shell_upload.php")); !os.IsNotExist(err) {
		t.Fatal("the write happened")
	}
	// Other writes are untouched.
	if err := WriteFile(ctx, filepath.Join(root, "notes.txt"), []byte("other"), 0o600); err != nil {
		t.Fatal(err)
	}
	// Outside a request, a write is not tied to an upload.
	_ = os.MkdirAll(filepath.Join(root, "public"), 0o755)
	if err := WriteFile(context.Background(), filepath.Join(root, "public", "c2.txt"), phpShell, 0o600); err != nil {
		t.Fatal("no request", err)
	}
}

func TestUploadLocationsAreBoundedAndExpire(t *testing.T) {
	deepSetup(t, engineSettings{})
	now := time.Unix(1_800_000_000, 0)
	locMu.Lock()
	locNow = func() time.Time { return now }
	locMu.Unlock()
	v := UploadVerdict{SHA256: strings.Repeat("a", 64)}
	rememberUpload("/srv/x/1", v)
	if uploadAt("/srv/x/1") == nil || len(locationsOf(v)) != 1 {
		t.Fatal("remembered")
	}
	now = now.Add(25 * time.Hour)
	if uploadAt("/srv/x/1") != nil {
		t.Fatal("expired")
	}
	for i := 0; i < MaxUploadLocations+5; i++ {
		rememberUpload("/srv/y/"+strings.Repeat("z", i%7)+string(rune('a'+i%26))+itoa(i), v)
	}
	if n := UploadLocations(); n > MaxUploadLocations {
		t.Fatalf("%d locations", n)
	}
	if !isServed("/srv/app/public/a.png", nil) || isServed("/srv/app/public", nil) || !isServed("/srv/www/a", []string{"/srv/www"}) || isServed("/srv/public/a", []string{"/srv/www"}) {
		t.Fatal("isServed")
	}
	if targetDirectory("/a.php") != "/" || targetDirectory("C:/a.php") != "C:/" || targetDirectory("/srv/a/b.php") != "/srv/a" {
		t.Fatal("targetDirectory")
	}
	segs := commandSegments(`a "b c" 'd e' f\ g; h | i && j`)
	if len(segs) != 4 || strings.Join(segs[0], ",") != "a,b c,d e,f g" {
		t.Fatalf("%q", segs)
	}
}

func itoa(i int) string {
	b, _ := json.Marshal(i)
	return string(b)
}
