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
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Deep scan (README "Upload policy and deep scan", "Scanner status"): the
// customer's own ClamAV (clamd INSTREAM over TCP or a Unix socket) and the
// hash-only reputation lookup (POST /api/rasp/upload-reputation, only the
// SHA-256 leaves the app), sync or async, with the fail mode and the
// quarantine. Port of the PHP SDK's DeepScan (#1066) and the TypeScript
// SDK's upload-deep-scan.ts. File contents are streamed in bounded pieces,
// never stored or sent anywhere but the customer's own clamd.

// Deep scan constants.
const (
	// ScannerEvent is the scanner status record.
	ScannerEvent    = "shield360.rasp.scanner"
	DeepScanSink    = "upload.deep_scan"
	clamChunk       = 64 * 1024
	scannerRepeat   = 5 * time.Minute
	reputationTTL   = time.Hour
	reputationMax   = 1000
	reputationPath  = "/api/rasp/upload-reputation"
	emptySHA256     = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	defaultScanWait = 5 * time.Second
)

var (
	clamNameRe = regexp.MustCompile(`^[A-Za-z0-9._:/-]{1,128}$`)
	clamTCPRe  = regexp.MustCompile(`^tcp:([A-Za-z0-9.-]{1,253}|\[[0-9a-fA-F:.]{2,45}\]):(\d{1,5})$`)
	clamOKRe   = regexp.MustCompile(`:\s*OK$`)
	clamFound  = regexp.MustCompile(`:\s*(.+?)\s+FOUND$`)
)

// ClamAddress is a clamd address: Network "unix" (Address an absolute path)
// or "tcp" (Address host:port).
type ClamAddress struct {
	Network, Address string
}

func isAbsPath(p string) bool {
	return strings.HasPrefix(p, "/") || drivePath.MatchString(p)
}

// ParseClamAddress reads unix:<absolute path> or tcp:<host>:<port> (a
// string, or {"address": ...}); nil otherwise.
func ParseClamAddress(v any) *ClamAddress {
	if m, ok := v.(map[string]any); ok {
		v = m["address"]
	}
	s, ok := v.(string)
	if !ok {
		return nil
	}
	if p, ok := strings.CutPrefix(s, "unix:"); ok {
		if p != "" && isAbsPath(p) {
			return &ClamAddress{"unix", p}
		}
		return nil
	}
	m := clamTCPRe.FindStringSubmatch(s)
	if m == nil {
		return nil
	}
	port, _ := strconv.Atoi(m[2])
	if port < 1 || port > 65535 {
		return nil
	}
	return &ClamAddress{"tcp", net.JoinHostPort(strings.Trim(m[1], "[]"), m[2])}
}

// DeepScanOptions are the deep scan engines and how they run (the mode is
// UploadOptions.DeepScanMode).
type DeepScanOptions struct {
	// Async scans after the app saved the file (UploadSaved); sync (the
	// default) holds the upload until the engines answer.
	Async bool
	// Timeout is one scan, all engines: 100 ms to 60 s, default 5 s.
	Timeout time.Duration
	// FailClosed raises upload.scan_unavailable when an engine cannot
	// answer (default: the file goes through and the status is reported).
	FailClosed bool
	ClamAV     *ClamAddress
	Reputation bool
	// TestID: a new value tests the engines once and reports the result.
	TestID string
}

func (d DeepScanOptions) timeout() time.Duration {
	if d.Timeout <= 0 {
		return defaultScanWait
	}
	return min(max(d.Timeout, 100*time.Millisecond), time.Minute)
}

func (d DeepScanOptions) failMode() string {
	if d.FailClosed {
		return "closed"
	}
	return "open"
}

// EngineError is why a deep scan engine could not answer: unreachable,
// timeout or error.
type EngineError struct{ Status string }

func (e *EngineError) Error() string { return "deep scan engine: " + e.Status }

func engineErr(err error) *EngineError {
	var ee *EngineError
	if errors.As(err, &ee) {
		return ee
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() || errors.Is(err, context.DeadlineExceeded) {
		return &EngineError{"timeout"}
	}
	return &EngineError{"error"}
}

// ---- clamd -------------------------------------------------------------------------

type clamStream struct {
	conn     net.Conn
	deadline time.Time
	err      *EngineError
}

func clamDial(addr ClamAddress, deadline time.Time) (*clamStream, *EngineError) {
	d := net.Dialer{Deadline: deadline}
	conn, err := d.Dial(addr.Network, addr.Address)
	if err != nil {
		if ee := engineErr(err); ee.Status == "timeout" {
			return nil, ee
		}
		return nil, &EngineError{"unreachable"}
	}
	_ = conn.SetDeadline(deadline)
	return &clamStream{conn: conn, deadline: deadline}, nil
}

func (s *clamStream) send(b []byte) {
	if s.err != nil {
		return
	}
	if _, err := s.conn.Write(b); err != nil {
		s.err = engineErr(err)
	}
}

// Write frames a piece (4-byte big-endian length, at most 64 KiB a frame).
// It never fails: an engine error is kept for the reply.
func (s *clamStream) Write(p []byte) (int, error) {
	for off := 0; off < len(p) && s.err == nil; off += clamChunk {
		part := p[off:min(off+clamChunk, len(p))]
		var n [4]byte
		binary.BigEndian.PutUint32(n[:], uint32(len(part)))
		s.send(append(n[:], part...))
	}
	return len(p), nil
}

func (s *clamStream) reply() (string, *EngineError) {
	if s.err != nil {
		return "", s.err
	}
	var buf []byte
	tmp := make([]byte, 4096)
	for !bytes.Contains(buf, []byte{0}) && len(buf) < 4096 {
		n, err := s.conn.Read(tmp)
		buf = append(buf, tmp[:n]...)
		if err != nil {
			if err == io.EOF {
				break
			}
			return "", engineErr(err)
		}
	}
	if i := bytes.IndexByte(buf, 0); i >= 0 {
		buf = buf[:i]
	}
	return strings.TrimSpace(string(buf)), nil
}

func (s *clamStream) close() { _ = s.conn.Close() }

func clamStart(addr ClamAddress, deadline time.Time) (*clamStream, *EngineError) {
	s, err := clamDial(addr, deadline)
	if err != nil {
		return nil, err
	}
	s.send([]byte("zINSTREAM\x00"))
	return s, nil
}

// finish ends the stream and reads the answer: "" for clean, ClamAV's name
// for a find.
func (s *clamStream) finish() (string, *EngineError) {
	defer s.close()
	s.send([]byte{0, 0, 0, 0})
	r, err := s.reply()
	if err != nil {
		return "", err
	}
	if clamOKRe.MatchString(r) {
		return "", nil
	}
	if m := clamFound.FindStringSubmatch(r); m != nil {
		if clamNameRe.MatchString(m[1]) {
			return m[1], nil
		}
		return "unnamed", nil
	}
	return "", &EngineError{"error"}
}

// ClamScan streams src to clamd (zINSTREAM) and returns ClamAV's name for a
// find, "" for clean.
func ClamScan(addr ClamAddress, src io.Reader, timeout time.Duration) (string, error) {
	s, err := clamStart(addr, time.Now().Add(timeout))
	if err != nil {
		return "", err
	}
	if _, rerr := io.Copy(s, src); rerr != nil && s.err == nil {
		s.close()
		return "", &EngineError{"error"}
	}
	name, ferr := s.finish()
	if ferr != nil {
		return "", ferr
	}
	return name, nil
}

// ClamPing asks clamd zPING and expects PONG.
func ClamPing(addr ClamAddress, timeout time.Duration) (bool, error) {
	s, err := clamDial(addr, time.Now().Add(timeout))
	if err != nil {
		return false, err
	}
	defer s.close()
	s.send([]byte("zPING\x00"))
	r, rerr := s.reply()
	if rerr != nil {
		return false, rerr
	}
	return r == "PONG", nil
}

// ---- reputation --------------------------------------------------------------------

type uploadEnvironment struct {
	url, apiKey string
	client      *http.Client
}

var (
	uploadEnvMu sync.RWMutex
	uploadEnv   uploadEnvironment
)

func setUploadEnv(url, apiKey string, client *http.Client) {
	uploadEnvMu.Lock()
	defer uploadEnvMu.Unlock()
	uploadEnv = uploadEnvironment{strings.TrimRight(url, "/"), apiKey, client}
}

type repEntry struct {
	verdict string
	until   time.Time
}

var (
	repMu    sync.Mutex
	repCache = map[string]repEntry{}
	repOrder []string
)

// UploadReputation asks Shield360 about a file's SHA-256 (only the hash
// leaves the app): malicious, suspicious, clean or unknown. Answers are
// cached an hour, at most 1000 hashes.
func UploadReputation(ctx context.Context, sha256 string, timeout time.Duration) (string, error) {
	repMu.Lock()
	if e, ok := repCache[sha256]; ok && e.until.After(time.Now()) {
		repMu.Unlock()
		return e.verdict, nil
	}
	repMu.Unlock()
	uploadEnvMu.RLock()
	env := uploadEnv
	uploadEnvMu.RUnlock()
	if env.url == "" || env.apiKey == "" {
		return "", &EngineError{"unreachable"}
	}
	client := env.client
	if client == nil {
		client = http.DefaultClient
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	body, _ := json.Marshal(map[string]string{"sha256": sha256})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, env.url+reputationPath, bytes.NewReader(body))
	if err != nil {
		return "", &EngineError{"error"}
	}
	req.Header.Set("Authorization", "Bearer "+env.apiKey)
	req.Header.Set("Content-Type", "application/json")
	res, err := client.Do(req)
	if err != nil {
		if ee := engineErr(err); ee.Status == "timeout" {
			return "", ee
		}
		return "", &EngineError{"unreachable"}
	}
	defer res.Body.Close()
	if res.StatusCode < 200 || res.StatusCode >= 300 {
		return "", &EngineError{"error"}
	}
	raw, _ := io.ReadAll(io.LimitReader(res.Body, 64*1024))
	var v struct {
		Verdict any `json:"verdict"`
	}
	if len(bytes.TrimSpace(raw)) > 0 && json.Unmarshal(raw, &v) != nil {
		return "", &EngineError{"error"}
	}
	verdict := "unknown"
	if s, ok := v.Verdict.(string); ok && (s == "malicious" || s == "suspicious" || s == "clean") {
		verdict = s
	}
	repMu.Lock()
	if _, had := repCache[sha256]; !had {
		if len(repOrder) >= reputationMax {
			delete(repCache, repOrder[0])
			repOrder = repOrder[1:]
		}
		repOrder = append(repOrder, sha256)
	}
	repCache[sha256] = repEntry{verdict, time.Now().Add(reputationTTL)}
	repMu.Unlock()
	return verdict, nil
}

// ---- scanner status ----------------------------------------------------------------

type engineStatus struct {
	status   string
	since    time.Time
	failures int
	lastSent time.Time
}

var (
	scannerMu       sync.Mutex
	scannerStatuses = map[string]*engineStatus{}
	scannerLastTest string
)

func resetScanner() {
	scannerMu.Lock()
	scannerStatuses = map[string]*engineStatus{}
	scannerLastTest = ""
	scannerMu.Unlock()
	repMu.Lock()
	repCache, repOrder = map[string]repEntry{}, nil
	repMu.Unlock()
}

// noteEngine records an engine's status and reports it when it changes,
// every 5 minutes while it is not ok, and for each test.
func noteEngine(engine, status, failMode, testID string) {
	now := time.Now()
	scannerMu.Lock()
	s := scannerStatuses[engine]
	send := false
	if s == nil || s.status != status {
		s = &engineStatus{status: status, since: now}
		if status != "ok" {
			s.failures = 1
		}
		scannerStatuses[engine] = s
		send = true
	} else {
		if status != "ok" {
			s.failures++
		}
		send = testID != "" || (status != "ok" && now.Sub(s.lastSent) >= scannerRepeat)
	}
	if send {
		s.lastSent = now
	}
	attrs := map[string]string{
		"shield360.rasp.app":               ApplicationName(),
		"shield360.rasp.scanner.engine":    engine,
		"shield360.rasp.scanner.status":    status,
		"shield360.rasp.scanner.fail_mode": failMode,
		"shield360.rasp.scanner.since":     isoTime(s.since),
		"shield360.rasp.scanner.failures":  strconv.Itoa(s.failures),
	}
	scannerMu.Unlock()
	if !send {
		return
	}
	if testID != "" {
		attrs["shield360.rasp.scanner.test_id"] = testID
	}
	stateMu.RLock()
	es := state.sink
	stateMu.RUnlock()
	if es != nil {
		es.add(Event{Name: ScannerEvent, Time: isoTime(now), Attrs: attrs}, "")
	}
}

// testEngines answers a new deepScan.testId once: clamd zPING and a
// reputation lookup of the empty file's hash.
func testEngines(d DeepScanOptions) {
	defer func() { _ = recover() }()
	if d.TestID == "" {
		return
	}
	scannerMu.Lock()
	if scannerLastTest == d.TestID {
		scannerMu.Unlock()
		return
	}
	scannerLastTest = d.TestID
	scannerMu.Unlock()
	timeout := min(d.timeout(), 5*time.Second)
	if d.ClamAV != nil {
		status := "ok"
		if ok, err := ClamPing(*d.ClamAV, timeout); err != nil {
			status = engineErr(err).Status
		} else if !ok {
			status = "error"
		}
		noteEngine("clamav", status, d.failMode(), d.TestID)
	}
	if d.Reputation {
		status := "ok"
		if _, err := UploadReputation(context.Background(), emptySHA256, timeout); err != nil {
			status = engineErr(err).Status
		}
		noteEngine("reputation", status, d.failMode(), d.TestID)
	}
}

// ---- the scan ----------------------------------------------------------------------

func deepScanOn(o UploadOptions) bool {
	return o.DeepScanMode != "" && o.DeepScanMode != ModeOff && (o.DeepScan.ClamAV != nil || o.DeepScan.Reputation)
}

// deepScanRun is one scan in progress: ClamAV fed as the bytes arrive, the
// reputation lookup once the hash is known.
type deepScanRun struct {
	o        UploadOptions
	deadline time.Time
	clam     *clamStream
	failed   []string
	finding  *UploadFinding
}

func startDeepScan(o UploadOptions) *deepScanRun {
	go testEngines(o.DeepScan)
	if !deepScanOn(o) {
		return nil
	}
	r := &deepScanRun{o: o, deadline: time.Now().Add(o.DeepScan.timeout())}
	if a := o.DeepScan.ClamAV; a != nil {
		s, err := clamStart(*a, r.deadline)
		if err != nil {
			noteEngine("clamav", err.Status, o.DeepScan.failMode(), "")
			r.failed = append(r.failed, "clamav")
		} else {
			r.clam = s
		}
	}
	return r
}

// Write feeds ClamAV (never fails).
func (r *deepScanRun) Write(p []byte) (int, error) {
	if r.clam != nil {
		_, _ = r.clam.Write(p)
	}
	return len(p), nil
}

// abort drops the scan (the file was refused or is trusted).
func (r *deepScanRun) abort() {
	if r != nil && r.clam != nil {
		r.clam.close()
		r.clam = nil
	}
}

// finish reads the engines' answers for a file with this hash ("" when not
// hashed). The finding is upload.malware, upload.reputation or (fail
// closed) upload.scan_unavailable; nil for none.
func (r *deepScanRun) finish(ctx context.Context, sha string, complete bool) *UploadFinding {
	fm := r.o.DeepScan.failMode()
	if r.clam != nil {
		var name string
		var err *EngineError
		if complete {
			name, err = r.clam.finish()
		} else {
			r.clam.close()
			err = &EngineError{"error"}
		}
		r.clam = nil
		if err != nil {
			noteEngine("clamav", err.Status, fm, "")
			r.failed = append(r.failed, "clamav")
		} else {
			noteEngine("clamav", "ok", fm, "")
			if name != "" {
				return &UploadFinding{Rule: "upload.malware", Engine: "clamav", Signature: name}
			}
		}
	}
	if r.o.DeepScan.Reputation && sha != "" {
		left := time.Until(r.deadline)
		if left < time.Millisecond {
			left = time.Millisecond
		}
		v, err := UploadReputation(ctx, sha, left)
		if err != nil {
			noteEngine("reputation", engineErr(err).Status, fm, "")
			r.failed = append(r.failed, "reputation")
		} else {
			noteEngine("reputation", "ok", fm, "")
			if v == "malicious" {
				return &UploadFinding{Rule: "upload.reputation", Engine: "reputation"}
			}
		}
	}
	if len(r.failed) > 0 && r.o.DeepScan.FailClosed {
		return &UploadFinding{Rule: "upload.scan_unavailable", Engine: r.failed[0]}
	}
	return nil
}

// deepFinding is the finding the deep scan's mode decides.
func deepFinding(f UploadFinding, v UploadVerdict, o UploadOptions) *Finding {
	field := o.Field
	if field == "" {
		field = "file"
	}
	return &Finding{Attack: MaliciousUpload, Rule: f.Rule, Input: &Input{Key: "body." + field + ".filename", Source: SourceRequest}, Mode: o.DeepScanMode,
		Upload: &UploadAttrs{Type: v.Type, Kind: v.Kind, Ext: v.Ext, Size: v.Size, SHA256: v.SHA256, Signature: f.Signature, Engine: f.Engine}}
}

// DeepScanFile runs the deep scan engines on a saved file now and returns
// the finding (nil for none). It does not report; InspectUploadFile and
// UploadSaved do.
func DeepScanFile(ctx context.Context, path, sha string, o UploadOptions) *UploadFinding {
	if !deepScanOn(o) || (sha != "" && o.Trusted[sha]) {
		return nil
	}
	r := startDeepScan(o)
	complete := true
	if r.clam != nil {
		f, err := os.Open(path)
		if err != nil {
			complete = false
		} else {
			_, err = io.Copy(r, f)
			_ = f.Close()
			complete = err == nil
		}
	}
	return r.finish(ctx, sha, complete)
}

// ---- quarantine --------------------------------------------------------------------

var (
	quarantineMu  sync.RWMutex
	quarantineDir string
)

// QuarantineDir is where blocked uploads are moved (Options.Uploads, else
// the OS temp directory + shield360-quarantine).
func QuarantineDir() string {
	quarantineMu.RLock()
	defer quarantineMu.RUnlock()
	if quarantineDir != "" {
		return quarantineDir
	}
	return filepath.Join(os.TempDir(), "shield360-quarantine")
}

func setQuarantineDir(d string) {
	quarantineMu.Lock()
	defer quarantineMu.Unlock()
	if isAbsPath(d) {
		quarantineDir = d
	} else {
		quarantineDir = ""
	}
}

// Quarantine moves a file into the quarantine directory (created 0700),
// renamed to its SHA-256 with mode 0600.
func Quarantine(path, sha string) bool {
	defer func() { _ = recover() }()
	d := QuarantineDir()
	if err := os.MkdirAll(d, 0o700); err != nil {
		return false
	}
	name := sha
	if !uploadSHARe.MatchString(name) {
		name = "upload-" + strconv.FormatInt(time.Now().UnixMilli(), 10)
	}
	target := filepath.Join(d, name+".quarantined")
	if err := os.Rename(path, target); err != nil {
		in, err := os.Open(path)
		if err != nil {
			return false
		}
		out, err := os.OpenFile(target, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
		if err != nil {
			_ = in.Close()
			return false
		}
		_, cerr := io.Copy(out, in)
		_ = in.Close()
		_ = out.Close()
		if cerr != nil {
			_ = os.Remove(target)
			return false
		}
		_ = os.Remove(path)
	}
	_ = os.Chmod(target, 0o600)
	return true
}
