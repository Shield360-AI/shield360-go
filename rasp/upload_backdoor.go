package rasp

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"
	"unicode"
)

// Backdoor checks (README "Uploads", "Backdoor checks"): where uploaded
// files were saved, per process and in memory only (resolved paths, at most
// 10,000, each kept 24 hours), and the checks that fire when the app saves
// one somewhere executable or served, loads it, runs it or makes it
// executable. The file and exec drop-ins (WriteFile, Create, OpenFile,
// Rename, Chmod, CommandContext, CheckCommand, CheckShellCommand) call in
// before the call they guard; CheckLoad and CheckExtract cover plugin loads
// and archive extraction. Port of upload-taint.ts and the PHP SDK's
// UploadTaint.

// Backdoor limits.
const (
	MaxUploadLocations = 10_000
	uploadLocationTTL  = 24 * time.Hour
	maxRequestUploads  = 64
)

var (
	interpreterRe = regexp.MustCompile(`(?i)^(sh|bash|zsh|dash|ksh|python[0-9.]*|node|nodejs|perl|php[0-9.]*|ruby|cmd|powershell|pwsh)(\.exe)?$`)
	sanitizeRe    = regexp.MustCompile(`[^a-z0-9._-]`)
	servedSegs    = map[string]bool{"public": true, "static": true, "www": true, "wwwroot": true, "htdocs": true, "webroot": true, "public_html": true}
)

type uploadLocation struct {
	v     UploadVerdict
	until time.Time
}

var (
	locMu     sync.Mutex
	locations = map[string]uploadLocation{}
	locOrder  []string
	locNow    = time.Now
)

func resetUploadLocations() {
	locMu.Lock()
	defer locMu.Unlock()
	locations, locOrder, locNow = map[string]uploadLocation{}, nil, time.Now
}

// UploadLocations is how many saved upload locations are known.
func UploadLocations() int {
	locMu.Lock()
	defer locMu.Unlock()
	return len(locations)
}

func stripFileScheme(p string) string { return strings.TrimPrefix(p, "file://") }

func realOf(resolved string) string {
	r, err := filepath.EvalSymlinks(resolved)
	if err != nil {
		return ""
	}
	return strings.ReplaceAll(r, "\\", "/")
}

// keysOf are the resolved path and, when different, its real path.
func uploadKeysOf(p string) []string {
	resolved := ResolvePath(stripFileScheme(p), "")
	if real := realOf(resolved); real != "" && real != resolved {
		return []string{resolved, real}
	}
	return []string{resolved}
}

// rememberUpload records a saved location; it returns the resolved path.
func rememberUpload(p string, v UploadVerdict) string {
	keys := uploadKeysOf(p)
	locMu.Lock()
	defer locMu.Unlock()
	now := locNow()
	for _, k := range keys {
		if _, had := locations[k]; had {
			delete(locations, k)
			for i, o := range locOrder {
				if o == k {
					locOrder = append(locOrder[:i], locOrder[i+1:]...)
					break
				}
			}
		}
		if len(locations) >= MaxUploadLocations {
			kept := locOrder[:0]
			for _, o := range locOrder {
				if l, ok := locations[o]; ok && l.until.After(now) {
					kept = append(kept, o)
				} else {
					delete(locations, o)
				}
			}
			locOrder = kept
			for len(locations) >= MaxUploadLocations && len(locOrder) > 0 {
				delete(locations, locOrder[0])
				locOrder = locOrder[1:]
			}
		}
		locations[k] = uploadLocation{v, now.Add(uploadLocationTTL)}
		locOrder = append(locOrder, k)
	}
	return keys[0]
}

// uploadAt is the verdict of the upload saved at a path, or nil.
func uploadAt(p string) *UploadVerdict {
	if p == "" {
		return nil
	}
	locMu.Lock()
	empty := len(locations) == 0
	locMu.Unlock()
	if empty {
		return nil
	}
	for _, k := range uploadKeysOf(p) {
		locMu.Lock()
		l, ok := locations[k]
		if ok && !l.until.After(locNow()) {
			delete(locations, k)
			ok = false
		}
		locMu.Unlock()
		if ok {
			v := l.v
			return &v
		}
	}
	return nil
}

func forgetKeys(keys []string) {
	locMu.Lock()
	defer locMu.Unlock()
	for _, k := range keys {
		delete(locations, k)
	}
}

// locationsOf are the known locations of an upload (the same hash).
func locationsOf(v UploadVerdict) []string {
	locMu.Lock()
	defer locMu.Unlock()
	var out []string
	for _, k := range locOrder {
		if l, ok := locations[k]; ok && v.SHA256 != "" && l.v.SHA256 == v.SHA256 {
			out = append(out, k)
		}
	}
	return out
}

// ---- the request's uploads -----------------------------------------------------------

type requestUpload struct {
	name string
	v    UploadVerdict
}

func addRequestUpload(ctx context.Context, name string, v UploadVerdict) {
	c := FromContext(ctx)
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.savedUploads) < maxRequestUploads {
		c.savedUploads = append(c.savedUploads, requestUpload{name, v})
	}
}

func requestUploads(ctx context.Context) []requestUpload {
	c := FromContext(ctx)
	if c == nil {
		return nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]requestUpload(nil), c.savedUploads...)
}

func sanitizedName(name string) string {
	return sanitizeRe.ReplaceAllString(strings.ToLower(name), "_")
}

func baseName(p string) string {
	p = strings.ReplaceAll(p, "\\", "/")
	if i := strings.LastIndexByte(p, '/'); i >= 0 {
		return p[i+1:]
	}
	return p
}

// uploadNamed: a file opened for writing named after one of the request's
// uploads (as sent, or sanitized).
func uploadNamed(ctx context.Context, p string) *UploadVerdict {
	ups := requestUploads(ctx)
	if len(ups) == 0 {
		return nil
	}
	name := baseName(p)
	for _, u := range ups {
		n := baseName(u.name)
		if n != "" && (n == name || sanitizedName(n) == name) {
			v := u.v
			return &v
		}
	}
	return nil
}

// uploadWithData: a write whose data is one of the request's uploads (same
// size and SHA-256).
func uploadWithData(ctx context.Context, data []byte) *UploadVerdict {
	ups := requestUploads(ctx)
	sha := ""
	for _, u := range ups {
		if u.v.Size == int64(len(data)) && u.v.SHA256 != "" {
			if sha == "" {
				s := sha256.Sum256(data)
				sha = hex.EncodeToString(s[:])
			}
			if sha == u.v.SHA256 {
				v := u.v
				return &v
			}
		}
	}
	return nil
}

// ---- the checks ----------------------------------------------------------------------

func targetDirectory(resolved string) string {
	i := strings.LastIndexByte(resolved, '/')
	d := ""
	if i >= 0 {
		d = resolved[:i]
	}
	if d == "" {
		return "/"
	}
	if len(d) == 2 && d[1] == ':' && unicode.IsLetter(rune(d[0])) {
		return d + "/"
	}
	return d
}

// isExecutableName: a server-script extension (file_write.script) or a
// server config name.
func isExecutableName(p string) bool {
	return scriptFile.MatchString(baseName(p)) || IsServerConfigName(p)
}

// isActiveContent: kind script, html, svg or executable, or any finding
// other than the capped and policy ones.
func isActiveContent(v UploadVerdict) bool {
	switch v.Kind {
	case "script", "html", "svg", "executable":
		return true
	}
	for _, f := range v.Findings {
		if !f.Capped && f.Rule != "upload.too_large" && f.Rule != "upload.type_not_allowed" {
			return true
		}
	}
	return false
}

// isServed: under one of servedDirs, or, without them, with a served
// directory segment.
func isServed(resolved string, servedDirs []string) bool {
	p := strings.ReplaceAll(resolved, "\\", "/")
	if len(servedDirs) > 0 {
		for _, d := range servedDirs {
			root := strings.TrimRight(strings.ReplaceAll(d, "\\", "/"), "/")
			if p == root || strings.HasPrefix(p, root+"/") {
				return true
			}
		}
		return false
	}
	segs := strings.Split(p, "/")
	for _, s := range segs[:max(len(segs)-1, 0)] {
		if servedSegs[strings.ToLower(s)] {
			return true
		}
	}
	return false
}

func backdoorFinding(rule string, v UploadVerdict, dest string) *Finding {
	return &Finding{Attack: UploadBackdoor, Rule: rule,
		Upload: &UploadAttrs{Type: v.Type, Kind: v.Kind, Ext: v.Ext, Size: v.Size, SHA256: v.SHA256, Dest: dest}}
}

// checkNewLocation records a location and checks it.
func checkNewLocation(p string, v UploadVerdict) *Finding {
	resolved := rememberUpload(p, v)
	dest := targetDirectory(resolved)
	if isExecutableName(resolved) {
		return backdoorFinding("backdoor.write_executable", v, dest)
	}
	if isServed(resolved, servedDirsNow()) && isActiveContent(v) {
		return backdoorFinding("backdoor.write_served", v, dest)
	}
	return nil
}

func servedDirsNow() []string {
	stateMu.RLock()
	r := state.remote
	stateMu.RUnlock()
	if r != nil && r.Uploads != nil {
		return r.Uploads.ServedDirs
	}
	return localUploads().ServedDirs
}

func detectBackdoorWrite(ctx context.Context, p, source string, data []byte) *Finding {
	if p == "" {
		return nil
	}
	var v *UploadVerdict
	if source != "" {
		v = uploadAt(source)
	}
	if v == nil {
		v = uploadNamed(ctx, p)
	}
	if v == nil && data != nil {
		v = uploadWithData(ctx, data)
	}
	if v == nil {
		return nil
	}
	return checkNewLocation(p, *v)
}

func detectBackdoorExec(argv []string) *Finding {
	if len(argv) == 0 {
		return nil
	}
	candidates := []string{argv[0]}
	if interpreterRe.MatchString(baseName(argv[0])) {
		for _, a := range argv[1:] {
			if !strings.HasPrefix(a, "-") {
				candidates = append(candidates, a)
				break
			}
		}
	}
	for _, c := range candidates {
		if v := uploadAt(c); v != nil {
			return backdoorFinding("backdoor.exec", *v, targetDirectory(ResolvePath(c, "")))
		}
	}
	// sh -c "<command line>": each command of the line.
	if shellRe.MatchString(baseName(argv[0])) {
		for i := 1; i+1 < len(argv); i++ {
			if argv[i] == "-c" || argv[i] == "/c" || argv[i] == "-Command" {
				for _, seg := range commandSegments(argv[i+1]) {
					if f := detectBackdoorExecWords(seg); f != nil {
						return f
					}
				}
				break
			}
		}
	}
	return nil
}

var shellRe = regexp.MustCompile(`(?i)^(sh|bash|zsh|dash|ksh|cmd|powershell|pwsh)(\.exe)?$`)

// detectBackdoorExecWords is detectBackdoorExec for one command of a shell
// line (no nested shell lines).
func detectBackdoorExecWords(words []string) *Finding {
	if len(words) == 0 {
		return nil
	}
	candidates := []string{words[0]}
	if interpreterRe.MatchString(baseName(words[0])) {
		for _, a := range words[1:] {
			if !strings.HasPrefix(a, "-") {
				candidates = append(candidates, a)
				break
			}
		}
	}
	for _, c := range candidates {
		if v := uploadAt(c); v != nil {
			return backdoorFinding("backdoor.exec", *v, targetDirectory(ResolvePath(c, "")))
		}
	}
	return nil
}

// commandSegments splits a shell command line into the words of each
// command (quotes and backslashes honored; ; & | and newlines split).
func commandSegments(command string) [][]string {
	var segments [][]string
	var words []string
	var cur strings.Builder
	has := false
	var q byte
	end := func() {
		if has || cur.Len() > 0 {
			words = append(words, cur.String())
		}
		cur.Reset()
		has = false
	}
	n := len(command)
	for i := 0; i < n; i++ {
		c := command[i]
		switch {
		case q == '\'':
			if c == '\'' {
				q = 0
			} else {
				cur.WriteByte(c)
			}
		case q == '"':
			if c == '"' {
				q = 0
			} else if c == '\\' && i+1 < n && strings.IndexByte("\"\\$`", command[i+1]) >= 0 {
				i++
				cur.WriteByte(command[i])
			} else {
				cur.WriteByte(c)
			}
		case c == '\'' || c == '"':
			q, has = c, true
		case c == '\\' && i+1 < n:
			i++
			cur.WriteByte(command[i])
			has = true
		case c == ';' || c == '&' || c == '|' || c == '\n':
			end()
			if len(words) > 0 {
				segments = append(segments, words)
			}
			words = nil
		case c == ' ' || c == '\t' || c == '\r' || c == '\v' || c == '\f':
			end()
		default:
			cur.WriteByte(c)
		}
	}
	end()
	if len(words) > 0 {
		segments = append(segments, words)
	}
	return segments
}

func pathFinding(rule string, p string) *Finding {
	v := uploadAt(p)
	if v == nil {
		return nil
	}
	return backdoorFinding(rule, *v, targetDirectory(ResolvePath(stripFileScheme(p), "")))
}

// checkBackdoor runs a backdoor check through the sink: nothing to do while
// no upload location is known (and RASP is off).
func checkBackdoor(ctx context.Context, sink string, detect func() *Finding) error {
	if !Active() {
		return nil
	}
	return checkSink(ctx, sink, func(*iastSlot) *Finding { return detect() })
}

func anyUploadKnown(ctx context.Context) bool {
	locMu.Lock()
	n := len(locations)
	locMu.Unlock()
	return n > 0 || len(requestUploads(ctx)) > 0
}

func checkBackdoorWrite(ctx context.Context, sink, p, source string, data []byte) error {
	if !anyUploadKnown(ctx) {
		return nil
	}
	return checkBackdoor(ctx, sink, func() *Finding { return detectBackdoorWrite(ctx, p, source, data) })
}

func checkBackdoorExec(ctx context.Context, sink string, argv []string) error {
	if !anyUploadKnown(ctx) {
		return nil
	}
	return checkBackdoor(ctx, sink, func() *Finding { return detectBackdoorExec(argv) })
}

func checkBackdoorShell(ctx context.Context, sink, command string) error {
	if !anyUploadKnown(ctx) {
		return nil
	}
	return checkBackdoor(ctx, sink, func() *Finding {
		for _, seg := range commandSegments(command) {
			if f := detectBackdoorExecWords(seg); f != nil {
				return f
			}
		}
		return nil
	})
}

// CheckLoad checks a file about to be loaded as code (plugin.Open, an
// embedded interpreter running a script file): backdoor.include when it is
// a saved upload. It returns only the block error.
func CheckLoad(ctx context.Context, path string) error {
	if !anyUploadKnown(ctx) {
		return nil
	}
	return checkBackdoor(ctx, "plugin.Open", func() *Finding { return pathFinding("backdoor.include", path) })
}

// CheckExtract checks an archive about to be extracted: backdoor.extract
// when it is a saved upload with an entry the traversal or link rule finds.
// It returns only the block error.
func CheckExtract(ctx context.Context, archive string) error {
	if !anyUploadKnown(ctx) {
		return nil
	}
	return checkBackdoor(ctx, "archive.extract", func() *Finding {
		v := uploadAt(archive)
		if v == nil {
			return nil
		}
		for _, f := range v.Findings {
			if f.Rule == "upload.archive_traversal" || f.Rule == "upload.archive_symlink" {
				return backdoorFinding("backdoor.extract", *v, targetDirectory(ResolvePath(stripFileScheme(archive), "")))
			}
		}
		return nil
	})
}

// Chmod is os.Chmod with RASP checks: backdoor.chmod when a saved upload
// gets an execute bit.
func Chmod(ctx context.Context, name string, mode os.FileMode) error {
	if mode&0o111 != 0 && anyUploadKnown(ctx) {
		if err := checkBackdoor(ctx, "os.Chmod", func() *Finding { return pathFinding("backdoor.chmod", name) }); err != nil {
			return err
		}
	}
	return os.Chmod(name, mode)
}

// ---- where uploads are saved ----------------------------------------------------------

// UploadSaved tells RASP where the app saved an upload it inspected: the
// location is remembered for the backdoor checks and checked now
// (backdoor.write_executable, backdoor.write_served; a blocked one is moved
// to quarantine), and with an async deep scan the engines scan the saved
// file in the background (a find in block mode is quarantined, then
// reported). It returns the block error.
func UploadSaved(ctx context.Context, path string, v UploadVerdict, o UploadOptions) error {
	if !Active() || path == "" {
		return nil
	}
	err := checkBackdoor(ctx, "upload.save", func() *Finding { return checkNewLocation(path, v) })
	if err != nil {
		keys := uploadKeysOf(path)
		if Quarantine(path, v.SHA256) {
			forgetKeys(keys)
		}
		return err
	}
	if o.DeepScan.Async && deepScanOn(o) && !(v.SHA256 != "" && o.Trusted[v.SHA256]) {
		go asyncDeepScan(context.WithoutCancel(ctx), path, v, o)
	}
	return nil
}

// asyncDeepScan scans a saved file after the response: a find the mode
// blocks moves every known location of the file to quarantine; the event
// says so.
func asyncDeepScan(ctx context.Context, path string, v UploadVerdict, o UploadOptions) {
	defer func() { _ = recover() }()
	f := DeepScanFile(ctx, path, v.SHA256, o)
	if f == nil {
		return
	}
	fd := deepFinding(*f, v, o)
	if effectiveUploadMode(fd) == ModeBlock {
		moved := false
		paths := append([]string{path}, locationsOf(v)...)
		seen := map[string]bool{}
		for _, p := range paths {
			if seen[p] {
				continue
			}
			seen[p] = true
			keys := uploadKeysOf(p)
			if st, err := os.Stat(p); err == nil && st.Mode().IsRegular() && Quarantine(p, v.SHA256) {
				forgetKeys(keys)
				moved = true
			}
		}
		if moved {
			fd.Upload.Action = "quarantined"
		}
	}
	_, _ = HandleFinding(ctx, fd, DeepScanSink, FindingExtra{})
}

// InspectUploadFile inspects an upload already on disk (a multipart temp
// file): the built-in checks, then, with a sync deep scan, the engines on
// the file. The location is remembered. It returns the verdict and the
// block error (a blocked file is moved to quarantine).
func InspectUploadFile(ctx context.Context, path, name, contentType string, o UploadOptions) (UploadVerdict, error) {
	f, err := os.Open(path)
	if err != nil {
		return UploadVerdict{}, err
	}
	defer f.Close()
	v, berr := inspectUpload(ctx, f, name, contentType, o, !o.DeepScan.Async)
	if Active() && v.Size >= 0 {
		rememberUpload(path, v)
	}
	if berr != nil {
		_ = f.Close()
		keys := uploadKeysOf(path)
		if Quarantine(path, v.SHA256) {
			forgetKeys(keys)
		}
		return v, berr
	}
	if o.DeepScan.Async && Active() && deepScanOn(o) && !(v.SHA256 != "" && o.Trusted[v.SHA256]) {
		go asyncDeepScan(context.WithoutCancel(ctx), path, v, o)
	}
	return v, nil
}

var _ io.Writer = (*deepScanRun)(nil)
