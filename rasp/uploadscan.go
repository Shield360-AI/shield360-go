package rasp

// Upload inspection (README "Uploads"): what an uploaded file really is, from
// its bytes, and the YARA-like signatures (README "Signatures"). A port of the
// TypeScript SDK's upload-inspect.ts and upload-signatures.ts, held to the
// same answers by testdata/uploads.json. Shield360 Edge imports this package
// and runs the same inspection on multipart uploads.
//
// Memory stays bounded whatever the file's size: the first 64 KiB, the last
// 1 MiB, one piece of at most 1 MiB with a 2 KiB overlap, and a running hash.

import (
	"bytes"
	"context"
	"crypto/sha256"
	_ "embed"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"hash"
	"io"
	"math"
	"path"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"
)

//go:embed data/upload-signatures.json
var uploadSignaturesJSON []byte

// Upload inspection limits (README "Uploads").
const (
	DefaultUploadScanBytes = 8 << 20
	MaxUploadScanBytes     = 64 << 20
	uploadHead             = 64 << 10
	uploadTail             = 1 << 20
	uploadPiece            = 1 << 20
	sigOverlap             = 2048
	sigWindowBefore        = 256
	sigWindowAfter         = 1024
	sigAnchorsPerPiece     = 8
	sigRegexSteps          = 1_000_000
	mib                    = 1 << 20
)

// UploadRuleOrder is README "Inspection rules": the first finding is reported.
var UploadRuleOrder = []string{
	"upload.eicar", "upload.malware", "upload.reputation", "upload.webshell", "upload.signature",
	"upload.executable", "upload.script", "upload.polyglot", "upload.active_content", "upload.server_config",
	"upload.double_extension", "upload.archive_traversal", "upload.archive_symlink", "upload.archive_bomb",
	"upload.archive_encrypted", "upload.office_macro", "upload.office_ole", "upload.archive_script",
	"upload.type_mismatch", "upload.type_not_allowed", "upload.too_large", "upload.scan_unavailable",
}

var cappedUploadRules = map[string]bool{"upload.office_ole": true, "upload.archive_script": true, "upload.type_mismatch": true}

func uploadRuleRank(rule string) int {
	for i, r := range UploadRuleOrder {
		if r == rule {
			return i
		}
	}
	return len(UploadRuleOrder)
}

// UploadFinding is one inspection finding (a malicious_upload rule).
type UploadFinding struct {
	Rule      string
	Engine    string // builtin, custom, policy
	Signature string
	Capped    bool
}

// UploadVerdict is what a file is.
type UploadVerdict struct {
	Type     string
	Kind     string
	Size     int64
	SHA256   string // only when the inspector saw every byte
	Ext      string
	Findings []UploadFinding
}

var uploadKindOf = func() map[string]string {
	m := map[string]string{"svg": "svg", "html": "html", "text": "text", "unknown": "other"}
	for k, ts := range map[string][]string{
		"executable": {"elf", "pe", "macho", "java_class", "wasm", "jar", "war"},
		"image":      {"jpeg", "png", "gif", "webp", "bmp", "ico", "tiff"},
		"document":   {"pdf", "ole2", "docx", "xlsx", "pptx"},
		"archive":    {"zip", "gzip", "bzip2", "xz", "7z", "rar", "tar"},
		"media":      {"mp4", "webm", "mp3", "wav", "ogg"},
		"script":     {"php", "jsp_asp", "shebang"},
	} {
		for _, t := range ts {
			m[t] = k
		}
	}
	return m
}()

// UploadKindOf is the kind of a real type.
func UploadKindOf(t string) string {
	if k, ok := uploadKindOf[t]; ok {
		return k
	}
	return "other"
}

// ---- signatures ----------------------------------------------------------------

type sigString struct {
	id     string
	kind   string // text, hex, regex
	bytes  []byte // folded when nocase; the anchor for regex
	nocase bool
	prog   []inst
}

type sigCond struct {
	op string // id, not, and, or, atLeast
	i  int
	n  int
	xs []*sigCond
}

// Signature is a compiled upload signature.
type Signature struct {
	ID, Title string
	strings   []sigString
	cond      *sigCond
}

// SignatureError is why a signature was refused (the contract's codes).
type SignatureError struct {
	Code   string
	Rule   int
	String string
}

func (e *SignatureError) Error() string { return "upload signature: " + e.Code }

var (
	sigRuleID   = regexp.MustCompile(`^[a-z0-9][a-z0-9_.-]{0,47}$`)
	sigStringID = regexp.MustCompile(`^[a-z][a-z0-9_]{0,15}$`)
	sigHex      = regexp.MustCompile(`^[0-9a-fA-F]{2}( ?[0-9a-fA-F]{2})*$`)
	sigToken    = regexp.MustCompile(`\(|\)|[A-Za-z_][A-Za-z0-9_]*|\S`)
	sigCount    = regexp.MustCompile(`^[0-9]{1,2}$`)
)

func asciiFold(b []byte) []byte {
	out := make([]byte, len(b))
	for i, c := range b {
		if c >= 'A' && c <= 'Z' {
			c += 32
		}
		out[i] = c
	}
	return out
}

func compileSigString(raw map[string]any) (sigString, string) {
	id, _ := raw["id"].(string)
	if !sigStringID.MatchString(id) || id == "and" || id == "or" || id == "not" || id == "any" || id == "all" {
		return sigString{}, "string_id"
	}
	n := 0
	for _, k := range []string{"text", "hex", "regex"} {
		if v, ok := raw[k]; ok && v != nil {
			n++
		}
	}
	if n != 1 {
		return sigString{}, "string_kind"
	}
	nocase, _ := raw["nocase"].(bool)
	if t, ok := raw["text"].(string); ok {
		b := []byte(t)
		if len(b) < 3 || len(b) > 256 {
			return sigString{}, "text"
		}
		if nocase {
			b = asciiFold(b)
		}
		return sigString{id: id, kind: "text", bytes: b, nocase: nocase}, ""
	}
	if h, ok := raw["hex"].(string); ok {
		h = strings.TrimSpace(h)
		if !sigHex.MatchString(h) {
			return sigString{}, "hex"
		}
		b, err := hex.DecodeString(strings.ReplaceAll(h, " ", ""))
		if err != nil || len(b) < 3 || len(b) > 256 {
			return sigString{}, "hex"
		}
		return sigString{id: id, kind: "hex", bytes: b}, ""
	}
	if r, ok := raw["regex"].(string); ok {
		prog := compileRegex(r)
		if prog == nil {
			return sigString{}, "regex"
		}
		a, ok := raw["anchor"].(string)
		if !ok || len(a) < 3 || len(a) > 64 {
			return sigString{}, "anchor"
		}
		return sigString{id: id, kind: "regex", bytes: []byte(a), prog: prog}, ""
	}
	return sigString{}, "string_kind"
}

func parseSigCondition(src string, ids map[string]int) (*sigCond, string) {
	text := strings.TrimSpace(src)
	if text == "" || len(text) > 256 {
		return nil, "condition"
	}
	switch {
	case text == "any":
		return &sigCond{op: "atLeast", n: 1}, ""
	case text == "all":
		return &sigCond{op: "atLeast", n: len(ids)}, ""
	case sigCount.MatchString(text):
		n, _ := strconv.Atoi(text)
		if n >= 1 && n <= len(ids) {
			return &sigCond{op: "atLeast", n: n}, ""
		}
		return nil, "condition"
	}
	toks := sigToken.FindAllString(text, -1)
	pos, depth, unknown := 0, 0, false
	peek := func() string {
		if pos < len(toks) {
			return toks[pos]
		}
		return ""
	}
	var or, and, unary func() *sigCond
	or = func() *sigCond {
		x := and()
		if x == nil {
			return nil
		}
		xs := []*sigCond{x}
		for peek() == "or" {
			pos++
			if y := and(); y != nil {
				xs = append(xs, y)
			} else {
				return nil
			}
		}
		if len(xs) == 1 {
			return xs[0]
		}
		return &sigCond{op: "or", xs: xs}
	}
	and = func() *sigCond {
		x := unary()
		if x == nil {
			return nil
		}
		xs := []*sigCond{x}
		for peek() == "and" {
			pos++
			if y := unary(); y != nil {
				xs = append(xs, y)
			} else {
				return nil
			}
		}
		if len(xs) == 1 {
			return xs[0]
		}
		return &sigCond{op: "and", xs: xs}
	}
	unary = func() *sigCond {
		t := peek()
		if t == "not" || t == "(" {
			pos++
			depth++
			if depth > 8 {
				return nil
			}
			if t == "not" {
				x := unary()
				depth--
				if x == nil {
					return nil
				}
				return &sigCond{op: "not", xs: []*sigCond{x}}
			}
			x := or()
			depth--
			if x == nil || peek() != ")" {
				return nil
			}
			pos++
			return x
		}
		if t != "" && sigStringID.MatchString(t) && t != "and" && t != "or" {
			pos++
			i, ok := ids[t]
			if !ok {
				unknown = true
				return nil
			}
			return &sigCond{op: "id", i: i}
		}
		return nil
	}
	c := or()
	if unknown {
		return nil, "unknown_string"
	}
	if c == nil || pos != len(toks) {
		return nil, "condition"
	}
	return c, ""
}

func (c *sigCond) holds(found []bool) bool {
	switch c.op {
	case "id":
		return found[c.i]
	case "not":
		return !c.xs[0].holds(found)
	case "and":
		for _, x := range c.xs {
			if !x.holds(found) {
				return false
			}
		}
		return true
	case "or":
		for _, x := range c.xs {
			if x.holds(found) {
				return true
			}
		}
		return false
	}
	n := 0
	for _, f := range found {
		if f {
			n++
		}
	}
	return n >= c.n
}

// CompileSignature checks one rule (decoded JSON) and compiles it.
func CompileSignature(raw any) (*Signature, *SignatureError) {
	m, ok := raw.(map[string]any)
	if !ok {
		return nil, &SignatureError{Code: "shape"}
	}
	id, _ := m["id"].(string)
	if !sigRuleID.MatchString(id) {
		return nil, &SignatureError{Code: "id"}
	}
	title, _ := m["title"].(string)
	if strings.TrimSpace(title) == "" || utf8.RuneCountInString(title) > 120 {
		return nil, &SignatureError{Code: "title"}
	}
	list, ok := m["strings"].([]any)
	if !ok || len(list) < 1 || len(list) > 16 {
		return nil, &SignatureError{Code: "strings"}
	}
	sig := &Signature{ID: id, Title: strings.TrimSpace(title)}
	ids := map[string]int{}
	for _, s := range list {
		sm, ok := s.(map[string]any)
		if !ok {
			return nil, &SignatureError{Code: "string_kind"}
		}
		spec, code := compileSigString(sm)
		if code != "" {
			sid, _ := sm["id"].(string)
			return nil, &SignatureError{Code: code, String: sid}
		}
		if _, dup := ids[spec.id]; dup {
			return nil, &SignatureError{Code: "duplicate_string", String: spec.id}
		}
		ids[spec.id] = len(sig.strings)
		sig.strings = append(sig.strings, spec)
	}
	var condText string
	switch v := m["condition"].(type) {
	case string:
		condText = v
	case float64:
		condText = strconv.FormatFloat(v, 'f', -1, 64)
	default:
		return nil, &SignatureError{Code: "condition"}
	}
	cond, code := parseSigCondition(condText, ids)
	if code != "" {
		return nil, &SignatureError{Code: code}
	}
	sig.cond = cond
	return sig, nil
}

// CompileSignatures compiles the organization's own rules: every valid one,
// in order, and the errors of the others; more than 64 or 64 KiB is refused whole.
func CompileSignatures(raw []json.RawMessage) ([]*Signature, []*SignatureError) {
	if len(raw) > 64 {
		return nil, []*SignatureError{{Code: "too_many"}}
	}
	total := 2
	for _, r := range raw {
		total += len(r) + 1
	}
	if total > 65536 {
		return nil, []*SignatureError{{Code: "too_large"}}
	}
	var sigs []*Signature
	var errs []*SignatureError
	seen := map[string]bool{}
	for i, r := range raw {
		var v any
		if json.Unmarshal(r, &v) != nil {
			errs = append(errs, &SignatureError{Code: "shape", Rule: i})
			continue
		}
		s, err := CompileSignature(v)
		if err != nil {
			err.Rule = i
			errs = append(errs, err)
			continue
		}
		if seen[s.ID] {
			errs = append(errs, &SignatureError{Code: "duplicate_id", Rule: i})
			continue
		}
		seen[s.ID] = true
		sigs = append(sigs, s)
	}
	return sigs, errs
}

// BuiltInSignatures are the contract's web-shell signatures.
var BuiltInSignatures = func() []*Signature {
	var d struct {
		Rules []json.RawMessage `json:"rules"`
	}
	_ = json.Unmarshal(uploadSignaturesJSON, &d)
	s, _ := CompileSignatures(d.Rules)
	return s
}()

type sigMatcher struct {
	sigs   []*Signature
	found  [][]bool
	budget RuleBudget
}

func newSigMatcher(sigs []*Signature) *sigMatcher {
	m := &sigMatcher{sigs: sigs, budget: RuleBudget{Steps: sigRegexSteps}}
	for _, s := range sigs {
		m.found = append(m.found, make([]bool, len(s.strings)))
	}
	return m
}

func latinRunes(b []byte) []rune {
	out := make([]rune, len(b))
	for i, c := range b {
		out[i] = rune(c)
	}
	return out
}

func (m *sigMatcher) regex(prog []inst, window []byte) (ok bool) {
	defer func() {
		if r := recover(); r != nil {
			m.budget.Steps = -1
			ok = false
		}
	}()
	return runRegex(prog, latinRunes(window), &m.budget)
}

func (m *sigMatcher) feed(piece, folded []byte, final bool) {
	for r, sig := range m.sigs {
		for i, s := range sig.strings {
			if m.found[r][i] {
				continue
			}
			if s.kind != "regex" {
				hay := piece
				if s.nocase {
					hay = folded
				}
				if bytes.Contains(hay, s.bytes) {
					m.found[r][i] = true
				}
				continue
			}
			if m.budget.Steps < 0 {
				continue
			}
			from := 0
			for n := 0; n < sigAnchorsPerPiece; n++ {
				j := bytes.Index(piece[from:], s.bytes)
				if j < 0 {
					break
				}
				at := from + j
				end := at + len(s.bytes) + sigWindowAfter
				if end > len(piece) && !final {
					break
				}
				lo := at - sigWindowBefore
				if lo < 0 {
					lo = 0
				}
				if end > len(piece) {
					end = len(piece)
				}
				if m.regex(s.prog, piece[lo:end]) {
					m.found[r][i] = true
					break
				}
				if m.budget.Steps < 0 {
					break
				}
				from = at + 1
			}
		}
	}
}

func (m *sigMatcher) matched() []*Signature {
	var out []*Signature
	for r, s := range m.sigs {
		if s.cond.holds(m.found[r]) {
			out = append(out, s)
		}
	}
	return out
}

// MatchSample runs signatures over a whole sample; the ids that match.
func MatchSample(sigs []*Signature, data []byte) []string {
	m := newSigMatcher(sigs)
	for start := 0; ; start += uploadPiece {
		lo := start - sigOverlap
		if lo < 0 {
			lo = 0
		}
		end := start + uploadPiece
		if end > len(data) {
			end = len(data)
		}
		m.feed(data[lo:end], asciiFold(data[lo:end]), end >= len(data))
		if end >= len(data) {
			break
		}
	}
	var ids []string
	for _, s := range m.matched() {
		ids = append(ids, s.ID)
	}
	return ids
}

// ---- real type --------------------------------------------------------------------

func hasAt(b []byte, at int, sig ...byte) bool {
	return len(b) >= at+len(sig) && bytes.Equal(b[at:at+len(sig)], sig)
}

func strAt(b []byte, at, n int) string {
	if at >= len(b) {
		return ""
	}
	end := at + n
	if end > len(b) {
		end = len(b)
	}
	return string(b[at:end])
}

// SniffUploadType is the real type from the first bytes (README "Real type").
func SniffUploadType(h []byte) string {
	switch {
	case hasAt(h, 0, 0x7f, 'E', 'L', 'F'):
		return "elf"
	case hasAt(h, 0, 'M', 'Z') && len(h) >= 0x40 && func() bool {
		off := int(int32(binary.LittleEndian.Uint32(h[0x3c:])))
		return off >= 0 && hasAt(h, off, 'P', 'E', 0, 0)
	}():
		return "pe"
	case hasAt(h, 0, 0xfe, 0xed, 0xfa, 0xce), hasAt(h, 0, 0xfe, 0xed, 0xfa, 0xcf), hasAt(h, 0, 0xce, 0xfa, 0xed, 0xfe), hasAt(h, 0, 0xcf, 0xfa, 0xed, 0xfe):
		return "macho"
	case hasAt(h, 0, 0xca, 0xfe, 0xba, 0xbe):
		if len(h) >= 8 && binary.BigEndian.Uint32(h[4:]) < 30 {
			return "macho"
		}
		return "java_class"
	case hasAt(h, 0, 0xff, 0xd8, 0xff):
		return "jpeg"
	case hasAt(h, 0, 0x89, 'P', 'N', 'G', 0x0d, 0x0a, 0x1a, 0x0a):
		return "png"
	case strAt(h, 0, 6) == "GIF87a" || strAt(h, 0, 6) == "GIF89a":
		return "gif"
	case strAt(h, 0, 4) == "RIFF" && strAt(h, 8, 4) == "WEBP":
		return "webp"
	case strAt(h, 0, 2) == "BM" && len(h) >= 26:
		return "bmp"
	case hasAt(h, 0, 0, 0, 1, 0):
		return "ico"
	case hasAt(h, 0, 'I', 'I', '*', 0) || hasAt(h, 0, 'M', 'M', 0, '*'):
		return "tiff"
	case bytes.Contains(h[:min(len(h), 1024)], []byte("%PDF-")):
		return "pdf"
	case hasAt(h, 0, 0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1):
		return "ole2"
	case hasAt(h, 0, 'P', 'K', 3, 4) || hasAt(h, 0, 'P', 'K', 5, 6):
		return "zip"
	case hasAt(h, 0, 0x1f, 0x8b):
		return "gzip"
	case strAt(h, 0, 3) == "BZh":
		return "bzip2"
	case hasAt(h, 0, 0xfd, '7', 'z', 'X', 'Z', 0):
		return "xz"
	case hasAt(h, 0, '7', 'z', 0xbc, 0xaf, 0x27, 0x1c):
		return "7z"
	case hasAt(h, 0, 'R', 'a', 'r', '!', 0x1a, 0x07):
		return "rar"
	case strAt(h, 257, 5) == "ustar":
		return "tar"
	case strAt(h, 4, 4) == "ftyp":
		return "mp4"
	case hasAt(h, 0, 0x1a, 0x45, 0xdf, 0xa3):
		return "webm"
	case strAt(h, 0, 3) == "ID3" || hasAt(h, 0, 0xff, 0xfb) || hasAt(h, 0, 0xff, 0xf3) || hasAt(h, 0, 0xff, 0xf2):
		return "mp3"
	case strAt(h, 0, 4) == "RIFF" && strAt(h, 8, 4) == "WAVE":
		return "wav"
	case strAt(h, 0, 4) == "OggS":
		return "ogg"
	case hasAt(h, 0, 0, 'a', 's', 'm'):
		return "wasm"
	}
	i := 0
	if hasAt(h, 0, 0xef, 0xbb, 0xbf) {
		i = 3
	}
	for i < len(h) && (h[i] == ' ' || (h[i] >= 0x09 && h[i] <= 0x0d)) {
		i++
	}
	lead := string(asciiFold(h[i:min(len(h), i+1024)]))
	switch {
	case strings.HasPrefix(lead, "<?php") || strings.HasPrefix(lead, "<?="):
		return "php"
	case strings.HasPrefix(lead, "<%") || strings.HasPrefix(lead, "<jsp:"):
		return "jsp_asp"
	case strings.HasPrefix(lead, "#!/"):
		return "shebang"
	}
	for _, t := range []string{"<!doctype html", "<html", "<head", "<body", "<script", "<iframe"} {
		if strings.HasPrefix(lead, t) {
			return "html"
		}
	}
	if strings.Contains(lead, "<svg") {
		return "svg"
	}
	if bytes.IndexByte(h[:min(len(h), 8192)], 0) < 0 {
		return "text"
	}
	return "unknown"
}

// ---- names --------------------------------------------------------------------------

var (
	uploadServerConfig = map[string]bool{".htaccess": true, ".htpasswd": true, ".user.ini": true, "web.config": true}
	uploadScriptExt    = regexp.MustCompile(`(?i)^(aspx?|jspx?|php[3-7]?|phar|phtml|sh|bash|py|pyc|pl|rb|so|dll|dylib|exe|cgi|js|mjs|cjs)$`)
	uploadAspSemicolon = regexp.MustCompile(`(?i)\.(aspx?|jspx?|php[3-7]?|phtml|cgi|pl)\s*;`)
	uploadTrailing     = regexp.MustCompile(`\.[^.]+[. ]+$`)
	uploadArchiveExt   = regexp.MustCompile(`(?i)\.(aspx?|jspx?|php[3-7]?|phar|phtml|cgi|pl|sh)$`)
	uploadExtShape     = regexp.MustCompile(`^[a-z0-9]{1,10}$`)
	uploadOleEntry     = regexp.MustCompile(`(?i)(^|/)embeddings/oleObject|(^|/)activeX/`)
)

func uploadBase(name string) string {
	if i := strings.LastIndexAny(name, `\/`); i >= 0 {
		return name[i+1:]
	}
	return name
}

// UploadExt is a name's last extension, lower case ([a-z0-9]{1,10}); "" otherwise.
func UploadExt(name string) string {
	base := strings.TrimRight(uploadBase(name), ". ")
	dot := strings.LastIndexByte(base, '.')
	if dot <= 0 && !strings.HasPrefix(base, ".") {
		return ""
	}
	ext := strings.ToLower(base[dot+1:])
	if uploadExtShape.MatchString(ext) {
		return ext
	}
	return ""
}

// IsServerConfigName is upload.server_config.
func IsServerConfigName(name string) bool {
	return uploadServerConfig[strings.ToLower(uploadBase(name))]
}

// HasDoubleExtension is upload.double_extension.
func HasDoubleExtension(name string) bool {
	base := uploadBase(name)
	if strings.Contains(base, "\x00") || strings.Contains(base, "%00") || uploadTrailing.MatchString(base) {
		return true
	}
	parts := strings.Split(base, ".")
	if len(parts) < 3 && !strings.Contains(base, ";") {
		return false
	}
	// A name with a ';' and no dot has no middle segment (it panicked here).
	for i := 1; i < len(parts)-1; i++ {
		seg := parts[i]
		if uploadScriptExt.MatchString(strings.SplitN(seg, ";", 2)[0]) {
			return true
		}
	}
	return uploadAspSemicolon.MatchString(base)
}

var uploadExtTypes = map[string][]string{
	"jpg": {"jpeg"}, "jpeg": {"jpeg"}, "jpe": {"jpeg"}, "png": {"png"}, "gif": {"gif"}, "webp": {"webp"}, "bmp": {"bmp"}, "ico": {"ico"}, "tif": {"tiff"}, "tiff": {"tiff"},
	"pdf": {"pdf"}, "docx": {"docx", "zip"}, "xlsx": {"xlsx", "zip"}, "pptx": {"pptx", "zip"}, "doc": {"ole2"}, "xls": {"ole2"}, "ppt": {"ole2"},
	"zip": {"zip", "docx", "xlsx", "pptx", "jar", "war"}, "gz": {"gzip"}, "tgz": {"gzip"},
	"mp4": {"mp4"}, "m4a": {"mp4"}, "mov": {"mp4"}, "mp3": {"mp3"}, "csv": {"text"}, "txt": {"text"}, "json": {"text"}, "md": {"text"},
}

var uploadCTTypes = map[string][]string{
	"image/jpeg": {"jpeg"}, "image/png": {"png"}, "image/gif": {"gif"}, "image/webp": {"webp"}, "image/bmp": {"bmp"},
	"image/x-icon": {"ico"}, "image/vnd.microsoft.icon": {"ico"}, "image/tiff": {"tiff"}, "application/pdf": {"pdf"},
	"application/vnd.openxmlformats-officedocument.wordprocessingml.document":   {"docx", "zip"},
	"application/vnd.openxmlformats-officedocument.spreadsheetml.sheet":         {"xlsx", "zip"},
	"application/vnd.openxmlformats-officedocument.presentationml.presentation": {"pptx", "zip"},
	"application/msword": {"ole2"}, "application/vnd.ms-excel": {"ole2"}, "application/vnd.ms-powerpoint": {"ole2"},
	"application/zip": {"zip", "docx", "xlsx", "pptx", "jar", "war"}, "application/gzip": {"gzip"},
	"video/mp4": {"mp4"}, "audio/mp4": {"mp4"}, "video/quicktime": {"mp4"}, "audio/mpeg": {"mp3"},
	"text/csv": {"text"}, "text/plain": {"text"}, "application/json": {"text"},
}

func containsStr(xs []string, s string) bool {
	for _, x := range xs {
		if x == s {
			return true
		}
	}
	return false
}

// UploadTypeMismatch is upload.type_mismatch.
func UploadTypeMismatch(t, name, contentType string) bool {
	if t == "unknown" {
		return false
	}
	ct := strings.ToLower(strings.TrimSpace(strings.SplitN(contentType, ";", 2)[0]))
	for _, expected := range [][]string{uploadExtTypes[UploadExt(name)], uploadCTTypes[ct]} {
		if len(expected) > 0 && !containsStr(expected, t) && UploadKindOf(expected[0]) != UploadKindOf(t) {
			return true
		}
	}
	return false
}

// ---- archives --------------------------------------------------------------------------

type archiveEntry struct {
	name               string
	symlink, encrypted bool
	compressed, size   uint64
}

func zipEntries(tail []byte) (entries []archiveEntry, total uint64, ok bool) {
	eocd := -1
	for i := len(tail) - 22; i >= 0 && i >= len(tail)-22-65535; i-- {
		if hasAt(tail, i, 'P', 'K', 5, 6) {
			eocd = i
			break
		}
	}
	if eocd < 0 {
		return nil, 0, false
	}
	total = uint64(binary.LittleEndian.Uint16(tail[eocd+10:]))
	cdSize := uint64(binary.LittleEndian.Uint32(tail[eocd+12:]))
	cdEnd := eocd
	if total == 0xffff || cdSize == 0xffffffff {
		loc := eocd - 20
		if loc < 0 || !hasAt(tail, loc, 'P', 'K', 6, 7) {
			return nil, total, true
		}
		z := loc - 56
		if z < 0 || !hasAt(tail, z, 'P', 'K', 6, 6) {
			return nil, total, true
		}
		total = binary.LittleEndian.Uint64(tail[z+32:])
		cdSize = binary.LittleEndian.Uint64(tail[z+40:])
		cdEnd = z
	}
	if cdSize > uint64(cdEnd) {
		return nil, total, true
	}
	p := cdEnd - int(cdSize)
	for p+46 <= cdEnd && hasAt(tail, p, 'P', 'K', 1, 2) && len(entries) < 10001 {
		madeBy := binary.LittleEndian.Uint16(tail[p+4:]) >> 8
		flags := binary.LittleEndian.Uint16(tail[p+8:])
		compressed := uint64(binary.LittleEndian.Uint32(tail[p+20:]))
		size := uint64(binary.LittleEndian.Uint32(tail[p+24:]))
		nameLen := int(binary.LittleEndian.Uint16(tail[p+28:]))
		extraLen := int(binary.LittleEndian.Uint16(tail[p+30:]))
		commentLen := int(binary.LittleEndian.Uint16(tail[p+32:]))
		attr := binary.LittleEndian.Uint32(tail[p+38:])
		if p+46+nameLen+extraLen > len(tail) {
			break
		}
		name := string(tail[p+46 : p+46+nameLen])
		e := p + 46 + nameLen
		extraEnd := e + extraLen
		for e+4 <= extraEnd {
			id := binary.LittleEndian.Uint16(tail[e:])
			ln := int(binary.LittleEndian.Uint16(tail[e+2:]))
			if id == 1 {
				q := e + 4
				if size == 0xffffffff && q+8 <= e+4+ln && q+8 <= len(tail) {
					size = binary.LittleEndian.Uint64(tail[q:])
					q += 8
				}
				if compressed == 0xffffffff && q+8 <= e+4+ln && q+8 <= len(tail) {
					compressed = binary.LittleEndian.Uint64(tail[q:])
				}
			}
			e += 4 + ln
		}
		mode := (attr >> 16) & 0o170000
		entries = append(entries, archiveEntry{name: name, symlink: madeBy == 3 && mode == 0o120000, encrypted: flags&1 == 1, compressed: compressed, size: size})
		p = extraEnd + commentLen
	}
	return entries, total, true
}

var uploadDrive = regexp.MustCompile(`^[A-Za-z]:`)

// UploadEntryEscapes is upload.archive_traversal for one entry name.
func UploadEntryEscapes(name string) bool {
	n := strings.ReplaceAll(name, `\`, "/")
	if strings.HasPrefix(n, "/") || uploadDrive.MatchString(n) {
		return true
	}
	for _, seg := range strings.Split(n, "/") {
		if seg == ".." {
			return true
		}
	}
	return false
}

// tarReader reads tar headers as the bytes pass (ustar name and prefix, GNU
// L, pax path).
type tarReader struct {
	entries     []archiveEntry
	next        int64
	header      []byte
	wantKind    byte
	wantLeft    int64
	wantSkip    int64
	wantBytes   []byte
	pendingName *string
	done        bool
}

var paxPath = regexp.MustCompile(`(?:^|\n)\d+ path=([^\n]*)\n`)

func (t *tarReader) feed(chunk []byte, offset int64) {
	i := 0
	for i < len(chunk) && !t.done && len(t.entries) <= 10000 {
		pos := offset + int64(i)
		if t.wantKind != 0 {
			take := int64(len(chunk) - i)
			if take > t.wantLeft {
				take = t.wantLeft
			}
			room := int64(512)
			if t.wantKind == 'x' {
				room = 4096
			}
			room -= int64(len(t.wantBytes))
			keep := take
			if keep > room {
				keep = room
			}
			t.wantBytes = append(t.wantBytes, chunk[i:i+int(keep)]...)
			t.wantLeft -= take
			i += int(take)
			if t.wantLeft == 0 {
				var name string
				if t.wantKind == 'L' {
					name = strings.SplitN(string(t.wantBytes), "\x00", 2)[0]
					t.pendingName = &name
				} else if m := paxPath.FindStringSubmatch(string(t.wantBytes)); m != nil {
					name = m[1]
					t.pendingName = &name
				}
				t.next = offset + int64(i) + t.wantSkip
				t.wantKind = 0
				t.wantBytes = nil
			}
			continue
		}
		if pos < t.next {
			skip := t.next - pos
			if skip > int64(len(chunk)-i) {
				skip = int64(len(chunk) - i)
			}
			i += int(skip)
			continue
		}
		take := 512 - len(t.header)
		if take > len(chunk)-i {
			take = len(chunk) - i
		}
		t.header = append(t.header, chunk[i:i+take]...)
		i += take
		if len(t.header) < 512 {
			continue
		}
		h := t.header
		t.header = nil
		if bytes.Count(h, []byte{0}) == 512 {
			t.done = true
			break
		}
		field := func(o, l int) string { return strings.SplitN(string(h[o:o+l]), "\x00", 2)[0] }
		size, _ := strconv.ParseInt(strings.TrimSpace(field(124, 12)), 8, 64)
		if size < 0 {
			size = 0
		}
		typ := h[156]
		if typ == 0 {
			typ = '0'
		}
		padded := (size + 511) / 512 * 512
		dataStart := offset + int64(i)
		t.next = dataStart + padded
		if typ == 'L' || typ == 'x' {
			capN := int64(512)
			if typ == 'x' {
				capN = 4096
			}
			if size > 0 {
				left := size
				if left > capN {
					left = capN
				}
				t.wantKind, t.wantLeft, t.wantSkip = typ, left, padded-left
			}
			continue
		}
		if typ == 'g' {
			continue
		}
		name := field(0, 100)
		if prefix := field(345, 155); prefix != "" && string(h[257:262]) == "ustar" {
			name = prefix + "/" + name
		}
		if t.pendingName != nil {
			name = *t.pendingName
			t.pendingName = nil
		}
		t.entries = append(t.entries, archiveEntry{name: name, symlink: typ == '1' || typ == '2', compressed: uint64(size), size: uint64(size)})
	}
}

// ---- scanner ----------------------------------------------------------------------------

var (
	polyglotMarkers = []string{"<?php", "<script", "<jsp:", `runat="server"`}
	activeMarkers   = []string{"<script", "javascript:", "<foreignobject", "<iframe", "<embed", "<object"}
	eventHandlerRe  = regexp.MustCompile(`[\t\n\f\r /]on[a-z]{3,20}\s*=`)
	oleVBA          = utf16le("_VBA_PROJECT")
	oleEncrypted    = utf16le("EncryptedPackage")
	oleNative       = utf16le("\x01Ole10Native")
)

func utf16le(s string) []byte {
	out := make([]byte, 0, 2*len(s))
	for i := 0; i < len(s); i++ {
		out = append(out, s[i], 0)
	}
	return out
}

// eicar is the EICAR test string, in two halves so this source file is not itself the test file.
var eicar = []byte(`X5O!P%@AP[4\PZX54(P^)7CC)7}$` + `EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*`)

// UploadScanner inspects a file fed in pieces: Push as the bytes arrive, Finish once.
type UploadScanner struct {
	name, contentType string
	scanBytes         int64
	trusted           map[string]bool
	size, scanned     int64
	head              []byte
	tail              []byte
	carry, carryFold  []byte
	pending           []byte
	hash              hash.Hash
	builtin, custom   *sigMatcher
	markers           map[string]bool
	tar               *tarReader
	tarChecked        bool
}

// NewUploadScanner starts an inspection. scanBytes 0 is the default (8 MiB);
// custom are the organization's own signatures (deep scan on), trusted the
// SHA-256 hashes marked safe.
func NewUploadScanner(name, contentType string, scanBytes int64, custom []*Signature, trusted map[string]bool) *UploadScanner {
	if scanBytes <= 0 {
		scanBytes = DefaultUploadScanBytes
	}
	if scanBytes > MaxUploadScanBytes {
		scanBytes = MaxUploadScanBytes
	}
	s := &UploadScanner{name: name, contentType: contentType, scanBytes: scanBytes, trusted: trusted, hash: sha256.New(), builtin: newSigMatcher(BuiltInSignatures), markers: map[string]bool{}}
	if len(custom) > 0 {
		s.custom = newSigMatcher(custom)
	}
	return s
}

// Write is Push, so the scanner is an io.Writer (io.Copy, io.TeeReader).
func (s *UploadScanner) Write(p []byte) (int, error) {
	s.Push(p)
	return len(p), nil
}

// Push feeds the next bytes.
func (s *UploadScanner) Push(data []byte) {
	if len(data) == 0 {
		return
	}
	offset := s.size
	s.size += int64(len(data))
	s.hash.Write(data)
	if len(s.head) < uploadHead {
		s.head = append(s.head, data[:min(len(data), uploadHead-len(s.head))]...)
	}
	s.tail = append(s.tail, data...)
	if len(s.tail) > 2*uploadTail {
		s.tail = append([]byte(nil), s.tail[len(s.tail)-uploadTail:]...)
	}
	if !s.tarChecked && len(s.head) >= 262 {
		s.tarChecked = true
		if SniffUploadType(s.head) == "tar" {
			s.tar = &tarReader{}
			fed := int64(min(len(s.head), int(offset)+len(data)))
			s.tar.feed(s.head[:fed], 0)
			if offset+int64(len(data)) > fed {
				s.tar.feed(data[fed-offset:], fed)
			}
		}
	} else if s.tar != nil {
		s.tar.feed(data, offset)
	}
	if s.scanned < s.scanBytes {
		part := data[:min(int64(len(data)), s.scanBytes-s.scanned)]
		s.scanned += int64(len(part))
		s.pending = append(s.pending, part...)
		if len(s.pending) >= uploadPiece {
			s.flush(false)
		}
	}
}

func (s *UploadScanner) scan(text, folded []byte, final bool) {
	s.builtin.feed(text, folded, final)
	if s.custom != nil {
		s.custom.feed(text, folded, final)
	}
	for _, m := range append(append([]string{}, polyglotMarkers...), activeMarkers...) {
		if bytes.Contains(folded, []byte(m)) {
			s.markers[m] = true
		}
	}
	if eventHandlerRe.Match(folded) {
		s.markers["on*="] = true
	}
	for _, m := range [][]byte{oleVBA, oleEncrypted, oleNative} {
		if bytes.Contains(text, m) {
			s.markers[string(m)] = true
		}
	}
}

func (s *UploadScanner) flush(final bool) {
	if len(s.pending) == 0 && !final {
		return
	}
	text := append(append([]byte{}, s.carry...), s.pending...)
	folded := append(append([]byte{}, s.carryFold...), asciiFold(s.pending)...)
	s.pending = nil
	s.scan(text, folded, final)
	s.carry = append([]byte(nil), text[max(0, len(text)-sigOverlap):]...)
	s.carryFold = append([]byte(nil), folded[max(0, len(folded)-sigOverlap):]...)
}

// Finish is the verdict. complete: the scanner saw every byte (only then is
// the hash reported).
func (s *UploadScanner) Finish(complete bool) UploadVerdict {
	s.flush(true)
	tail := s.tail
	if len(tail) > uploadTail {
		tail = tail[len(tail)-uploadTail:]
	}
	if s.size > s.scanned {
		unseen := s.size - s.scanned
		if unseen > int64(len(tail)) {
			unseen = int64(len(tail))
		}
		extra := tail[int64(len(tail))-unseen:]
		s.scan(extra, asciiFold(extra), true)
	}
	v := UploadVerdict{Size: s.size, Ext: UploadExt(s.name)}
	if complete {
		v.SHA256 = hex.EncodeToString(s.hash.Sum(nil))
	}
	t := SniffUploadType(s.head)
	var entries []archiveEntry
	var total uint64
	if t == "zip" {
		if es, tot, ok := zipEntries(tail); ok {
			entries, total = es, tot
			has := func(p func(string) bool) bool {
				for _, e := range entries {
					if p(strings.ReplaceAll(e.name, `\`, "/")) {
						return true
					}
				}
				return false
			}
			if has(func(n string) bool { return n == "[Content_Types].xml" }) {
				switch {
				case has(func(n string) bool { return strings.HasPrefix(n, "word/") }):
					t = "docx"
				case has(func(n string) bool { return strings.HasPrefix(n, "xl/") }):
					t = "xlsx"
				case has(func(n string) bool { return strings.HasPrefix(n, "ppt/") }):
					t = "pptx"
				}
			}
			if t == "zip" && has(func(n string) bool { return strings.HasPrefix(n, "WEB-INF/") }) {
				t = "war"
			} else if t == "zip" && has(func(n string) bool { return n == "META-INF/MANIFEST.MF" }) {
				t = "jar"
			}
		}
	} else if s.tar != nil {
		entries, total = s.tar.entries, uint64(len(s.tar.entries))
	}
	v.Type, v.Kind = t, UploadKindOf(t)
	add := func(rule, engine, sig string) {
		v.Findings = append(v.Findings, UploadFinding{Rule: rule, Engine: engine, Signature: sig, Capped: cappedUploadRules[rule]})
	}
	if v.SHA256 == "" || !s.trusted[v.SHA256] {
		if s.size <= 256 {
			txt := bytes.TrimRight(s.head, " \t\r\n\f\v")
			if len(txt) <= 128 && bytes.HasPrefix(txt, eicar) {
				add("upload.eicar", "builtin", "")
			}
		}
		if m := s.builtin.matched(); len(m) > 0 {
			add("upload.webshell", "builtin", m[0].ID)
		}
		if s.custom != nil {
			if m := s.custom.matched(); len(m) > 0 {
				add("upload.signature", "custom", m[0].ID)
			}
		}
		anyMarker := func(ms []string) bool {
			for _, m := range ms {
				if s.markers[m] {
					return true
				}
			}
			return false
		}
		switch v.Kind {
		case "executable":
			add("upload.executable", "builtin", "")
		case "script":
			add("upload.script", "builtin", "")
		case "image", "document", "media", "archive":
			if anyMarker(polyglotMarkers) {
				add("upload.polyglot", "builtin", "")
			}
		case "html", "svg":
			if anyMarker(activeMarkers) || s.markers["on*="] {
				add("upload.active_content", "builtin", "")
			}
		}
		if s.name != "" && IsServerConfigName(s.name) {
			add("upload.server_config", "builtin", "")
		}
		if s.name != "" && HasDoubleExtension(s.name) {
			add("upload.double_extension", "builtin", "")
		}
		var declared uint64
		var traversal, link, encrypted, macro, ole, script, entryBomb bool
		for _, e := range entries {
			declared += e.size
			n := strings.ReplaceAll(e.name, `\`, "/")
			last := path.Base("/" + n)
			traversal = traversal || UploadEntryEscapes(e.name)
			link = link || e.symlink
			encrypted = encrypted || e.encrypted
			macro = macro || strings.EqualFold(last, "vbaProject.bin")
			ole = ole || uploadOleEntry.MatchString(n)
			script = script || uploadArchiveExt.MatchString(last)
			compressed := e.compressed
			if compressed < 1 {
				compressed = 1
			}
			entryBomb = entryBomb || (e.size > 10*mib && e.size > 1000*compressed)
		}
		if traversal {
			add("upload.archive_traversal", "builtin", "")
		}
		if link {
			add("upload.archive_symlink", "builtin", "")
		}
		bomb := total > 10000 || len(entries) > 10000 || declared > 1024*mib || entryBomb
		if t == "gzip" && len(tail) >= 4 && s.size > 18 {
			isize := uint64(binary.LittleEndian.Uint32(tail[len(tail)-4:]))
			bomb = bomb || (isize > 10*mib && isize > 1000*uint64(s.size))
		}
		if bomb {
			add("upload.archive_bomb", "builtin", "")
		}
		if encrypted || (t == "ole2" && s.markers[string(oleEncrypted)]) {
			add("upload.archive_encrypted", "builtin", "")
		}
		if macro || (t == "ole2" && s.markers[string(oleVBA)]) {
			add("upload.office_macro", "builtin", "")
		}
		if ole || (t == "ole2" && s.markers[string(oleNative)]) {
			add("upload.office_ole", "builtin", "")
		}
		if script {
			add("upload.archive_script", "builtin", "")
		}
		if UploadTypeMismatch(t, s.name, s.contentType) {
			add("upload.type_mismatch", "builtin", "")
		}
	}
	sort.SliceStable(v.Findings, func(i, j int) bool { return uploadRuleRank(v.Findings[i].Rule) < uploadRuleRank(v.Findings[j].Rule) })
	return v
}

// InspectUploadBytes inspects bytes in memory.
func InspectUploadBytes(data []byte, name, contentType string) UploadVerdict {
	s := NewUploadScanner(name, contentType, 0, nil, nil)
	s.Push(data)
	return s.Finish(true)
}

// ---- reporting ----------------------------------------------------------------------------

// UploadOptions are what InspectUpload applies: the policy (README "Upload
// policy and deep scan"). The zero value is no policy.
type UploadOptions struct {
	// Field is the form field (the event's input key body.<field>.filename).
	Field string
	// Allow lists types or kinds; empty is any type. A type listed by name
	// gets past the type checks.
	Allow []string
	// MaxBytes 0 is no limit.
	MaxBytes int64
	// Mode, when set, decides the built-in findings instead of malicious_upload's mode.
	Mode Mode
	// Signatures are the organization's own (decided by DeepScanMode).
	Signatures   []*Signature
	DeepScanMode Mode
	// DeepScan are the deep scan engines (ClamAV, reputation) and how they
	// run; they run when DeepScanMode is monitor or block.
	DeepScan  DeepScanOptions
	Trusted   map[string]bool
	ScanBytes int64
}

var uploadTypeRules = map[string]bool{"upload.executable": true, "upload.script": true, "upload.type_mismatch": true}

// InspectUpload reads an uploaded file (bounded memory), reports what it is
// (README "Inspection rules": one event a file, the strongest decision) and
// returns the verdict, and the block error when it must be refused. Edge and
// apps that parse multipart themselves call it for each file part.
func InspectUpload(ctx context.Context, r io.Reader, name, contentType string, o UploadOptions) (UploadVerdict, error) {
	return inspectUpload(ctx, r, name, contentType, o, !o.DeepScan.Async)
}

// inspectUpload is InspectUpload; deep runs the deep scan engines on the
// bytes as they are read (a sync deep scan), reported with sink
// upload.deep_scan after the inspection's own event.
func inspectUpload(ctx context.Context, r io.Reader, name, contentType string, o UploadOptions, deep bool) (UploadVerdict, error) {
	s := o.NewScanner(name, contentType)
	var run *deepScanRun
	if deep && Active() {
		run = startDeepScan(o)
	}
	var w io.Writer = s
	if run != nil {
		w = io.MultiWriter(s, run)
	}
	if _, err := io.Copy(w, r); err != nil {
		run.abort()
		return s.Finish(false), nil
	}
	v := s.Finish(true)
	if !Active() {
		run.abort()
		return v, nil
	}
	addRequestUpload(ctx, name, v)
	if best := strongestUpload(UploadFindings(v, o), effectiveUploadMode); best != nil {
		if _, err := HandleFinding(ctx, best, "request.upload", FindingExtra{}); err != nil {
			run.abort()
			return v, err
		}
	}
	if run == nil {
		return v, nil
	}
	if v.SHA256 != "" && o.Trusted[v.SHA256] {
		run.abort()
		return v, nil
	}
	if f := run.finish(ctx, v.SHA256, true); f != nil {
		_, err := HandleFinding(ctx, deepFinding(*f, v, o), DeepScanSink, FindingExtra{})
		return v, err
	}
	return v, nil
}

// NewScanner starts an inspection with these options: the scan size, the
// trusted hashes, and the organization's own signatures when the deep scan
// is on.
func (o UploadOptions) NewScanner(name, contentType string) *UploadScanner {
	var custom []*Signature
	if o.DeepScanMode != "" && o.DeepScanMode != ModeOff {
		custom = o.Signatures
	}
	return NewUploadScanner(name, contentType, o.ScanBytes, custom, o.Trusted)
}

// UploadFindings applies the policy (allow list, maxBytes, a listed type
// passing the type checks) to a verdict and returns one malicious_upload
// finding per rule, in README "Inspection rules" order, each carrying the
// mode that decides it and the upload event attributes.
func UploadFindings(v UploadVerdict, o UploadOptions) []*Finding {
	findings := append([]UploadFinding{}, v.Findings...)
	if len(o.Allow) > 0 && !containsStr(o.Allow, v.Type) && !containsStr(o.Allow, v.Kind) {
		findings = append(findings, UploadFinding{Rule: "upload.type_not_allowed", Engine: "policy"})
	}
	if o.MaxBytes > 0 && v.Size > o.MaxBytes {
		findings = append(findings, UploadFinding{Rule: "upload.too_large", Engine: "policy"})
	}
	if containsStr(o.Allow, v.Type) || containsStr(o.Allow, v.Kind) {
		kept := findings[:0]
		for _, f := range findings {
			if !uploadTypeRules[f.Rule] {
				kept = append(kept, f)
			}
		}
		findings = kept
	}
	sort.SliceStable(findings, func(i, j int) bool { return uploadRuleRank(findings[i].Rule) < uploadRuleRank(findings[j].Rule) })
	field := o.Field
	if field == "" {
		field = "file"
	}
	out := make([]*Finding, 0, len(findings))
	for _, f := range findings {
		mode := o.Mode
		if f.Engine == "custom" {
			mode = o.DeepScanMode
		}
		fd := &Finding{Attack: MaliciousUpload, Rule: f.Rule, Input: &Input{Key: "body." + field + ".filename", Source: SourceRequest}, Mode: mode,
			Upload: &UploadAttrs{Type: v.Type, Kind: v.Kind, Ext: v.Ext, Size: v.Size, SHA256: v.SHA256, Signature: f.Signature, Engine: f.Engine}}
		if f.Capped {
			fd.Action = ModeMonitor
		}
		out = append(out, fd)
	}
	return out
}

// strongestUpload is the finding with the strongest decision, the rule
// order breaking ties (one event a file); nil when none decides more than off.
func strongestUpload(findings []*Finding, modeOf func(*Finding) Mode) *Finding {
	var best *Finding
	bestRank := 0
	for _, f := range findings {
		if rank := modeRank[modeOf(f)]; rank > bestRank {
			best, bestRank = f, rank
		}
	}
	return best
}

func effectiveUploadMode(f *Finding) Mode {
	if !Active() {
		return ModeOff
	}
	stateMu.RLock()
	m := modeForLocked(f.Attack)
	if f.Mode != "" && state.local.attacks[f.Attack] != ModeOff {
		m = f.Mode
		if m == ModeBlock && state.monitorOnly {
			m = ModeMonitor
		}
	}
	stateMu.RUnlock()
	if f.Action != "" && modeRank[f.Action] < modeRank[m] {
		m = f.Action
	}
	return m
}

var (
	uploadWordRe = regexp.MustCompile(`^[a-z0-9_]{1,16}$`)
	uploadSigRe  = regexp.MustCompile(`^[A-Za-z0-9._:/-]{1,128}$`)
	uploadSHARe  = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

// addUploadAttrs adds README "Upload event attributes", each only when it has its shape.
func addUploadAttrs(attrs map[string]string, f *Finding) {
	u := f.Upload
	if u == nil || (f.Attack != MaliciousUpload && f.Attack != UploadBackdoor) {
		return
	}
	p := "shield360.rasp.upload."
	if uploadWordRe.MatchString(u.Type) {
		attrs[p+"type"] = u.Type
	}
	if uploadWordRe.MatchString(u.Kind) {
		attrs[p+"kind"] = u.Kind
	}
	if uploadExtShape.MatchString(u.Ext) {
		attrs[p+"ext"] = u.Ext
	}
	if u.Size >= 0 {
		attrs[p+"size"] = strconv.FormatInt(u.Size, 10)
	}
	if uploadSHARe.MatchString(u.SHA256) {
		attrs[p+"sha256"] = u.SHA256
	}
	if uploadSigRe.MatchString(u.Signature) {
		attrs[p+"signature"] = u.Signature
	}
	switch u.Engine {
	case "builtin", "custom", "clamav", "reputation", "policy":
		attrs[p+"engine"] = u.Engine
	}
	if u.Dest != "" {
		if d, ok := MaskTarget(u.Dest); ok {
			attrs[p+"dest"] = d
		}
	}
	if u.Action == "quarantined" {
		attrs[p+"action"] = "quarantined"
	}
}

// ---- policy from the signed config -------------------------------------------------------

// UploadRoutePolicy is one route's upload policy.
type UploadRoutePolicy struct {
	Route    string
	Allow    []string
	MaxBytes int64
	Mode     Mode
	DeepScan Mode
	// Scan ("sync", "async"), Timeout and FailMode ("open", "closed")
	// replace the deep scan's when set.
	Scan     string
	Timeout  time.Duration
	FailMode string
}

// UploadPolicy is the signed config's uploads block (or the local
// options): the inspection policy, the served directories the backdoor
// checks use, and the deep scan.
type UploadPolicy struct {
	Allow        []string
	MaxBytes     int64
	ServedDirs   []string
	Trusted      map[string]bool
	Signatures   []*Signature
	DeepScanMode Mode
	DeepScan     DeepScanOptions
	Routes       []UploadRoutePolicy
}

func uploadTimeout(v any) time.Duration {
	f, ok := v.(float64)
	if !ok || math.IsNaN(f) || math.IsInf(f, 0) {
		return 0
	}
	return time.Duration(min(60000, max(100, int64(f)))) * time.Millisecond
}

func parseDeepScan(v any) (Mode, DeepScanOptions) {
	d, _ := v.(map[string]any)
	o := DeepScanOptions{Timeout: defaultScanWait, ClamAV: ParseClamAddress(d["clamav"])}
	o.Async = d["scan"] == "async"
	if t := uploadTimeout(d["timeoutMs"]); t > 0 {
		o.Timeout = t
	}
	o.FailClosed = d["failMode"] == "closed"
	o.Reputation = d["reputation"] == true
	if tid, ok := d["testId"].(string); ok && len(tid) <= 128 {
		o.TestID = tid
	}
	mode := uploadMode(d["mode"])
	if mode == "" {
		mode = ModeOff
	}
	return mode, o
}

func uploadMode(v any) Mode {
	if s, ok := v.(string); ok && (s == "off" || s == "monitor" || s == "block") {
		return Mode(s)
	}
	return ""
}

func uploadInt(v any) int64 {
	if f, ok := v.(float64); ok && f >= 1 && f == float64(int64(f)) {
		return int64(f)
	}
	return 0
}

func uploadStrings(v any, max int, keep func(string) bool) []string {
	list, _ := v.([]any)
	var out []string
	for _, x := range list {
		if s, ok := x.(string); ok && keep(s) && len(out) < max {
			out = append(out, s)
		}
	}
	return out
}

func allowedUploadName(s string) bool {
	if _, ok := uploadKindOf[s]; ok {
		return true
	}
	switch s {
	case "image", "document", "text", "archive", "media", "executable", "script", "html", "svg", "other":
		return true
	}
	return false
}

// ParseUploadPolicy reads the signed config's uploads block; nil when absent or not an object.
func ParseUploadPolicy(raw json.RawMessage) *UploadPolicy {
	var m map[string]any
	if len(raw) == 0 || json.Unmarshal(raw, &m) != nil || m == nil {
		return nil
	}
	p := &UploadPolicy{Allow: uploadStrings(m["allow"], 64, allowedUploadName), MaxBytes: uploadInt(m["maxBytes"]), Trusted: map[string]bool{}}
	for _, h := range uploadStrings(m["trusted"], 1000, uploadSHARe.MatchString) {
		p.Trusted[h] = true
	}
	var rules struct {
		Rules []json.RawMessage `json:"rules"`
	}
	if json.Unmarshal(raw, &rules) == nil {
		p.Signatures, _ = CompileSignatures(rules.Rules)
	}
	p.DeepScanMode, p.DeepScan = parseDeepScan(m["deepScan"])
	p.ServedDirs = uploadStrings(m["servedDirs"], 32, func(s string) bool { return isAbsPath(s) && len(s) <= 512 })
	routes, _ := m["routes"].([]any)
	for _, r := range routes {
		rm, ok := r.(map[string]any)
		route, _ := rm["route"].(string)
		if !ok || !strings.HasPrefix(route, "/") || len(route) > 256 || len(p.Routes) >= 64 {
			continue
		}
		rp := UploadRoutePolicy{Route: route, MaxBytes: uploadInt(rm["maxBytes"]), Mode: uploadMode(rm["mode"]), DeepScan: uploadMode(rm["deepScan"]), Timeout: uploadTimeout(rm["timeoutMs"])}
		if sc, _ := rm["scan"].(string); sc == "sync" || sc == "async" {
			rp.Scan = sc
		}
		if fm, _ := rm["failMode"].(string); fm == "open" || fm == "closed" {
			rp.FailMode = fm
		}
		if _, has := rm["allow"]; has {
			rp.Allow = uploadStrings(rm["allow"], 64, allowedUploadName)
			if rp.Allow == nil {
				rp.Allow = []string{}
			}
		}
		p.Routes = append(p.Routes, rp)
	}
	return p
}

// UploadOptionsFor is the policy for a route from the verified signed config
// (the first route that equals it, or a prefix ending in *, else the app's).
func UploadOptionsFor(route string) UploadOptions {
	stateMu.RLock()
	r := state.remote
	stateMu.RUnlock()
	return uploadOptionsFrom(r, route)
}

func uploadOptionsFrom(r *RemoteConfig, route string) UploadOptions {
	var p *UploadPolicy
	if r != nil && r.Uploads != nil {
		p = r.Uploads
	} else if l := localUploads(); l.policy != nil {
		p = l.policy
	}
	if p == nil {
		return UploadOptions{}
	}
	o := UploadOptions{Allow: p.Allow, MaxBytes: p.MaxBytes, Signatures: p.Signatures, DeepScanMode: p.DeepScanMode, DeepScan: p.DeepScan, Trusted: p.Trusted, ScanBytes: localUploads().ScanBytes}
	for _, rp := range p.Routes {
		if (strings.HasSuffix(rp.Route, "*") && strings.HasPrefix(route, strings.TrimSuffix(rp.Route, "*"))) || rp.Route == route {
			if rp.Allow != nil {
				o.Allow = rp.Allow
			}
			if rp.MaxBytes > 0 {
				o.MaxBytes = rp.MaxBytes
			}
			o.Mode = rp.Mode
			if rp.DeepScan != "" {
				o.DeepScanMode = rp.DeepScan
			}
			if rp.Scan != "" {
				o.DeepScan.Async = rp.Scan == "async"
			}
			if rp.Timeout > 0 {
				o.DeepScan.Timeout = rp.Timeout
			}
			if rp.FailMode != "" {
				o.DeepScan.FailClosed = rp.FailMode == "closed"
			}
			break
		}
	}
	return o
}

// UploadSettings are the local upload options, used without a signed
// config (README "Upload policy and deep scan"): the same block as the
// signed config's uploads (servedDirs, maxBytes, allow, deepScan, routes,
// trusted, rules) as JSON, plus ScanBytes and QuarantineDir (local only).
type UploadSettings struct {
	// Policy is the uploads block as JSON (the signed config's shape).
	Policy        json.RawMessage
	ScanBytes     int64
	QuarantineDir string
}

type localUploadState struct {
	policy     *UploadPolicy
	ServedDirs []string
	ScanBytes  int64
}

var (
	localUploadMu sync.RWMutex
	localUpload   localUploadState
)

func setLocalUploads(u *UploadSettings) {
	st := localUploadState{}
	dir := ""
	if u != nil {
		st.policy = ParseUploadPolicy(u.Policy)
		if st.policy != nil {
			st.ServedDirs = st.policy.ServedDirs
		}
		st.ScanBytes = u.ScanBytes
		dir = u.QuarantineDir
	}
	localUploadMu.Lock()
	localUpload = st
	localUploadMu.Unlock()
	setQuarantineDir(dir)
}

func localUploads() localUploadState {
	localUploadMu.RLock()
	defer localUploadMu.RUnlock()
	return localUpload
}
