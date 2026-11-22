package rasp

// Upload inspection (README "Uploads"): the conformance corpus
// (testdata/uploads.json), fixture files built here (never real malware: the
// shells are inert text and EICAR is the industry's harmless test string), the
// policy, and the events. Mirrors the TypeScript SDK's uploads.test.ts.

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type uploadCorpus struct {
	Types []struct {
		Hex  string `json:"hex"`
		Type string `json:"type"`
	} `json:"types"`
	Names []struct {
		Name  string   `json:"name"`
		Rules []string `json:"rules"`
	} `json:"names"`
	Mismatch []struct {
		Type        string `json:"type"`
		Name        string `json:"name"`
		ContentType string `json:"contentType"`
		Mismatch    bool   `json:"mismatch"`
	} `json:"mismatch"`
	Signatures []struct {
		Rule   map[string]any `json:"rule"`
		Sample string         `json:"sample"`
		Match  bool           `json:"match"`
	} `json:"signatures"`
	Invalid []struct {
		Rule any    `json:"rule"`
		Code string `json:"code"`
	} `json:"invalid"`
}

// readShared reads a file from sdk/rasp: ../../rasp in the monorepo, or the
// copy the Go mirror ships beside this package (.github/scripts/mirror-sdk.sh).
func readShared(parts ...string) ([]byte, error) {
	raw, err := os.ReadFile(filepath.Join(append([]string{"..", "..", "rasp"}, parts...)...))
	if err == nil {
		return raw, nil
	}
	return os.ReadFile(filepath.Join(append([]string{"mirror-shared"}, parts...)...))
}

func loadUploadCorpus(t *testing.T) uploadCorpus {
	t.Helper()
	raw, err := readShared("testdata", "uploads.json")
	if err != nil {
		t.Fatal(err)
	}
	var c uploadCorpus
	if err := json.Unmarshal(raw, &c); err != nil {
		t.Fatal(err)
	}
	return c
}

func TestUploadSignaturesByteIdentical(t *testing.T) {
	contract, err := readShared("rules", "upload-signatures.json")
	if err != nil || !bytes.Equal(contract, uploadSignaturesJSON) {
		t.Fatal("data/upload-signatures.json must be byte-identical to sdk/rasp/rules/upload-signatures.json")
	}
	var d struct {
		Rules []json.RawMessage `json:"rules"`
	}
	_ = json.Unmarshal(contract, &d)
	if len(BuiltInSignatures) != len(d.Rules) {
		_, errs := CompileSignatures(d.Rules)
		t.Fatalf("%d of %d built-in signatures compile: %v", len(BuiltInSignatures), len(d.Rules), errs[0])
	}
}

func TestUploadConformance(t *testing.T) {
	c := loadUploadCorpus(t)
	for _, tc := range c.Types {
		b, _ := hex.DecodeString(tc.Hex)
		if got := SniffUploadType(b); got != tc.Type {
			t.Errorf("sniff %s: got %s", tc.Type, got)
		}
	}
	for _, tc := range c.Names {
		var got []string
		if IsServerConfigName(tc.Name) {
			got = append(got, "upload.server_config")
		}
		if HasDoubleExtension(tc.Name) {
			got = append(got, "upload.double_extension")
		}
		if strings.Join(got, ",") != strings.Join(tc.Rules, ",") {
			t.Errorf("name %q: got %v want %v", tc.Name, got, tc.Rules)
		}
	}
	for _, tc := range c.Mismatch {
		if got := UploadTypeMismatch(tc.Type, tc.Name, tc.ContentType); got != tc.Mismatch {
			t.Errorf("mismatch %+v: got %v", tc, got)
		}
	}
	for _, tc := range c.Signatures {
		sig, err := CompileSignature(tc.Rule)
		if err != nil {
			t.Errorf("signature %v: %v", tc.Rule["id"], err.Code)
			continue
		}
		sample := []byte(tc.Sample)
		if tc.Sample == "@@ACROSS@@" {
			sample = append(append(bytes.Repeat([]byte("x"), 1048570), "MARKERTEXT"...), bytes.Repeat([]byte("x"), 100)...)
		}
		if got := len(MatchSample([]*Signature{sig}, sample)) > 0; got != tc.Match {
			t.Errorf("signature %v: match %v", tc.Rule["id"], got)
		}
	}
	for _, tc := range c.Invalid {
		_, err := CompileSignature(tc.Rule)
		if err == nil || err.Code != tc.Code {
			t.Errorf("invalid %v: got %v want %s", tc.Rule, err, tc.Code)
		}
	}
}

func TestSignatureWorkIsBounded(t *testing.T) {
	sig, err := CompileSignature(map[string]any{"id": "r", "title": "t", "strings": []any{map[string]any{"id": "a", "regex": "(a|aa)*b", "anchor": "aaa"}}, "condition": "any"})
	if err != nil {
		t.Fatal(err.Code)
	}
	start := time.Now()
	if ids := MatchSample([]*Signature{sig}, bytes.Repeat([]byte("a"), 4<<20)); len(ids) != 0 {
		t.Fatal(ids)
	}
	if time.Since(start) > 5*time.Second {
		t.Fatal("regex work is not bounded")
	}
}

// ---- fixtures ----------------------------------------------------------------------

var (
	eicarFixture = []byte(`X5O!P%@AP[4\PZX54(P^)7CC)7}$` + `EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*`)
	jpegFixture  = append([]byte{0xff, 0xd8, 0xff, 0xe0, 0, 0x10, 'J', 'F', 'I', 'F', 0}, bytes.Repeat([]byte{7}, 200)...)
	pngFixture   = append([]byte{0x89, 'P', 'N', 'G', 0x0d, 0x0a, 0x1a, 0x0a}, bytes.Repeat([]byte{1}, 300)...)
	pdfFixture   = []byte("%PDF-1.4\n1 0 obj << /Type /Catalog >> endobj\ntrailer << /Root 1 0 R >>\n%%EOF\n")
	csvFixture   = []byte("name,amount,note\nalice,3,\"on time\"\nbob,5,late\n")
	shellFixture = []byte(`<?php @eval($_POST["x"]); ?>`)
)

type zipEntryFixture struct {
	name      string
	data      []byte
	symlink   bool
	encrypted bool
	declared  uint32
}

func zipFixture(t *testing.T, entries ...zipEntryFixture) []byte {
	t.Helper()
	var buf bytes.Buffer
	w := zip.NewWriter(&buf)
	for _, e := range entries {
		h := &zip.FileHeader{Name: e.name, Method: zip.Store}
		if e.symlink {
			h.SetMode(os.ModeSymlink | 0o777)
		}
		f, err := w.CreateHeader(h)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = f.Write(append([]byte{}, e.data...))
	}
	_ = w.Close()
	out := buf.Bytes()
	// Patch the central directory for the declared-size and encryption cases.
	for p := bytes.Index(out, []byte("PK\x01\x02")); p >= 0; {
		n := int(binary.LittleEndian.Uint16(out[p+28:]))
		name := string(out[p+46 : p+46+n])
		for _, e := range entries {
			if e.name != name {
				continue
			}
			if e.declared > 0 {
				binary.LittleEndian.PutUint32(out[p+24:], e.declared)
			}
			if e.encrypted {
				binary.LittleEndian.PutUint16(out[p+8:], binary.LittleEndian.Uint16(out[p+8:])|1)
			}
		}
		q := bytes.Index(out[p+4:], []byte("PK\x01\x02"))
		if q < 0 {
			break
		}
		p += 4 + q
	}
	return out
}

func tarFixture(t *testing.T, name string, typ byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	w := tar.NewWriter(&buf)
	h := &tar.Header{Name: name, Typeflag: typ, Mode: 0o644, Format: tar.FormatUSTAR}
	if typ == tar.TypeSymlink {
		h.Linkname = "/etc/passwd"
	} else {
		h.Size = 1
	}
	if err := w.WriteHeader(h); err != nil {
		t.Fatal(err)
	}
	if typ != tar.TypeSymlink {
		_, _ = w.Write([]byte("x"))
	}
	_ = w.Close()
	return buf.Bytes()
}

func firstRule(data []byte, name string) string {
	v := InspectUploadBytes(data, name, "")
	if len(v.Findings) == 0 {
		return ""
	}
	return v.Findings[0].Rule
}

func TestUploadFixtures(t *testing.T) {
	v := InspectUploadBytes(append(append(append([]byte{}, jpegFixture...), shellFixture...), 9, 9, 9), "profile.jpg", "image/jpeg")
	if v.Type != "jpeg" || v.Findings[0].Rule != "upload.webshell" || v.Findings[0].Signature != "php.eval_request" {
		t.Errorf("image with embedded shell: %+v", v)
	}
	if v := InspectUploadBytes([]byte(`<?php system($_GET["c"]); ?>`), "avatar.jpg", "image/jpeg"); v.Findings[0].Signature != "php.exec_request" {
		t.Errorf(".jpg that is PHP: %+v", v)
	}
	if got := firstRule([]byte(`<?php echo "hi"; ?>`), "a.jpg"); got != "upload.script" {
		t.Errorf("plain php: %s", got)
	}
	if got := firstRule([]byte(`<svg xmlns="http://www.w3.org/2000/svg"><script>x()</script></svg>`), "logo.svg"); got != "upload.active_content" {
		t.Errorf("svg with script: %s", got)
	}
	if got := firstRule([]byte(`<svg xmlns="http://www.w3.org/2000/svg" onload="x()"></svg>`), "logo.svg"); got != "upload.active_content" {
		t.Errorf("svg with handler: %s", got)
	}
	cases := []struct {
		data []byte
		name string
		want string
	}{
		{zipFixture(t, zipEntryFixture{name: "../../var/www/html/x.php", data: []byte("a")}), "a.zip", "upload.archive_traversal"},
		{zipFixture(t, zipEntryFixture{name: "link", data: []byte("/etc/passwd"), symlink: true}), "a.zip", "upload.archive_symlink"},
		{zipFixture(t, zipEntryFixture{name: "big.bin", data: make([]byte, 1000), declared: 4000 << 20}), "a.zip", "upload.archive_bomb"},
		{zipFixture(t, zipEntryFixture{name: "secret.txt", data: []byte("xxxx"), encrypted: true}), "a.zip", "upload.archive_encrypted"},
		{tarFixture(t, "../etc/cron.d/x", tar.TypeReg), "a.tar", "upload.archive_traversal"},
		{tarFixture(t, "link", tar.TypeSymlink), "a.tar", "upload.archive_symlink"},
		{eicarFixture, "test.txt", "upload.eicar"},
		{[]byte{0x7f, 'E', 'L', 'F', 2, 1, 1, 0, 0, 0}, "cat.png", "upload.executable"},
		{[]byte("AddType application/x-httpd-php .jpg\n"), ".htaccess", "upload.server_config"},
		{pngFixture, "shell.php.png", "upload.double_extension"},
	}
	for _, c := range cases {
		if got := firstRule(c.data, c.name); got != c.want {
			t.Errorf("%s: got %q want %q", c.name, got, c.want)
		}
	}
	docm := zipFixture(t, zipEntryFixture{name: "[Content_Types].xml", data: []byte("<Types/>")}, zipEntryFixture{name: "word/document.xml", data: []byte("<w/>")}, zipEntryFixture{name: "word/vbaProject.bin", data: []byte("stub")})
	if v := InspectUploadBytes(docm, "report.docx", ""); v.Type != "docx" || v.Findings[0].Rule != "upload.office_macro" {
		t.Errorf("macro doc: %+v", v)
	}
	ole := append(append([]byte{0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1}, make([]byte, 100)...), utf16le("_VBA_PROJECT")...)
	if got := firstRule(ole, "old.doc"); got != "upload.office_macro" {
		t.Errorf("ole macro: %s", got)
	}
	for _, b := range []struct {
		data     []byte
		name, ct string
	}{{pdfFixture, "invoice.pdf", "application/pdf"}, {pngFixture, "photo.png", "image/png"}, {jpegFixture, "me.jpg", "image/jpeg"}, {csvFixture, "data.csv", "text/csv"}} {
		v := InspectUploadBytes(b.data, b.name, b.ct)
		if len(v.Findings) != 0 || len(v.SHA256) != 64 {
			t.Errorf("benign %s: %+v", b.name, v)
		}
	}
}

func TestInspectUploadEventsAndPolicy(t *testing.T) {
	log := setupEngine(t, engineSettings{})
	v, err := InspectUpload(context.Background(), bytes.NewReader(append(append([]byte{}, jpegFixture...), shellFixture...)), "profile.jpg", "image/jpeg", UploadOptions{Field: "avatar"})
	if err != nil || v.Type != "jpeg" {
		t.Fatalf("%v %+v", err, v)
	}
	ev := log.all()
	if len(ev) != 1 {
		t.Fatalf("events %v", ev)
	}
	a := ev[0].Attrs
	if a["shield360.rasp.attack"] != "malicious_upload" || a["shield360.rasp.rule"] != "upload.webshell" || a["shield360.rasp.input_key"] != "body.avatar.filename" ||
		a["shield360.rasp.upload.type"] != "jpeg" || a["shield360.rasp.upload.ext"] != "jpg" || a["shield360.rasp.upload.signature"] != "php.eval_request" || len(a["shield360.rasp.upload.sha256"]) != 64 {
		t.Errorf("attrs %v", a)
	}
	for _, val := range a {
		if strings.Contains(val, "profile") || strings.Contains(val, "eval(") {
			t.Errorf("an attribute carries the name or content: %q", val)
		}
	}

	// A route's own mode blocks; a capped rule never does; a listed type passes the type checks.
	_, err = InspectUpload(context.Background(), bytes.NewReader(pdfFixture), "a.pdf", "application/pdf", UploadOptions{Allow: []string{"image"}, Mode: ModeBlock})
	var blocked *BlockedError
	if !errors.As(err, &blocked) || blocked.Rule != "upload.type_not_allowed" {
		t.Errorf("type not allowed: %v", err)
	}
	if _, err = InspectUpload(context.Background(), bytes.NewReader(zipFixture(t, zipEntryFixture{name: "a.txt", data: []byte("a")})), "a.jpg", "", UploadOptions{Mode: ModeBlock}); err != nil {
		t.Errorf("capped mismatch blocked: %v", err)
	}
	if _, err = InspectUpload(context.Background(), bytes.NewReader([]byte{0x7f, 'E', 'L', 'F', 2, 1, 1, 0}), "tool", "", UploadOptions{Allow: []string{"executable"}, Mode: ModeBlock}); err != nil {
		t.Errorf("listed type blocked: %v", err)
	}
	// No pinned key: the route's block is lowered to monitor.
	log2 := setupEngine(t, engineSettings{monitorOnly: true})
	if _, err = InspectUpload(context.Background(), bytes.NewReader(shellFixture), "a.jpg", "", UploadOptions{Mode: ModeBlock}); err != nil || log2.all()[0].Attrs["shield360.rasp.decision"] != "monitored" {
		t.Errorf("monitor only: %v %v", err, log2.all())
	}
	// Own signatures run only with the deep scan on.
	own, _ := CompileSignature(map[string]any{"id": "acme.marker", "title": "ACME", "strings": []any{map[string]any{"id": "a", "text": "ACME-INTERNAL-ONLY"}}, "condition": "any"})
	log3 := setupEngine(t, engineSettings{})
	_, _ = InspectUpload(context.Background(), strings.NewReader("x ACME-INTERNAL-ONLY y"), "a.txt", "", UploadOptions{Signatures: []*Signature{own}})
	if len(log3.all()) != 0 {
		t.Errorf("own signature ran with deep scan off: %v", log3.all())
	}
	_, err = InspectUpload(context.Background(), strings.NewReader("x ACME-INTERNAL-ONLY y"), "a.txt", "", UploadOptions{Signatures: []*Signature{own}, DeepScanMode: ModeBlock})
	if !errors.As(err, &blocked) || blocked.Rule != "upload.signature" {
		t.Errorf("own signature: %v", err)
	}
}

func TestUploadPolicyFromSignedConfig(t *testing.T) {
	p := ParseUploadPolicy(json.RawMessage(`{"allow":["image","nope"],"maxBytes":-1,"trusted":["` + strings.Repeat("a", 64) + `","x"],
		"rules":[{"id":"r","title":"t","strings":[{"id":"a","text":"abc"}],"condition":"any"}],"deepScan":{"mode":"monitor"},
		"routes":[{"route":"/api/*","allow":["pdf"],"maxBytes":10,"mode":"block","deepScan":"block"},{"route":"bad"}]}`))
	if p == nil || len(p.Allow) != 1 || p.MaxBytes != 0 || len(p.Trusted) != 1 || len(p.Signatures) != 1 || p.DeepScanMode != ModeMonitor || len(p.Routes) != 1 {
		t.Fatalf("%+v", p)
	}
	setupEngine(t, engineSettings{})
	setRemoteConfig(&RemoteConfig{Version: "v", Exp: float64(time.Now().Add(time.Hour).Unix()), Attacks: map[AttackType]Mode{}, Uploads: p})
	o := UploadOptionsFor("/api/avatar")
	if o.Mode != ModeBlock || o.DeepScanMode != ModeBlock || o.MaxBytes != 10 || o.Allow[0] != "pdf" {
		t.Errorf("route: %+v", o)
	}
	if o := UploadOptionsFor("/other"); o.Mode != "" || o.Allow[0] != "image" || o.DeepScanMode != ModeMonitor {
		t.Errorf("app: %+v", o)
	}
	if ParseUploadPolicy(json.RawMessage(`null`)) != nil {
		t.Error("null is no policy")
	}
}
