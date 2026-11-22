package defend

import (
	"bytes"
	"encoding/json"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/ThinkfleetAI/shield360-go/clienttype"
)

// Defend's shared data and corpora: the prompt-injection golden corpus
// (cli/internal/coding/injection/testdata, the Go detector's answers),
// byte-identical copies of the shared rules, signatures, detector and crumb
// code, and the crumb spec's test vector. Read from the monorepo; skipped
// when the SDK is built on its own (the public mirror).

func repo(t *testing.T, rel string) []byte {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "..", rel))
	if os.IsNotExist(err) {
		t.Skipf("%s not present (SDK built on its own)", rel)
	}
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestAgreesWithTheGoDetectorOnTheGoldenCorpus(t *testing.T) {
	var corpus struct {
		Samples []struct{ ID, Source, Text string }
	}
	var expected struct {
		Results []struct {
			ID       string
			Score    float64
			Detected bool
			Rules    []string
		}
	}
	if err := json.Unmarshal(repo(t, "cli/internal/coding/injection/testdata/corpus.json"), &corpus); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(repo(t, "cli/internal/coding/injection/testdata/expected.json"), &expected); err != nil {
		t.Fatal(err)
	}
	if len(corpus.Samples) != len(expected.Results) || len(corpus.Samples) < 100 {
		t.Fatalf("%d samples, %d results", len(corpus.Samples), len(expected.Results))
	}
	var failures []string
	prompts := 0
	for i, s := range corpus.Samples {
		e := expected.Results[i]
		if s.ID != e.ID {
			t.Fatalf("sample %d: %s vs %s", i, s.ID, e.ID)
		}
		if s.Source == "prompt" {
			prompts++
		}
		score, rules := InjectionScore(s.Text, s.Source)
		sort.Strings(rules)
		want := append([]string(nil), e.Rules...)
		sort.Strings(want)
		if math.Abs(score-e.Score) > 1e-9 || (score >= InjectionThreshold()) != e.Detected || strings.Join(rules, ",") != strings.Join(want, ",") {
			failures = append(failures, s.ID)
		}
	}
	if prompts < 100 {
		t.Fatalf("%d prompt samples", prompts)
	}
	if len(failures) > 0 {
		t.Fatalf("%d of %d samples differ: %v", len(failures), len(corpus.Samples), failures)
	}
}

func TestKeepsByteIdenticalCopiesOfSharedDataAndCode(t *testing.T) {
	for _, tc := range []struct{ copy, original string }{
		{"internal/injection/rules.json", "cli/internal/coding/injection/rules.json"},
		{"internal/injection/detector.go", "cli/internal/coding/injection/detector.go"},
		{"internal/crumb/crumb.go", "cli/internal/crumb/crumb.go"},
		{"../clienttype/signatures.json", "sdk/client-type/signatures.json"},
	} {
		got, err := os.ReadFile(tc.copy)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, repo(t, tc.original)) {
			t.Errorf("%s must be a byte-identical copy of %s", tc.copy, tc.original)
		}
	}
	if !bytes.Equal(clienttype.SignaturesJSON(), mustReadFile(t, "../clienttype/signatures.json")) {
		t.Error("the embedded signatures differ from the file")
	}
}

func mustReadFile(t *testing.T, p string) []byte {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// The crumb spec's test vector (agent-guides/edge-deception-spec.md).
func TestCrumbSpecVector(t *testing.T) {
	var secret [32]byte
	copy(secret[:], "0123456789abcdef0123456789abcdef")
	hp := NewHoneypots(HoneypotSettings{Mode: "block", Secret: secret, EpochSeconds: 86_400, Grace: 1}, nil, func() time.Time { return time.Unix(86400*20000, 0) })
	fp := Fingerprint("192.0.2.1", "Agent/1.0")
	c := hp.CrumbsFor("192.0.2.1", "Agent/1.0")
	if got := strings.TrimPrefix(c.Path, "/"+hp.word("aeaaatraobjtbzpygzcgysx5gll3ruka")+"/_internal/"); got != "aeaaatraobjtbzpygzcgysx5gll3ruka" {
		t.Fatalf("path crumb %s", c.Path)
	}
	if hexOf(fp) != "5330e5f83644" {
		t.Fatalf("fingerprint %s", hexOf(fp))
	}
	spec := string(repo(t, "agent-guides/edge-deception-spec.md"))
	if !strings.Contains(spec, "aeaaatraobjtbzpygzcgysx5gll3ruka") || !strings.Contains(spec, "5330e5f83644") {
		t.Fatal("the spec's vector changed")
	}
}

func hexOf(b [6]byte) string {
	const digits = "0123456789abcdef"
	out := make([]byte, 0, 12)
	for _, x := range b {
		out = append(out, digits[x>>4], digits[x&15])
	}
	return string(out)
}
