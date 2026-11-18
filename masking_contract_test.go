package shield360

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/ThinkfleetAI/shield360-go/rasp"
)

// The masking contract (sdk/rasp/README.md, "Masking"), held to the shared
// cases every SDK checks: application log text and RASP snippets.
type maskingCases struct {
	Text []struct {
		Name string `json:"name"`
		In   string `json:"in"`
		Out  string `json:"out"`
	} `json:"text"`
	Limited []struct {
		Name  string `json:"name"`
		In    string `json:"in"`
		Limit int    `json:"limit"`
		Out   string `json:"out"`
	} `json:"limited"`
	Snippets []struct {
		In  string `json:"in"`
		Out string `json:"out"`
	} `json:"snippets"`
}

func loadMaskingCases(t *testing.T) maskingCases {
	t.Helper()
	for _, p := range []string{
		filepath.Join("..", "rasp", "testdata", "masking.json"),
		filepath.Join("rasp", "testdata", "masking.json"),
	} {
		data, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		var c maskingCases
		if err := json.Unmarshal(data, &c); err != nil {
			t.Fatalf("masking.json: %v", err)
		}
		return c
	}
	t.Fatal("sdk/rasp/testdata/masking.json not found")
	return maskingCases{}
}

func TestMaskingContractLogsAndSnippets(t *testing.T) {
	c := loadMaskingCases(t)
	for _, tc := range c.Text {
		if got := MaskLogText(tc.In, 1<<20); got != tc.Out {
			t.Errorf("text %q: MaskLogText(%q) = %q, want %q", tc.Name, tc.In, got, tc.Out)
		}
	}
	for _, tc := range c.Limited {
		if got := MaskLogText(tc.In, tc.Limit); got != tc.Out {
			t.Errorf("limited %q: got %q, want %q", tc.Name, got, tc.Out)
		}
	}
	for _, tc := range c.Snippets {
		if got := rasp.MaskSnippet(tc.In); got != tc.Out {
			t.Errorf("snippet %q: got %q, want %q", tc.In, got, tc.Out)
		}
	}
}
