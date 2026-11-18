package masking

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

// Every section of sdk/rasp/testdata/masking.json, as in every other SDK.
type cases struct {
	Text []struct {
		Name, In, Out string
	} `json:"text"`
	Limited []struct {
		Name, In, Out string
		Limit         int
	} `json:"limited"`
	Keys []struct {
		Key       string `json:"key"`
		Sensitive bool   `json:"sensitive"`
	} `json:"keys"`
	Values []struct {
		Key   string `json:"key"`
		Value any    `json:"value"`
		Out   any    `json:"out"`
	} `json:"values"`
	Snippets []struct {
		In, Out string
	} `json:"snippets"`
}

func load(t *testing.T) cases {
	t.Helper()
	for _, p := range []string{
		filepath.Join("..", "..", "..", "rasp", "testdata", "masking.json"),
		filepath.Join("..", "..", "rasp", "testdata", "masking.json"),
	} {
		data, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		var c cases
		if err := json.Unmarshal(data, &c); err != nil {
			t.Fatal(err)
		}
		return c
	}
	t.Fatal("sdk/rasp/testdata/masking.json not found")
	return cases{}
}

func TestContract(t *testing.T) {
	c := load(t)
	if len(c.Text) == 0 || len(c.Keys) == 0 || len(c.Values) == 0 {
		t.Fatal("masking.json is empty")
	}
	for _, tc := range c.Text {
		if got := Secrets(tc.In); got != tc.Out {
			t.Errorf("text %q: Secrets(%q) = %q, want %q", tc.Name, tc.In, got, tc.Out)
		}
	}
	for _, tc := range c.Limited {
		if got := Text(tc.In, tc.Limit); got != tc.Out {
			t.Errorf("limited %q: got %q, want %q", tc.Name, got, tc.Out)
		}
	}
	for _, tc := range c.Keys {
		if got := IsSensitiveKey(tc.Key); got != tc.Sensitive {
			t.Errorf("key %q: sensitive = %v, want %v", tc.Key, got, tc.Sensitive)
		}
	}
	for _, tc := range c.Values {
		if got := Value(tc.Key, tc.Value, 4096); !reflect.DeepEqual(got, tc.Out) {
			t.Errorf("value %q: got %#v, want %#v", tc.Key, got, tc.Out)
		}
	}
	for _, tc := range c.Snippets {
		if got := Text(tc.In, 64); got != tc.Out {
			t.Errorf("snippet %q: got %q, want %q", tc.In, got, tc.Out)
		}
	}
}
