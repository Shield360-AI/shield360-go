package defend

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// Client-type rule matching (sdk/rasp/testdata/ai-attack-agents.json,
// clientTypeRules): scanner and ai_attack_agent are subtypes of
// unverified_automation, so existing rules keep matching attack tools.
func TestClientTypeRulesConformance(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "rasp", "testdata", "shared", "testdata", "ai-attack-agents.json"))
	if err != nil {
		t.Fatal(err)
	}
	var v struct {
		ClientTypeRules []struct {
			Rule       []string `json:"rule"`
			ClientType *string  `json:"clientType"`
			Match      bool     `json:"match"`
		} `json:"clientTypeRules"`
	}
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	if len(v.ClientTypeRules) == 0 {
		t.Fatal("no cases")
	}
	for _, c := range v.ClientTypeRules {
		ct := ""
		if c.ClientType != nil {
			ct = *c.ClientType
		}
		if got := ClientTypeMatches(c.Rule, ct); got != c.Match {
			t.Errorf("rule %v covers %q: %v, want %v", c.Rule, ct, got, c.Match)
		}
	}
}
