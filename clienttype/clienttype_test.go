package clienttype

import (
	"strings"
	"testing"
)

func TestClassify(t *testing.T) {
	browser := map[string]string{"user-agent": "Mozilla/5.0 Chrome/120.0 Safari/537.36", "accept-language": "en"}
	for _, tc := range []struct {
		headers map[string]string
		s       Signals
		want    string
		reason  string
	}{
		{browser, Signals{}, Human, ""},
		{browser, Signals{VerifiedAgent: true}, VerifiedAgent, "agent_verified"},
		{browser, Signals{Edge: &EdgeSignal{ClientType: "verified_crawler"}}, VerifiedAgent, "edge:verified_crawler"},
		{browser, Signals{TrapHit: true}, SuspectedAIAgent, "trap_hit"},
		{browser, Signals{Edge: &EdgeSignal{Trap: 2}}, SuspectedAIAgent, "edge:trap_level_2"},
		{map[string]string{"user-agent": "Claude-User/1.0"}, Signals{}, SuspectedAIAgent, "ua_ai_agent:claude-user"},
		{map[string]string{"user-agent": "GPTBot/1.0"}, Signals{}, UnverifiedAutomation, "ua_ai_crawler:gptbot"},
		{map[string]string{}, Signals{}, UnverifiedAutomation, "no_user_agent"},
		{map[string]string{}, Signals{Breadth: BreadthAgent}, SuspectedAIAgent, "breadth"},
		{map[string]string{"user-agent": "Mozilla/5.0 Chrome/120.0"}, Signals{}, UnverifiedAutomation, "browser_headers_missing"},
		{browser, Signals{Edge: &EdgeSignal{Risk: 80}}, UnverifiedAutomation, "edge:risk"},
	} {
		got := Classify(tc.headers, tc.s)
		if got.ClientType != tc.want || (tc.reason != "" && !strings.Contains(strings.Join(got.Reasons, ","), tc.reason)) {
			t.Errorf("%v %+v: %+v", tc.headers, tc.s, got)
		}
	}
	if SignaturesVersion() == "" {
		t.Fatal("signatures")
	}
}

func TestBreadthCounter(t *testing.T) {
	b := NewBreadthCounter(1000, 2)
	if b.See("a", "/x/1", 0) != 1 || b.See("a", "/y/1", 0) != 2 || b.See("a", "/y/1", 10) != 2 {
		t.Fatal("count")
	}
	if b.See("a", "/z", 2000) != 1 {
		t.Fatal("window")
	}
	b.See("b", "/", 0)
	b.See("c", "/", 0)
	if b.See("a", "/q", 2001) != 1 {
		t.Fatal("oldest dropped")
	}
}
