package rasp

import (
	"reflect"
	"testing"
)

// README "Collector contexts": the same language with another set of fields,
// for the collector's coding-agent hooks and the AI proxy.

func sp(s string) *string { return &s }

func TestCollectorContextFields(t *testing.T) {
	if got := RuleContextFields(ContextAgentTool); !reflect.DeepEqual(got, []string{"agent.name", "device.os", "tool.command", "tool.name", "tool.path", "user.id"}) {
		t.Fatalf("agent_tool fields = %v", got)
	}
	if got := RuleContextFields(ContextAIProxy); !reflect.DeepEqual(got, []string{"ai.model", "ai.provider", "ai.tokens", "device.os", "user.id"}) {
		t.Fatalf("ai_proxy fields = %v", got)
	}
	if RuleContextFields("nope") != nil {
		t.Fatal("an unknown context has no fields")
	}
	if len(RuleContextFields(ContextApp)) != len(ruleFields) {
		t.Fatal("the app context keeps the app fields")
	}
}

func TestCollectorContextCompile(t *testing.T) {
	cases := []struct {
		ctx  RuleContext
		src  string
		code string
	}{
		{ContextAgentTool, `tool.name == "Bash" && tool.command.contains("kubectl delete")`, ""},
		{ContextAgentTool, `agent.name in ["cursor", "codex"] && device.os == "linux"`, ""},
		{ContextAgentTool, `tool.path.matches("^/etc/")`, ""},
		{ContextAgentTool, `user.id.endsWith("@contractor.example")`, ""},
		{ContextAIProxy, `ai.provider == "openai" && ai.model.startsWith("gpt-4")`, ""},
		{ContextAIProxy, `ai.tokens.matches("^[0-9]{6,}$")`, ""},
		// Fields belong to their own context only.
		{ContextAgentTool, `ai.model == "x"`, "unknown_field"},
		{ContextAIProxy, `tool.name == "Bash"`, "unknown_field"},
		{ContextAgentTool, `request.path == "/"`, "unknown_field"},
		{ContextApp, `tool.name == "Bash"`, "unknown_field"},
		// Collector fields are strings, never maps.
		{ContextAgentTool, `tool.name["x"] == "y"`, "type"},
		// The rest of the language is unchanged.
		{ContextAIProxy, `ai.model`, "type"},
		{ContextAIProxy, `ai.model.nope("x")`, "unknown_method"},
		{ContextAgentTool, `tool.name == "Bash" &&`, "syntax"},
		{"elsewhere", `user.id == "x"`, "context"},
	}
	for _, c := range cases {
		e, err := CompileRuleExprIn(c.src, c.ctx)
		code := ""
		if err != nil {
			code = err.Code
		}
		if code != c.code {
			t.Errorf("%s %q: code %q, want %q", c.ctx, c.src, code, c.code)
		}
		if err == nil && (e.Phase != PhaseRequest || e.Context != c.ctx || e.UsesInput) {
			t.Errorf("%q: phase %s context %s", c.src, e.Phase, e.Context)
		}
	}
	// The app context is what CompileRuleExpr always was.
	if _, err := CompileRuleExpr(`request.path == "/"`); err != nil {
		t.Fatal(err)
	}
}

func TestCollectorContextEvaluate(t *testing.T) {
	expr, err := CompileRuleExprIn(`tool.name == "Bash" && tool.command.contains("terraform destroy") && !user.id.endsWith("@ops.example")`, ContextAgentTool)
	if err != nil {
		t.Fatal(err)
	}
	subject := &RuleSubject{Collector: &RuleCollector{ToolName: sp("Bash"), ToolCommand: sp("cd infra && terraform destroy -auto-approve"), UserID: sp("dev@example.com")}}
	if !EvaluateRuleExpr(expr, subject, nil).Matched {
		t.Fatal("expected a match")
	}
	subject.Collector.UserID = sp("sre@ops.example")
	if EvaluateRuleExpr(expr, subject, nil).Matched {
		t.Fatal("the ops team is excluded")
	}
	// Missing fields are null: a null comparison is false, and a nil
	// collector subject matches nothing that needs a field.
	if EvaluateRuleExpr(expr, &RuleSubject{}, nil).Matched {
		t.Fatal("no subject, no match")
	}
	nullCheck, _ := CompileRuleExprIn(`tool.path == null`, ContextAgentTool)
	if !EvaluateRuleExpr(nullCheck, &RuleSubject{Collector: &RuleCollector{ToolName: sp("Bash")}}, nil).Matched {
		t.Fatal("an absent path reads as null")
	}

	proxy, err := CompileRuleExprIn(`ai.provider == "anthropic" && ai.tokens.matches("^[0-9]{6,}$")`, ContextAIProxy)
	if err != nil {
		t.Fatal(err)
	}
	big := &RuleSubject{Collector: &RuleCollector{AIProvider: sp("anthropic"), AITokens: sp("250000")}}
	small := &RuleSubject{Collector: &RuleCollector{AIProvider: sp("anthropic"), AITokens: sp("90000")}}
	if !EvaluateRuleExpr(proxy, big, nil).Matched || EvaluateRuleExpr(proxy, small, nil).Matched {
		t.Fatal("token threshold by digit count")
	}
	// An app subject never satisfies a collector field.
	app, _ := CompileRuleExprIn(`device.os == "darwin"`, ContextAIProxy)
	if EvaluateRuleExpr(app, &RuleSubject{App: sp("darwin")}, nil).Matched {
		t.Fatal("app fields are not collector fields")
	}
}
