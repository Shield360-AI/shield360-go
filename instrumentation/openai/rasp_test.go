package openai

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/ThinkfleetAI/shield360-go/rasp"
)

// SHIELD: a chat completion's text and tool-call arguments become RASP
// model_output inputs in the caller's RASP context.
func TestChatCompletionRecordsModelOutputForRasp(t *testing.T) {
	rasp.Init(&rasp.Options{}, rasp.InitContext{ApplicationName: "a", Getenv: func(string) string { return "" }})
	t.Cleanup(func() { rasp.Init(nil, rasp.InitContext{Getenv: func(string) string { return "" }}) })
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"c1","model":"gpt-4o","choices":[{"index":0,"message":{"role":"assistant","content":"first line\nsecond line",` +
			`"tool_calls":[{"id":"t1","type":"function","function":{"name":"run_query","arguments":"{\"sql\":\"select 1\"}"}}]},"finish_reason":"stop"}]}`))
	}))
	defer srv.Close()

	ctx := rasp.WithScope(context.Background())
	client := NewClient("sk-test", WithBaseURL(srv.URL))
	if _, err := client.CreateChatCompletion(ctx, ChatCompletionRequest{Model: "gpt-4o", Messages: []ChatMessage{{Role: "user", Content: "hi"}}}); err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, i := range rasp.FromContext(ctx).Inputs() {
		got = append(got, i.Key+"="+i.Value)
	}
	want := []string{"model.completion=first line", "model.completion=second line", "model.tool.run_query.sql=select 1"}
	if len(got) != len(want) {
		t.Fatalf("inputs %v", got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("%d: %s, want %s", i, got[i], want[i])
		}
	}
}
