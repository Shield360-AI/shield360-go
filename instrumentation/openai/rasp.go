package openai

import (
	"context"

	"github.com/ThinkfleetAI/shield360-go/rasp"
)

// recordModelOutput hands what the model returned to RASP as untrusted
// input (completion text and tool-call arguments). A no-op unless RASP is on
// and ctx carries a RASP context.
func recordModelOutput(ctx context.Context, resp *ChatCompletionResponse) {
	if resp == nil || !rasp.ModelOutputRecording() {
		return
	}
	for i, c := range resp.Choices {
		if i >= 8 {
			break
		}
		rasp.RecordModelOutput(ctx, c.Message.Content, "")
		for k, t := range c.Message.ToolCalls {
			if k >= 32 {
				break
			}
			rasp.RecordToolArguments(ctx, t.Function.Arguments, t.Function.Name)
		}
	}
}
