package anthropic

import (
	"context"

	"github.com/Shield360-AI/shield360-go/rasp"
)

// recordModelOutput hands what the model returned to RASP as untrusted
// input (text blocks and tool_use input). A no-op unless RASP is on and ctx
// carries a RASP context.
func recordModelOutput(ctx context.Context, resp *MessageResponse) {
	if resp == nil || !rasp.ModelOutputRecording() {
		return
	}
	for i, b := range resp.Content {
		if i >= 64 {
			break
		}
		switch b.Type {
		case "text":
			rasp.RecordModelOutput(ctx, b.Text, "")
		case "tool_use":
			rasp.RecordToolArguments(ctx, b.Input, b.Name)
		}
	}
}
