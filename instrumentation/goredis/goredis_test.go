package goredis

import (
	"context"
	"testing"
	"time"

	"github.com/ThinkfleetAI/shield360-go/instrumentation/internal/spantest"
	"github.com/redis/go-redis/v9"
)

func TestCommandsAreTracedByNameOnly(t *testing.T) {
	rec := spantest.Recorder(t)
	// Nothing listens on port 1: the command fails fast and its span still ends.
	rdb := redis.NewClient(&redis.Options{Addr: "127.0.0.1:1", DialTimeout: 200 * time.Millisecond, MaxRetries: -1})
	defer func() { _ = rdb.Close() }()
	if err := Instrument(rdb); err != nil {
		t.Fatal(err)
	}

	_ = rdb.Set(context.Background(), "session:ada@example.com", "secret-token", 0).Err()

	spans := rec.Ended()
	var found bool
	for _, s := range spans {
		if s.Name() == "set" {
			found = true
			attrs := spantest.Attrs(s)
			if _, ok := attrs["db.statement"]; ok {
				t.Error("db.statement recorded")
			}
			if _, ok := attrs["db.query.text"]; ok {
				t.Error("db.query.text recorded")
			}
		}
	}
	if !found {
		t.Fatalf("no set span in %d spans", len(spans))
	}
	spantest.NoValue(t, spans, "ada@example.com", "secret-token")
}
