package mongodb

import (
	"context"
	"errors"
	"strconv"
	"testing"

	"github.com/ThinkfleetAI/shield360-go/instrumentation/internal/spantest"
	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/event"
	"go.mongodb.org/mongo-driver/v2/x/mongo/driver"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"
)

func command(t *testing.T, d bson.D) bson.Raw {
	t.Helper()
	raw, err := bson.Marshal(d)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestCommandsAreTracedWithoutTheirDocument(t *testing.T) {
	rec := spantest.Recorder(t)
	m := Monitor()
	ctx := context.Background()
	conn := "db.internal:27017[-3]"

	m.Started(ctx, &event.CommandStartedEvent{
		Command:      command(t, bson.D{{Key: "find", Value: "users"}, {Key: "filter", Value: bson.D{{Key: "email", Value: "ada@example.com"}}}}),
		DatabaseName: "shop", CommandName: "find", RequestID: 1, ConnectionID: conn,
	})
	m.Succeeded(ctx, &event.CommandSucceededEvent{CommandFinishedEvent: event.CommandFinishedEvent{CommandName: "find", RequestID: 1, ConnectionID: conn}})

	m.Started(ctx, &event.CommandStartedEvent{
		Command:      command(t, bson.D{{Key: "insert", Value: "users"}, {Key: "documents", Value: bson.A{bson.D{{Key: "email", Value: "ada@example.com"}}}}}),
		DatabaseName: "shop", CommandName: "insert", RequestID: 2, ConnectionID: conn,
	})
	m.Failed(ctx, &event.CommandFailedEvent{
		CommandFinishedEvent: event.CommandFinishedEvent{CommandName: "insert", RequestID: 2, ConnectionID: conn},
		Failure:              driver.Error{Code: 10107, Name: "NotWritablePrimary", Message: "not primary for ada@example.com"},
	})

	// Handshake and auth commands are plumbing.
	m.Started(ctx, &event.CommandStartedEvent{Command: command(t, bson.D{{Key: "hello", Value: 1}}), DatabaseName: "admin", CommandName: "hello", RequestID: 3, ConnectionID: conn})
	m.Succeeded(ctx, &event.CommandSucceededEvent{CommandFinishedEvent: event.CommandFinishedEvent{CommandName: "hello", RequestID: 3, ConnectionID: conn}})

	spans := rec.Ended()
	if len(spans) != 2 {
		t.Fatalf("got %d spans, want 2", len(spans))
	}
	find, insert := spans[0], spans[1]
	if find.Name() != "find shop.users" || find.SpanKind() != trace.SpanKindClient {
		t.Errorf("find span: %q %v", find.Name(), find.SpanKind())
	}
	a := spantest.Attrs(find)
	for k, want := range map[string]string{
		"db.system.name": "mongodb", "db.operation.name": "find", "db.namespace": "shop",
		"db.collection.name": "users", "server.address": "db.internal",
	} {
		if got := a[attribute.Key(k)].AsString(); got != want {
			t.Errorf("%s = %q, want %q", k, got, want)
		}
	}
	if a["server.port"].AsInt64() != 27017 {
		t.Errorf("server.port = %v", a["server.port"])
	}
	if insert.Status().Code != codes.Error || spantest.Attrs(insert)["error.type"].AsString() != "NotWritablePrimary" {
		t.Errorf("insert failure: %v %v", insert.Status(), spantest.Attrs(insert)["error.type"])
	}
	spantest.NoValue(t, spans, "ada@example.com", "not primary")
}

func TestServerAddressFromConnectionID(t *testing.T) {
	for id, want := range map[string]string{
		"localhost:27017[-12]": "localhost:27017",
		"10.0.0.5:27018-4":     "10.0.0.5:27018",
		"[::1]:27017[-1]":      "::1:27017",
	} {
		host, port, ok := serverOf(id)
		if !ok || host+":"+strconv.Itoa(port) != want {
			t.Errorf("serverOf(%q) = %q %d %v, want %q", id, host, port, ok, want)
		}
	}
	if _, _, ok := serverOf("not an address"); ok {
		t.Error("parsed a malformed id")
	}
}

func TestErrorTypeNeverUsesTheMessage(t *testing.T) {
	if got := errorType(driver.Error{Code: 11000, Message: "dup key: ada"}); got != "11000" {
		t.Errorf("code only: %q", got)
	}
	if got := errorType(errors.New("value ada")); got != "*errors.errorString" {
		t.Errorf("plain error: %q", got)
	}
}
