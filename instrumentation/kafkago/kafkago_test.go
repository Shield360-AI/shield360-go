package kafkago

import (
	"context"
	"errors"
	"testing"

	"github.com/ThinkfleetAI/shield360-go/instrumentation/internal/spantest"
	"github.com/segmentio/kafka-go"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"
)

type fakeWriter struct {
	got []kafka.Message
	err error
}

func (w *fakeWriter) WriteMessages(_ context.Context, msgs ...kafka.Message) error {
	w.got = append(w.got, msgs...)
	return w.err
}

func TestTraceCrossesKafkaWithoutKeysOrValues(t *testing.T) {
	rec := spantest.Recorder(t)
	w := &fakeWriter{}
	in := []kafka.Message{
		{Topic: "orders", Key: []byte("ada@example.com"), Value: []byte("card 4111"), Headers: []kafka.Header{{Key: "app", Value: []byte("1")}}},
		{Topic: "orders", Value: []byte("card 4222")},
	}
	if err := WriteMessages(context.Background(), w, in...); err != nil {
		t.Fatal(err)
	}
	if len(in[0].Headers) != 1 || len(in[1].Headers) != 0 {
		t.Error("the caller's messages were modified")
	}
	if len(w.got) != 2 {
		t.Fatalf("wrote %d messages", len(w.got))
	}
	for _, m := range w.got {
		c := headerCarrier(m.Headers)
		if c.Get("traceparent") == "" {
			t.Errorf("no traceparent header: %v", m.Headers)
		}
	}

	// The consumer reads the first message and continues the producer's trace.
	read := w.got[0]
	read.Partition, read.Offset = 3, 42
	_, span := StartProcess(context.Background(), read, "billing")
	span.End()

	spans := rec.Ended()
	if len(spans) != 2 {
		t.Fatalf("got %d spans, want 2", len(spans))
	}
	send, process := spans[0], spans[1]
	if send.Name() != "send orders" || send.SpanKind() != trace.SpanKindProducer {
		t.Errorf("send span: %q %v", send.Name(), send.SpanKind())
	}
	sa := spantest.Attrs(send)
	if sa["messaging.system"].AsString() != "kafka" || sa["messaging.destination.name"].AsString() != "orders" || sa["messaging.batch.message_count"].AsInt64() != 2 {
		t.Errorf("send attributes: %v", sa)
	}
	if process.Name() != "process orders" || process.SpanKind() != trace.SpanKindConsumer {
		t.Errorf("process span: %q %v", process.Name(), process.SpanKind())
	}
	if process.Parent().SpanID() != send.SpanContext().SpanID() || process.SpanContext().TraceID() != send.SpanContext().TraceID() {
		t.Error("process span does not continue the send span's trace")
	}
	if len(process.Links()) != 1 || process.Links()[0].SpanContext.SpanID() != send.SpanContext().SpanID() {
		t.Error("process span has no link to the send span")
	}
	pa := spantest.Attrs(process)
	if pa["messaging.destination.partition.id"].AsString() != "3" || pa["messaging.kafka.offset"].AsInt64() != 42 || pa["messaging.consumer.group.name"].AsString() != "billing" {
		t.Errorf("process attributes: %v", pa)
	}
	for _, s := range spans {
		if _, ok := spantest.Attrs(s)["messaging.kafka.message.key"]; ok {
			t.Errorf("%s records the message key", s.Name())
		}
	}
	spantest.NoValue(t, spans, "ada@example.com", "4111", "4222")
}

func TestAFailedWriteIsAnError(t *testing.T) {
	rec := spantest.Recorder(t)
	w := &fakeWriter{err: kafka.MessageSizeTooLarge}
	if err := WriteMessages(context.Background(), w, kafka.Message{Topic: "orders"}); !errors.Is(err, kafka.MessageSizeTooLarge) {
		t.Fatalf("err = %v", err)
	}
	s := rec.Ended()[0]
	if s.Status().Code != codes.Error || spantest.Attrs(s)["error.type"].AsString() != kafka.MessageSizeTooLarge.Title() {
		t.Errorf("status %v, error.type %v", s.Status(), spantest.Attrs(s)["error.type"])
	}
	if _, ok := spantest.Attrs(s)["messaging.batch.message_count"]; ok {
		t.Error("batch count on a single message")
	}
}

func TestMixedTopicsHaveNoDestination(t *testing.T) {
	rec := spantest.Recorder(t)
	_ = WriteMessages(context.Background(), &fakeWriter{}, kafka.Message{Topic: "a"}, kafka.Message{Topic: "b"})
	s := rec.Ended()[0]
	if s.Name() != "send" {
		t.Errorf("name %q", s.Name())
	}
	if _, ok := spantest.Attrs(s)["messaging.destination.name"]; ok {
		t.Error("destination set for mixed topics")
	}
}
