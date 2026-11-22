// Package kafkago traces segmentio/kafka-go producers and consumers and
// carries the trace across Kafka in message headers.
//
//	// producer: one PRODUCER span per call, trace context in each message's headers
//	err := kafkago.WriteMessages(ctx, writer, kafka.Message{Value: body})
//
//	// consumer: one CONSUMER span per message, continuing the producer's trace
//	msg, err := reader.ReadMessage(ctx)
//	ctx, span := kafkago.StartProcess(ctx, msg, "orders-workers")
//	defer span.End()
//
// Spans follow the OpenTelemetry messaging conventions (messaging.system=kafka,
// messaging.operation.type, messaging.destination.name, partition, offset,
// consumer group).
//
// SHIELD: data minimisation. Message keys and values are never recorded.
// Call shield360.Init first so the spans are exported and the trace context
// propagator is set.
package kafkago

import (
	"context"
	"strconv"

	"github.com/segmentio/kafka-go"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/trace"
)

const scope = "github.com/Shield360-AI/shield360-go/instrumentation/kafkago"

func tracer() trace.Tracer { return otel.Tracer(scope) }

// Writer is the part of *kafka.Writer WriteMessages uses.
type Writer interface {
	WriteMessages(ctx context.Context, msgs ...kafka.Message) error
}

// WriteMessages writes msgs with w inside one PRODUCER span ("send orders"),
// with the span's trace context added to each message's headers. The caller's
// messages are not modified. Topic is w's Topic when w is a *kafka.Writer
// with one set, else the messages' own Topic.
func WriteMessages(ctx context.Context, w Writer, msgs ...kafka.Message) error {
	topic := ""
	if kw, ok := w.(*kafka.Writer); ok && kw != nil {
		topic = kw.Topic
	}
	if topic == "" {
		topic = commonTopic(msgs)
	}
	name := "send"
	if topic != "" {
		name += " " + topic
	}
	attrs := []attribute.KeyValue{
		attribute.String("messaging.system", "kafka"),
		attribute.String("messaging.operation.type", "send"),
		attribute.String("messaging.operation.name", "send"),
	}
	if topic != "" {
		attrs = append(attrs, attribute.String("messaging.destination.name", topic))
	}
	if len(msgs) > 1 {
		attrs = append(attrs, attribute.Int("messaging.batch.message_count", len(msgs)))
	}
	ctx, span := tracer().Start(ctx, name, trace.WithSpanKind(trace.SpanKindProducer), trace.WithAttributes(attrs...))
	defer span.End()

	out := make([]kafka.Message, len(msgs))
	prop := otel.GetTextMapPropagator()
	for i, m := range msgs {
		m.Headers = append([]kafka.Header(nil), m.Headers...)
		prop.Inject(ctx, (*headerCarrier)(&m.Headers))
		out[i] = m
	}
	err := w.WriteMessages(ctx, out...)
	if err != nil {
		span.SetAttributes(attribute.String("error.type", errorType(err)))
		span.SetStatus(codes.Error, "")
	}
	return err
}

// StartProcess starts a CONSUMER span ("process orders") for a message read
// from Kafka, continuing the trace from its headers. group is the consumer
// group ("" when none). End the span when the message is handled.
func StartProcess(ctx context.Context, msg kafka.Message, group string) (context.Context, trace.Span) {
	headers := msg.Headers
	parent := otel.GetTextMapPropagator().Extract(ctx, (*headerCarrier)(&headers))
	attrs := []attribute.KeyValue{
		attribute.String("messaging.system", "kafka"),
		attribute.String("messaging.operation.type", "process"),
		attribute.String("messaging.operation.name", "process"),
		attribute.String("messaging.destination.partition.id", strconv.Itoa(msg.Partition)),
		attribute.Int64("messaging.kafka.offset", msg.Offset),
	}
	name := "process"
	if msg.Topic != "" {
		name += " " + msg.Topic
		attrs = append(attrs, attribute.String("messaging.destination.name", msg.Topic))
	}
	if group != "" {
		attrs = append(attrs, attribute.String("messaging.consumer.group.name", group))
	}
	opts := []trace.SpanStartOption{trace.WithSpanKind(trace.SpanKindConsumer), trace.WithAttributes(attrs...)}
	// The producer's span is a link as well as the parent, as the conventions ask.
	if sc := trace.SpanContextFromContext(parent); sc.IsValid() {
		opts = append(opts, trace.WithLinks(trace.Link{SpanContext: sc}))
	}
	return tracer().Start(parent, name, opts...)
}

func commonTopic(msgs []kafka.Message) string {
	topic := ""
	for i, m := range msgs {
		if i == 0 {
			topic = m.Topic
		} else if m.Topic != topic {
			return ""
		}
	}
	return topic
}

// errorType names a write failure by its Kafka error code name, else "_OTHER".
func errorType(err error) string {
	if ke, ok := err.(kafka.Error); ok {
		return ke.Title()
	}
	return "_OTHER"
}

// headerCarrier lets the propagator read and write kafka-go headers.
type headerCarrier []kafka.Header

var _ propagation.TextMapCarrier = (*headerCarrier)(nil)

func (c *headerCarrier) Get(key string) string {
	for _, h := range *c {
		if h.Key == key {
			return string(h.Value)
		}
	}
	return ""
}

func (c *headerCarrier) Set(key, value string) {
	for i, h := range *c {
		if h.Key == key {
			(*c)[i].Value = []byte(value)
			return
		}
	}
	*c = append(*c, kafka.Header{Key: key, Value: []byte(value)})
}

func (c *headerCarrier) Keys() []string {
	keys := make([]string, 0, len(*c))
	for _, h := range *c {
		keys = append(keys, h.Key)
	}
	return keys
}
