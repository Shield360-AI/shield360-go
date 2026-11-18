// Package spantest records spans for the instrumentation tests.
package spantest

import (
	"strings"
	"testing"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/propagation"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
)

// Recorder sets a global tracer provider that records every span, and the
// W3C trace context propagator, until the test ends.
func Recorder(t *testing.T) *tracetest.SpanRecorder {
	t.Helper()
	rec := tracetest.NewSpanRecorder()
	prevTP, prevProp := otel.GetTracerProvider(), otel.GetTextMapPropagator()
	otel.SetTracerProvider(sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(rec)))
	otel.SetTextMapPropagator(propagation.TraceContext{})
	t.Cleanup(func() {
		otel.SetTracerProvider(prevTP)
		otel.SetTextMapPropagator(prevProp)
	})
	return rec
}

// Attrs maps a span's attributes by key.
func Attrs(s sdktrace.ReadOnlySpan) map[attribute.Key]attribute.Value {
	m := map[attribute.Key]attribute.Value{}
	for _, kv := range s.Attributes() {
		m[kv.Key] = kv.Value
	}
	return m
}

// NoValue fails the test when any attribute, event or status of any span
// contains one of the values.
func NoValue(t *testing.T, spans []sdktrace.ReadOnlySpan, values ...string) {
	t.Helper()
	for _, s := range spans {
		texts := []string{s.Name(), s.Status().Description}
		for _, kv := range s.Attributes() {
			texts = append(texts, kv.Value.Emit())
		}
		for _, e := range s.Events() {
			texts = append(texts, e.Name)
			for _, kv := range e.Attributes {
				texts = append(texts, kv.Value.Emit())
			}
		}
		for _, text := range texts {
			for _, v := range values {
				if strings.Contains(text, v) {
					t.Errorf("span %q records %q: %q", s.Name(), v, text)
				}
			}
		}
	}
}
