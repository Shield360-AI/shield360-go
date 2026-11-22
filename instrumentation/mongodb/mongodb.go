// Package mongodb traces MongoDB Go driver v2 (go.mongodb.org/mongo-driver/v2)
// commands inside the request trace.
//
//	client, err := mongo.Connect(options.Client().ApplyURI(uri).SetMonitor(mongodb.Monitor()))
//
// Each command is one CLIENT span named "find shop.users" with
// db.system.name=mongodb, db.operation.name, db.namespace, db.collection.name,
// server.address and server.port.
//
// SHIELD: data minimisation. The command document (filters, updates,
// inserted documents) is never recorded, and neither is a failure's message,
// which can quote a duplicate key's value: a failed command has error.type
// and an error status only. Handshake and authentication commands are not
// traced. Call shield360.Init first so the spans are exported.
//
// For driver v1, use go.opentelemetry.io/contrib/instrumentation/go.mongodb.org/mongo-driver/mongo/otelmongo,
// which keeps the command out by default too.
package mongodb

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"

	"go.mongodb.org/mongo-driver/v2/event"
	"go.mongodb.org/mongo-driver/v2/x/mongo/driver"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"
)

const scope = "github.com/Shield360-AI/shield360-go/instrumentation/mongodb"

// Commands that are connection plumbing, not the app's work.
var skipped = map[string]bool{
	"hello": true, "ismaster": true, "saslstart": true, "saslcontinue": true,
	"getnonce": true, "authenticate": true, "endsessions": true, "buildinfo": true,
}

type key struct {
	conn string
	id   int64
}

type monitor struct {
	tracer trace.Tracer
	mu     sync.Mutex
	spans  map[key]trace.Span
}

// Option configures Monitor.
type Option func(*monitor)

// WithTracerProvider uses tp instead of the global tracer provider.
func WithTracerProvider(tp trace.TracerProvider) Option {
	return func(m *monitor) { m.tracer = tp.Tracer(scope) }
}

// Monitor returns a command monitor for options.Client().SetMonitor.
func Monitor(opts ...Option) *event.CommandMonitor {
	m := &monitor{tracer: otel.Tracer(scope), spans: map[key]trace.Span{}}
	for _, o := range opts {
		o(m)
	}
	return &event.CommandMonitor{Started: m.started, Succeeded: m.succeeded, Failed: m.failed}
}

func (m *monitor) started(ctx context.Context, e *event.CommandStartedEvent) {
	if skipped[strings.ToLower(e.CommandName)] {
		return
	}
	collection := collectionOf(e)
	name := e.CommandName
	if e.DatabaseName != "" {
		target := e.DatabaseName
		if collection != "" {
			target += "." + collection
		}
		name += " " + target
	}
	attrs := []attribute.KeyValue{
		attribute.String("db.system.name", "mongodb"),
		attribute.String("db.operation.name", e.CommandName),
	}
	if e.DatabaseName != "" {
		attrs = append(attrs, attribute.String("db.namespace", e.DatabaseName))
	}
	if collection != "" {
		attrs = append(attrs, attribute.String("db.collection.name", collection))
	}
	if host, port, ok := serverOf(e.ConnectionID); ok {
		attrs = append(attrs, attribute.String("server.address", host))
		if port > 0 {
			attrs = append(attrs, attribute.Int("server.port", port))
		}
	}
	_, span := m.tracer.Start(ctx, name, trace.WithSpanKind(trace.SpanKindClient), trace.WithAttributes(attrs...))
	m.mu.Lock()
	m.spans[key{e.ConnectionID, e.RequestID}] = span
	m.mu.Unlock()
}

func (m *monitor) take(conn string, id int64) trace.Span {
	m.mu.Lock()
	defer m.mu.Unlock()
	k := key{conn, id}
	span := m.spans[k]
	delete(m.spans, k)
	return span
}

func (m *monitor) succeeded(_ context.Context, e *event.CommandSucceededEvent) {
	if span := m.take(e.ConnectionID, e.RequestID); span != nil {
		span.End()
	}
}

func (m *monitor) failed(_ context.Context, e *event.CommandFailedEvent) {
	span := m.take(e.ConnectionID, e.RequestID)
	if span == nil {
		return
	}
	span.SetAttributes(attribute.String("error.type", errorType(e.Failure)))
	span.SetStatus(codes.Error, "")
	span.End()
}

// collectionOf is the collection a command names: the string value of its
// first element ({"find": "users", ...}). Only that name is read.
func collectionOf(e *event.CommandStartedEvent) string {
	if len(e.Command) == 0 {
		return ""
	}
	v, err := e.Command.LookupErr(e.CommandName)
	if err != nil {
		return ""
	}
	if s, ok := v.StringValueOK(); ok {
		return s
	}
	return ""
}

// serverOf reads host and port from a driver connection id ("host:port[-n]").
func serverOf(connID string) (string, int, bool) {
	if i := strings.LastIndex(connID, "["); i > 0 {
		connID = connID[:i]
	}
	if i := strings.LastIndex(connID, "-"); i > 0 && strings.Contains(connID[:i], ":") {
		if _, err := strconv.Atoi(connID[i+1:]); err == nil {
			connID = connID[:i]
		}
	}
	host, portStr, err := net.SplitHostPort(connID)
	if err != nil || host == "" {
		return "", 0, false
	}
	port, _ := strconv.Atoi(portStr)
	return host, port, true
}

// errorType names the failure without its message, which can quote values:
// the server's error name ("NotWritablePrimary") or code, else the Go type.
func errorType(err error) string {
	if err == nil {
		return "_OTHER"
	}
	var de driver.Error
	if errors.As(err, &de) {
		if de.Name != "" {
			return de.Name
		}
		if de.Code != 0 {
			return strconv.Itoa(int(de.Code))
		}
	}
	return fmt.Sprintf("%T", err)
}
