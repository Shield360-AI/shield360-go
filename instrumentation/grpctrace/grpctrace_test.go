package grpctrace

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/Shield360-AI/shield360-go/instrumentation/internal/spantest"
	"go.opentelemetry.io/otel/trace"
	"google.golang.org/grpc"
	grpccodes "google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/health"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
)

func TestCallsAreTracedAndHealthChecksLeftOut(t *testing.T) {
	rec := spantest.Recorder(t)
	lis := bufconn.Listen(1 << 20)
	srv := grpc.NewServer(ServerOption())
	healthpb.RegisterHealthServer(srv, health.NewServer())
	srv.RegisterService(&grpc.ServiceDesc{
		ServiceName: "orders.Orders",
		HandlerType: (*any)(nil),
		Methods: []grpc.MethodDesc{{
			MethodName: "Get",
			Handler: func(_ any, _ context.Context, dec func(any) error, _ grpc.UnaryServerInterceptor) (any, error) {
				if err := dec(new(healthpb.HealthCheckRequest)); err != nil {
					return nil, err
				}
				return nil, status.Error(grpccodes.NotFound, "no order")
			},
		}},
	}, struct{}{})
	go func() { _ = srv.Serve(lis) }()
	defer srv.Stop()

	conn, err := grpc.NewClient("passthrough:///bufnet",
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) { return lis.DialContext(ctx) }),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		DialOption(),
	)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if _, err := healthpb.NewHealthClient(conn).Check(ctx, &healthpb.HealthCheckRequest{}); err != nil {
		t.Fatal(err)
	}
	// The order is not found: the call fails and is still traced.
	_ = conn.Invoke(ctx, "/orders.Orders/Get", &healthpb.HealthCheckRequest{Service: "ada@example.com"}, &healthpb.HealthCheckResponse{})

	srv.GracefulStop()
	spans := rec.Ended()
	kinds := map[trace.SpanKind]bool{}
	for _, s := range spans {
		if s.Name() == "grpc.health.v1.Health/Check" {
			t.Errorf("health check traced (%v)", s.SpanKind())
		}
		if s.Name() != "orders.Orders/Get" {
			continue
		}
		kinds[s.SpanKind()] = true
		a := spantest.Attrs(s)
		if a["rpc.system.name"].AsString() != "grpc" || a["rpc.method"].AsString() != "orders.Orders/Get" {
			t.Errorf("rpc attributes: %v", a)
		}
		if a["rpc.response.status_code"].AsString() != "NOT_FOUND" {
			t.Errorf("rpc.response.status_code = %v, want NOT_FOUND", a["rpc.response.status_code"])
		}
		if len(s.Events()) != 0 {
			t.Errorf("message events recorded: %v", s.Events())
		}
	}
	if !kinds[trace.SpanKindClient] || !kinds[trace.SpanKindServer] {
		t.Errorf("want client and server spans, got %v of %d spans", kinds, len(spans))
	}
	spantest.NoValue(t, spans, "ada@example.com")
}
