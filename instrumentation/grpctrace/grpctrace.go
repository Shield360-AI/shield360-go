// Package grpctrace traces gRPC (google.golang.org/grpc) clients and servers
// with the OpenTelemetry stats handlers, health checks left out.
//
//	conn, err := grpc.NewClient(addr, grpctrace.DialOption(), ...)
//	srv := grpc.NewServer(grpctrace.ServerOption())
//
// Spans follow the current OpenTelemetry RPC conventions (rpc.system.name=grpc,
// rpc.method="orders.Orders/Get", rpc.response.status_code). Messages are never recorded, and the
// per-message size events stay off (otelgrpc's default). Call shield360.Init
// first so the spans are exported.
package grpctrace

import (
	"go.opentelemetry.io/contrib/instrumentation/google.golang.org/grpc/otelgrpc"
	"go.opentelemetry.io/contrib/instrumentation/google.golang.org/grpc/otelgrpc/filters"
	"google.golang.org/grpc"
)

// DialOption traces each call a client connection makes. Options are passed
// on to otelgrpc after the Shield360 defaults.
func DialOption(opts ...otelgrpc.Option) grpc.DialOption {
	return grpc.WithStatsHandler(otelgrpc.NewClientHandler(append(defaults(), opts...)...))
}

// ServerOption traces each call a server handles. Options are passed on to
// otelgrpc after the Shield360 defaults.
func ServerOption(opts ...otelgrpc.Option) grpc.ServerOption {
	return grpc.StatsHandler(otelgrpc.NewServerHandler(append(defaults(), opts...)...))
}

func defaults() []otelgrpc.Option {
	return []otelgrpc.Option{
		// grpc.health.v1.Health calls arrive every few seconds from probes.
		otelgrpc.WithFilter(filters.Not(filters.HealthCheck())),
	}
}
