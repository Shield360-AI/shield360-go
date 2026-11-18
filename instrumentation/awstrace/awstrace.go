// Package awstrace traces AWS SDK for Go v2 (github.com/aws/aws-sdk-go-v2)
// calls inside the request trace.
//
//	cfg, err := config.LoadDefaultConfig(ctx)
//	awstrace.Instrument(&cfg)
//	s3Client := s3.NewFromConfig(cfg)
//
// Each call is one CLIENT span named "Service.Operation" ("SQS.SendMessage")
// with the OpenTelemetry RPC conventions (rpc.system.name=aws-api,
// rpc.method="SQS/SendMessage"), aws.region and the request id. DynamoDB
// calls add table and index names; SQS and SNS calls add the queue or topic. Request and response bodies, item values and message
// bodies are never recorded. Call shield360.Init first so the spans are exported.
package awstrace

import (
	"github.com/aws/aws-sdk-go-v2/aws"
	"go.opentelemetry.io/contrib/instrumentation/github.com/aws/aws-sdk-go-v2/otelaws"
)

// Instrument adds tracing to every client built from cfg after this call.
// Options are passed on to otelaws.
func Instrument(cfg *aws.Config, opts ...otelaws.Option) {
	if cfg == nil {
		return
	}
	otelaws.AppendMiddlewares(&cfg.APIOptions, opts...)
}
