package awstrace

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Shield360-AI/shield360-go/instrumentation/internal/spantest"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sqs"
)

func TestCallsAreTracedWithoutTheirBody(t *testing.T) {
	rec := spantest.Recorder(t)
	var body string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		body = string(b)
		w.Header().Set("Content-Type", "application/x-amz-json-1.0")
		w.Header().Set("x-amzn-RequestId", "req-1")
		_, _ = io.WriteString(w, `{"MessageId":"m-1","MD5OfMessageBody":"x"}`)
	}))
	defer srv.Close()

	cfg := aws.Config{Region: "us-east-1", Credentials: aws.AnonymousCredentials{}, BaseEndpoint: aws.String(srv.URL)}
	Instrument(&cfg)
	Instrument(nil)
	client := sqs.NewFromConfig(cfg)
	_, _ = client.SendMessage(context.Background(), &sqs.SendMessageInput{
		QueueUrl:    aws.String(srv.URL + "/123/orders"),
		MessageBody: aws.String("card for ada@example.com"),
	})
	if body == "" {
		t.Fatal("the fake SQS endpoint was not called")
	}

	spans := rec.Ended()
	var found bool
	for _, s := range spans {
		if s.Name() != "SQS.SendMessage" {
			continue
		}
		found = true
		a := spantest.Attrs(s)
		if a["rpc.system.name"].AsString() != "aws-api" || a["rpc.method"].AsString() != "SQS/SendMessage" || a["messaging.system"].AsString() != "aws_sqs" {
			t.Errorf("rpc attributes: %v", a)
		}
	}
	if !found {
		t.Fatalf("no SQS.SendMessage span in %d spans", len(spans))
	}
	spantest.NoValue(t, spans, "ada@example.com")
}
