package tunnel

import (
	"io"
	"strings"
	"testing"

	relayv1 "github.com/JTM-rootstorm/scalevault/gen/relay/v1"
)

func TestProbeRejectsArbitraryDestination(t *testing.T) {
	request := probeRequest()
	request.Payload = &relayv1.RelayEnvelope_RequestStart{
		RequestStart: &relayv1.RequestStart{Method: "POST", Path: "/admin/status"},
	}
	stream := &scriptedProbeStream{received: []*relayv1.RelayEnvelope{
		request,
	}}

	err := ServeProbe(stream, "test-installation")
	if err == nil || !strings.Contains(err.Error(), "accepts only POST /echo") {
		t.Fatalf("expected fixed-destination rejection, got %v", err)
	}
	if len(stream.sent) != 0 {
		t.Fatalf("expected no response envelopes, got %d", len(stream.sent))
	}
}

func TestProbeRejectsOversizedChunk(t *testing.T) {
	requestStart := probeRequest()
	requestStart.Payload = &relayv1.RelayEnvelope_RequestStart{
		RequestStart: &relayv1.RequestStart{Method: "POST", Path: "/echo"},
	}
	requestBody := probeRequest()
	requestBody.Payload = &relayv1.RelayEnvelope_BodyChunk{
		BodyChunk: &relayv1.BodyChunk{Data: make([]byte, maxChunkBytes+1)},
	}
	stream := &scriptedProbeStream{received: []*relayv1.RelayEnvelope{
		requestStart,
		requestBody,
	}}

	err := ServeProbe(stream, "test-installation")
	if err == nil || !strings.Contains(err.Error(), "body chunk exceeds") {
		t.Fatalf("expected chunk-size rejection, got %v", err)
	}
	if len(stream.sent) != 1 {
		t.Fatalf("expected only response start, got %d envelopes", len(stream.sent))
	}
}

type scriptedProbeStream struct {
	received []*relayv1.RelayEnvelope
	sent     []*relayv1.NodeEnvelope
}

func (stream *scriptedProbeStream) Send(envelope *relayv1.NodeEnvelope) error {
	stream.sent = append(stream.sent, envelope)
	return nil
}

func (stream *scriptedProbeStream) Recv() (*relayv1.RelayEnvelope, error) {
	if len(stream.received) == 0 {
		return nil, io.EOF
	}
	envelope := stream.received[0]
	stream.received = stream.received[1:]
	return envelope, nil
}

func probeRequest() *relayv1.RelayEnvelope {
	return &relayv1.RelayEnvelope{
		ProtocolVersion: probeProtocolVersion,
		InstallationId:  "test-installation",
		ConnectionId:    "test-connection",
		RequestId:       "test-request",
		TraceId:         "test-trace",
	}
}
