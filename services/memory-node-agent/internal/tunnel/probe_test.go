package tunnel

import (
	"io"
	"strings"
	"testing"
	"time"

	relayv1 "github.com/JTM-rootstorm/scalevault/gen/relay/v1"
)

func TestProbeRejectsArbitraryDestination(t *testing.T) {
	request := probeRequest()
	request.Payload = &relayv1.RelayEnvelope_RequestStart{
		RequestStart: &relayv1.RequestStart{Method: "POST", Path: "/admin/status"},
	}
	stream := &scriptedProbeStream{received: []*relayv1.RelayEnvelope{
		validRelayHello(),
		request,
	}}

	err := ServeProbe(stream, "01890a5d-ac96-7b10-8000-000000000001")
	if err == nil || !strings.Contains(err.Error(), "accepts only POST /relay/mcp") {
		t.Fatalf("expected fixed-destination rejection, got %v", err)
	}
	if len(stream.sent) != 1 || stream.sent[0].GetNodeHello() == nil {
		t.Fatalf("expected only node hello, got %d envelopes", len(stream.sent))
	}
}

func TestProbeRejectsOversizedChunk(t *testing.T) {
	requestStart := probeRequest()
	requestStart.Payload = &relayv1.RelayEnvelope_RequestStart{
		RequestStart: &relayv1.RequestStart{
			Method:             probeMethod,
			Path:               probePath,
			DeadlineUnixMillis: time.Now().Add(5 * time.Second).UnixMilli(),
		},
	}
	requestBody := probeRequest()
	requestBody.Payload = &relayv1.RelayEnvelope_BodyChunk{
		BodyChunk: &relayv1.BodyChunk{Data: make([]byte, maxChunkBytes+1), Sequence: 1},
	}
	stream := &scriptedProbeStream{received: []*relayv1.RelayEnvelope{
		validRelayHello(),
		requestStart,
		requestBody,
	}}

	err := ServeProbe(stream, "01890a5d-ac96-7b10-8000-000000000001")
	if err == nil || !strings.Contains(err.Error(), "body chunk exceeds") {
		t.Fatalf("expected chunk-size rejection, got %v", err)
	}
	if len(stream.sent) != 2 {
		t.Fatalf("expected node hello and response start, got %d envelopes", len(stream.sent))
	}
}

func TestProbeRejectsRequestBeforeRelayHello(t *testing.T) {
	stream := &scriptedProbeStream{received: []*relayv1.RelayEnvelope{probeRequest()}}

	err := ServeProbe(stream, "01890a5d-ac96-7b10-8000-000000000001")
	if err == nil || !strings.Contains(err.Error(), "relay hello must precede requests") {
		t.Fatalf("expected missing relay hello rejection, got %v", err)
	}
	if len(stream.sent) != 1 || stream.sent[0].GetNodeHello() == nil {
		t.Fatalf("expected node hello before rejection, got %d envelopes", len(stream.sent))
	}
}

func TestProbeRejectsUnsequencedBodyChunk(t *testing.T) {
	requestStart := probeRequest()
	requestStart.Payload = &relayv1.RelayEnvelope_RequestStart{
		RequestStart: &relayv1.RequestStart{
			Method:             probeMethod,
			Path:               probePath,
			DeadlineUnixMillis: time.Now().Add(5 * time.Second).UnixMilli(),
		},
	}
	requestBody := probeRequest()
	requestBody.Payload = &relayv1.RelayEnvelope_BodyChunk{
		BodyChunk: &relayv1.BodyChunk{Data: []byte("out of order"), Sequence: 2},
	}
	stream := &scriptedProbeStream{received: []*relayv1.RelayEnvelope{
		validRelayHello(),
		requestStart,
		requestBody,
	}}

	err := ServeProbe(stream, "01890a5d-ac96-7b10-8000-000000000001")
	if err == nil || !strings.Contains(err.Error(), "body chunk sequence mismatch") {
		t.Fatalf("expected sequence rejection, got %v", err)
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
		InstallationId:  "01890a5d-ac96-7b10-8000-000000000001",
		ConnectionId:    probeConnectionID,
		RequestId:       "01890a5d-ac96-7b10-8000-000000000003",
		TraceId:         "01890a5d-ac96-7b10-8000-000000000004",
	}
}

func validRelayHello() *relayv1.RelayEnvelope {
	return &relayv1.RelayEnvelope{
		ProtocolVersion: probeProtocolVersion,
		InstallationId:  "01890a5d-ac96-7b10-8000-000000000001",
		ConnectionId:    probeConnectionID,
		Payload: &relayv1.RelayEnvelope_RelayHello{
			RelayHello: &relayv1.RelayHello{
				Capabilities:    append([]string(nil), probeCapabilities...),
				EffectiveLimits: productionLimits(),
			},
		},
	}
}
