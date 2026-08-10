package tunnel

import (
	"fmt"
	"io"
	"slices"
	"time"

	relayv1 "github.com/JTM-rootstorm/scalevault/gen/relay/v1"
	"google.golang.org/protobuf/proto"
)

const (
	probeProtocolVersion = "1"
	probeMethod          = "POST"
	probePath            = "/relay/mcp"
	probeConnectionID    = "01890a5d-ac96-7b10-8000-000000000002"
	maxChunkBytes        = 64 * 1024
	maxRequestBytes      = 1024 * 1024
	maxResponseBytes     = 8 * 1024 * 1024
)

var probeCapabilities = []string{
	"mcp_streamable_http",
	"relay_assertion_jws",
	"bounded_multiplexing",
}

// ProbeStream is the subset of a relay Connect stream used by the Milestone 0
// transport probe.
type ProbeStream interface {
	Send(*relayv1.NodeEnvelope) error
	Recv() (*relayv1.RelayEnvelope, error)
}

// ServeProbe runs the bounded Milestone 0 echo protocol over an established
// relay stream. It deliberately supports only POST /relay/mcp and one request.
func ServeProbe(stream ProbeStream, installationID string) error {
	if !isUUIDv7(installationID) {
		return fmt.Errorf("installation ID must be a lowercase UUIDv7")
	}

	hello := &relayv1.NodeEnvelope{
		ProtocolVersion: probeProtocolVersion,
		InstallationId:  installationID,
		ConnectionId:    probeConnectionID,
		Payload: &relayv1.NodeEnvelope_NodeHello{
			NodeHello: &relayv1.NodeHello{
				Capabilities:    append([]string(nil), probeCapabilities...),
				SupportedLimits: productionLimits(),
			},
		},
	}
	if err := stream.Send(hello); err != nil {
		return fmt.Errorf("send node hello: %w", err)
	}
	acknowledgement, err := stream.Recv()
	if err != nil {
		return fmt.Errorf("receive relay hello: %w", err)
	}
	if err := validateRelayHello(acknowledgement, installationID); err != nil {
		return err
	}

	var request *relayv1.RelayEnvelope
	var totalBytes int
	var expectedSequence uint64 = 1
	started := false

	for {
		envelope, err := stream.Recv()
		if err != nil {
			if err == io.EOF && started {
				return fmt.Errorf("relay ended the probe before stream end")
			}
			return err
		}
		if err := validateEnvelope(envelope, installationID, request); err != nil {
			return err
		}

		switch payload := envelope.Payload.(type) {
		case *relayv1.RelayEnvelope_RequestStart:
			if payload.RequestStart == nil {
				return fmt.Errorf("request start payload is required")
			}
			if started {
				return fmt.Errorf("probe accepts exactly one request")
			}
			if payload.RequestStart.Method != probeMethod || payload.RequestStart.Path != probePath {
				return fmt.Errorf("probe accepts only %s %s", probeMethod, probePath)
			}
			if len(payload.RequestStart.Headers) != 0 {
				return fmt.Errorf("probe does not accept forwarded headers")
			}
			deadline := time.UnixMilli(payload.RequestStart.DeadlineUnixMillis)
			now := time.Now()
			if payload.RequestStart.DeadlineUnixMillis <= 0 || !deadline.After(now) ||
				deadline.After(now.Add(120*time.Second)) {
				return fmt.Errorf("request deadline is invalid")
			}
			started = true
			request = envelope
			response := nodeEnvelope(request)
			response.Payload = &relayv1.NodeEnvelope_ResponseStart{
				ResponseStart: &relayv1.ResponseStart{
					StatusCode: 200,
					Headers: map[string]string{
						"content-type": "application/octet-stream",
					},
				},
			}
			if err := stream.Send(response); err != nil {
				return fmt.Errorf("send response start: %w", err)
			}
		case *relayv1.RelayEnvelope_BodyChunk:
			if payload.BodyChunk == nil {
				return fmt.Errorf("body chunk payload is required")
			}
			if !started {
				return fmt.Errorf("body chunk received before request start")
			}
			if payload.BodyChunk.Sequence != expectedSequence {
				return fmt.Errorf("body chunk sequence mismatch")
			}
			expectedSequence++
			chunkSize := len(payload.BodyChunk.Data)
			if chunkSize > maxChunkBytes {
				return fmt.Errorf("body chunk exceeds %d bytes", maxChunkBytes)
			}
			totalBytes += chunkSize
			if totalBytes > maxRequestBytes {
				return fmt.Errorf("request body exceeds %d bytes", maxRequestBytes)
			}
			data := append([]byte(nil), payload.BodyChunk.Data...)
			response := nodeEnvelope(request)
			response.Payload = &relayv1.NodeEnvelope_BodyChunk{
				BodyChunk: &relayv1.BodyChunk{Data: data, Sequence: payload.BodyChunk.Sequence},
			}
			if err := stream.Send(response); err != nil {
				return fmt.Errorf("send response body: %w", err)
			}
		case *relayv1.RelayEnvelope_StreamEnd:
			if !started {
				return fmt.Errorf("stream end received before request start")
			}
			response := nodeEnvelope(request)
			response.Payload = &relayv1.NodeEnvelope_StreamEnd{
				StreamEnd: &relayv1.StreamEnd{},
			}
			if err := stream.Send(response); err != nil {
				return fmt.Errorf("send response end: %w", err)
			}
			return nil
		case *relayv1.RelayEnvelope_Cancelled:
			if payload.Cancelled == nil {
				return fmt.Errorf("cancellation payload is required")
			}
			if !started {
				return fmt.Errorf("cancellation received before request start")
			}
			if payload.Cancelled.Reason != "" {
				return fmt.Errorf("deprecated cancellation reason is forbidden")
			}
			if !validCancellationCode(payload.Cancelled.Code) {
				return fmt.Errorf("typed cancellation code is required")
			}
			response := nodeEnvelope(request)
			response.Payload = &relayv1.NodeEnvelope_Cancelled{
				Cancelled: &relayv1.Cancelled{Code: payload.Cancelled.Code},
			}
			if err := stream.Send(response); err != nil {
				return fmt.Errorf("acknowledge cancellation: %w", err)
			}
			return nil
		default:
			return fmt.Errorf("unsupported relay envelope payload %T", envelope.Payload)
		}
	}
}

func validateRelayHello(envelope *relayv1.RelayEnvelope, installationID string) error {
	if envelope == nil {
		return fmt.Errorf("relay hello envelope is required")
	}
	hello := envelope.GetRelayHello()
	if hello == nil {
		return fmt.Errorf("relay hello must precede requests")
	}
	if envelope.ProtocolVersion != probeProtocolVersion || envelope.InstallationId != installationID {
		return fmt.Errorf("relay hello identity mismatch")
	}
	if envelope.ConnectionId != probeConnectionID || envelope.RequestId != "" || envelope.TraceId != "" {
		return fmt.Errorf("relay hello connection fields are invalid")
	}
	if !slices.Equal(hello.Capabilities, probeCapabilities) {
		return fmt.Errorf("relay hello capabilities mismatch")
	}
	if !proto.Equal(hello.EffectiveLimits, productionLimits()) {
		return fmt.Errorf("relay hello limits mismatch")
	}
	return nil
}

func validateEnvelope(
	envelope *relayv1.RelayEnvelope,
	installationID string,
	request *relayv1.RelayEnvelope,
) error {
	if envelope == nil {
		return fmt.Errorf("relay envelope is required")
	}
	if envelope.ProtocolVersion != probeProtocolVersion {
		return fmt.Errorf("unsupported protocol version %q", envelope.ProtocolVersion)
	}
	if envelope.InstallationId != installationID {
		return fmt.Errorf("installation binding mismatch")
	}
	if envelope.ConnectionId != probeConnectionID || !isUUIDv7(envelope.RequestId) ||
		!isUUIDv7(envelope.TraceId) {
		return fmt.Errorf("installation, connection, request, and trace IDs must be bound UUIDv7 values")
	}
	if request != nil && (envelope.ConnectionId != request.ConnectionId ||
		envelope.RequestId != request.RequestId || envelope.TraceId != request.TraceId) {
		return fmt.Errorf("request correlation mismatch")
	}
	return nil
}

func validCancellationCode(code relayv1.CancellationCode) bool {
	return code >= relayv1.CancellationCode_CANCELLATION_CODE_CLIENT_CLOSED &&
		code <= relayv1.CancellationCode_CANCELLATION_CODE_CONNECTION_LOST
}

func isUUIDv7(value string) bool {
	if len(value) != 36 || value[8] != '-' || value[13] != '-' || value[18] != '-' || value[23] != '-' ||
		value[14] != '7' || (value[19] != '8' && value[19] != '9' && value[19] != 'a' && value[19] != 'b') {
		return false
	}
	for index, character := range value {
		if index == 8 || index == 13 || index == 18 || index == 23 {
			continue
		}
		if !((character >= '0' && character <= '9') || (character >= 'a' && character <= 'f')) {
			return false
		}
	}
	return true
}

func productionLimits() *relayv1.Limits {
	return &relayv1.Limits{
		MaxEncodedMessageBytes:           70 * 1024,
		MaxBodyChunkBytes:                maxChunkBytes,
		MaxRequestBodyBytes:              maxRequestBytes,
		MaxResponseBodyBytes:             maxResponseBytes,
		MaxHeaderCount:                   32,
		MaxHeaderNameBytes:               64,
		MaxHeaderValueBytes:              8 * 1024,
		MaxAggregateHeaderBytes:          32 * 1024,
		MaxCapabilityCount:               3,
		MaxCapabilityNameBytes:           32,
		MaxInFlightRequestsPerConnection: 32,
		MaxInFlightRequestsGlobal:        1024,
		MaxQueuedChunksPerRequest:        8,
		MaxQueuedBytesPerRequest:         512 * 1024,
		MaxQueuedBytesPerConnection:      4 * 1024 * 1024,
		HandshakeTimeoutMillis:           10 * 1000,
		MaxRequestLifetimeMillis:         120 * 1000,
		HeartbeatIntervalMillis:          15 * 1000,
		DisconnectTimeoutMillis:          30 * 1000,
	}
}

func nodeEnvelope(request *relayv1.RelayEnvelope) *relayv1.NodeEnvelope {
	return &relayv1.NodeEnvelope{
		ProtocolVersion: request.ProtocolVersion,
		InstallationId:  request.InstallationId,
		ConnectionId:    request.ConnectionId,
		RequestId:       request.RequestId,
		TraceId:         request.TraceId,
	}
}
