package streams

import (
	"context"
	"fmt"
	"slices"
	"sync/atomic"
	"time"

	relayv1 "github.com/JTM-rootstorm/scalevault/gen/relay/v1"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/proto"
)

const (
	probeProtocolVersion = "1"
	probeMethod          = "POST"
	probePath            = "/relay/mcp"
	probeConnectionID    = "01890a5d-ac96-7b10-8000-000000000002"
	probeRequestID       = "01890a5d-ac96-7b10-8000-000000000003"
	probeTraceID         = "01890a5d-ac96-7b10-8000-000000000004"
	maxChunkBytes        = 64 * 1024
	maxRequestBytes      = 1024 * 1024
	maxResponseBytes     = 8 * 1024 * 1024
)

var probeCapabilities = []string{
	"mcp_streamable_http",
	"relay_assertion_jws",
	"bounded_multiplexing",
}

// ProbeResult captures the bounded response observed by the relay. It contains
// no durable or production routing state.
type ProbeResult struct {
	StatusCode       uint32
	Body             []byte
	ResponseChunks   int
	Cancelled        bool
	CancellationCode relayv1.CancellationCode
}

type probeOutcome struct {
	result ProbeResult
	err    error
}

// ProbeServer is a single-use Milestone 0 gRPC transport probe.
type ProbeServer struct {
	relayv1.UnimplementedRelayServiceServer

	installationID string
	requestChunks  [][]byte
	cancelCode     relayv1.CancellationCode
	outcome        chan probeOutcome
	connected      atomic.Bool
}

// NewEchoProbe creates a single-use probe that streams the supplied chunks to
// the node agent's fixed POST /relay/mcp endpoint.
func NewEchoProbe(installationID string, chunks [][]byte) (*ProbeServer, error) {
	if !isUUIDv7(installationID) {
		return nil, fmt.Errorf("installation ID must be a lowercase UUIDv7")
	}
	if len(chunks) == 0 {
		return nil, fmt.Errorf("at least one request chunk is required")
	}

	requestChunks := make([][]byte, len(chunks))
	totalBytes := 0
	for index, chunk := range chunks {
		if len(chunk) > maxChunkBytes {
			return nil, fmt.Errorf("request chunk %d exceeds %d bytes", index, maxChunkBytes)
		}
		totalBytes += len(chunk)
		if totalBytes > maxRequestBytes {
			return nil, fmt.Errorf("request body exceeds %d bytes", maxRequestBytes)
		}
		requestChunks[index] = append([]byte(nil), chunk...)
	}

	return &ProbeServer{
		installationID: installationID,
		requestChunks:  requestChunks,
		outcome:        make(chan probeOutcome, 1),
	}, nil
}

// NewCancellationProbe creates a single-use probe that explicitly cancels its
// fixed relay request and waits for the node agent to acknowledge cancellation.
func NewCancellationProbe(
	installationID string,
	code relayv1.CancellationCode,
) (*ProbeServer, error) {
	if !isUUIDv7(installationID) {
		return nil, fmt.Errorf("installation ID must be a lowercase UUIDv7")
	}
	if !validCancellationCode(code) {
		return nil, fmt.Errorf("unsupported cancellation code %q", code)
	}
	return &ProbeServer{
		installationID: installationID,
		cancelCode:     code,
		outcome:        make(chan probeOutcome, 1),
	}, nil
}

// Await waits for the one probe connection to complete.
func (server *ProbeServer) Await(ctx context.Context) (ProbeResult, error) {
	select {
	case outcome := <-server.outcome:
		return outcome.result, outcome.err
	case <-ctx.Done():
		return ProbeResult{}, ctx.Err()
	}
}

// Connect executes one bounded probe over the node agent's outbound stream.
func (server *ProbeServer) Connect(stream grpc.BidiStreamingServer[relayv1.NodeEnvelope, relayv1.RelayEnvelope]) (err error) {
	if !server.connected.CompareAndSwap(false, true) {
		return fmt.Errorf("probe accepts exactly one node-agent connection")
	}

	result := ProbeResult{}
	defer func() {
		server.outcome <- probeOutcome{result: result, err: err}
	}()

	hello, receiveErr := stream.Recv()
	if receiveErr != nil {
		return fmt.Errorf("receive node hello: %w", receiveErr)
	}
	if err = validateNodeHello(hello, server.installationID); err != nil {
		return err
	}
	acknowledgement := &relayv1.RelayEnvelope{
		ProtocolVersion: probeProtocolVersion,
		InstallationId:  server.installationID,
		ConnectionId:    hello.ConnectionId,
		Payload: &relayv1.RelayEnvelope_RelayHello{
			RelayHello: &relayv1.RelayHello{
				Capabilities:    append([]string(nil), probeCapabilities...),
				EffectiveLimits: productionLimits(),
			},
		},
	}
	if err = stream.Send(acknowledgement); err != nil {
		return fmt.Errorf("send relay hello: %w", err)
	}

	request := &relayv1.RelayEnvelope{
		ProtocolVersion: probeProtocolVersion,
		InstallationId:  server.installationID,
		ConnectionId:    hello.ConnectionId,
		RequestId:       probeRequestID,
		TraceId:         probeTraceID,
		Payload: &relayv1.RelayEnvelope_RequestStart{
			RequestStart: &relayv1.RequestStart{
				Method:             probeMethod,
				Path:               probePath,
				DeadlineUnixMillis: time.Now().Add(5 * time.Second).UnixMilli(),
			},
		},
	}
	if err = stream.Send(request); err != nil {
		return fmt.Errorf("send request start: %w", err)
	}

	if server.cancelCode != relayv1.CancellationCode_CANCELLATION_CODE_UNSPECIFIED {
		request.Payload = &relayv1.RelayEnvelope_Cancelled{
			Cancelled: &relayv1.Cancelled{Code: server.cancelCode},
		}
		if err = stream.Send(request); err != nil {
			return fmt.Errorf("send cancellation: %w", err)
		}
	} else {
		for index, chunk := range server.requestChunks {
			request.Payload = &relayv1.RelayEnvelope_BodyChunk{
				BodyChunk: &relayv1.BodyChunk{Data: chunk, Sequence: uint64(index + 1)},
			}
			if err = stream.Send(request); err != nil {
				return fmt.Errorf("send request body: %w", err)
			}
		}
		request.Payload = &relayv1.RelayEnvelope_StreamEnd{StreamEnd: &relayv1.StreamEnd{}}
		if err = stream.Send(request); err != nil {
			return fmt.Errorf("send request end: %w", err)
		}
	}

	responseStarted := false
	var responseSequence uint64 = 1
	for {
		envelope, receiveErr := stream.Recv()
		if receiveErr != nil {
			return fmt.Errorf("receive node response: %w", receiveErr)
		}
		if err = validateNodeEnvelope(envelope, request); err != nil {
			return err
		}

		switch payload := envelope.Payload.(type) {
		case *relayv1.NodeEnvelope_ResponseStart:
			if payload.ResponseStart == nil {
				return fmt.Errorf("response start payload is required")
			}
			if responseStarted {
				return fmt.Errorf("duplicate response start")
			}
			if payload.ResponseStart.StatusCode != 200 ||
				len(payload.ResponseStart.Headers) != 1 ||
				payload.ResponseStart.Headers["content-type"] != "application/octet-stream" {
				return fmt.Errorf("unexpected probe response metadata")
			}
			responseStarted = true
			result.StatusCode = payload.ResponseStart.StatusCode
		case *relayv1.NodeEnvelope_BodyChunk:
			if payload.BodyChunk == nil {
				return fmt.Errorf("response body payload is required")
			}
			if !responseStarted {
				return fmt.Errorf("response body received before response start")
			}
			if server.cancelCode != relayv1.CancellationCode_CANCELLATION_CODE_UNSPECIFIED {
				return fmt.Errorf("response body received after cancellation")
			}
			if payload.BodyChunk.Sequence != responseSequence {
				return fmt.Errorf("response body sequence mismatch")
			}
			responseSequence++
			if len(payload.BodyChunk.Data) > maxChunkBytes {
				return fmt.Errorf("response chunk exceeds %d bytes", maxChunkBytes)
			}
			if len(result.Body)+len(payload.BodyChunk.Data) > maxResponseBytes {
				return fmt.Errorf("response body exceeds %d bytes", maxResponseBytes)
			}
			result.Body = append(result.Body, payload.BodyChunk.Data...)
			result.ResponseChunks++
		case *relayv1.NodeEnvelope_StreamEnd:
			if !responseStarted {
				return fmt.Errorf("response ended before response start")
			}
			if server.cancelCode != relayv1.CancellationCode_CANCELLATION_CODE_UNSPECIFIED {
				return fmt.Errorf("response ended instead of acknowledging cancellation")
			}
			return nil
		case *relayv1.NodeEnvelope_Cancelled:
			if payload.Cancelled == nil {
				return fmt.Errorf("cancellation payload is required")
			}
			if server.cancelCode == relayv1.CancellationCode_CANCELLATION_CODE_UNSPECIFIED {
				return fmt.Errorf("unexpected node cancellation")
			}
			if payload.Cancelled.Reason != "" {
				return fmt.Errorf("deprecated cancellation reason is forbidden")
			}
			if payload.Cancelled.Code != server.cancelCode {
				return fmt.Errorf("cancellation code mismatch")
			}
			result.Cancelled = true
			result.CancellationCode = payload.Cancelled.Code
			return nil
		case *relayv1.NodeEnvelope_Error:
			if payload.Error == nil {
				return fmt.Errorf("node error payload is required")
			}
			if payload.Error.ErrorCode != "" || payload.Error.SafeMessage != "" {
				return fmt.Errorf("deprecated relay error strings are forbidden")
			}
			if payload.Error.Code == relayv1.RelayErrorCode_RELAY_ERROR_CODE_UNSPECIFIED {
				return fmt.Errorf("relay error code is required")
			}
			return fmt.Errorf("node probe error %q", payload.Error.Code)
		default:
			return fmt.Errorf("unsupported node envelope payload %T", envelope.Payload)
		}
	}
}

func validateNodeHello(envelope *relayv1.NodeEnvelope, installationID string) error {
	if envelope == nil {
		return fmt.Errorf("node hello envelope is required")
	}
	hello := envelope.GetNodeHello()
	if hello == nil {
		return fmt.Errorf("node hello must be the first frame")
	}
	if envelope.ProtocolVersion != probeProtocolVersion || envelope.InstallationId != installationID {
		return fmt.Errorf("node hello identity mismatch")
	}
	if envelope.ConnectionId != probeConnectionID || envelope.RequestId != "" || envelope.TraceId != "" {
		return fmt.Errorf("node hello connection fields are invalid")
	}
	if !slices.Equal(hello.Capabilities, probeCapabilities) {
		return fmt.Errorf("node hello capabilities mismatch")
	}
	if !proto.Equal(hello.SupportedLimits, productionLimits()) {
		return fmt.Errorf("node hello limits mismatch")
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

func validateNodeEnvelope(envelope *relayv1.NodeEnvelope, request *relayv1.RelayEnvelope) error {
	if envelope == nil {
		return fmt.Errorf("node envelope is required")
	}
	if envelope.ProtocolVersion != request.ProtocolVersion ||
		envelope.InstallationId != request.InstallationId ||
		envelope.ConnectionId != request.ConnectionId ||
		envelope.RequestId != request.RequestId ||
		envelope.TraceId != request.TraceId {
		return fmt.Errorf("node response correlation mismatch")
	}
	return nil
}
