package streams

import (
	"context"
	"fmt"
	"sync/atomic"

	relayv1 "github.com/JTM-rootstorm/scalevault/gen/relay/v1"
	"google.golang.org/grpc"
)

const (
	probeProtocolVersion = "1"
	probeMethod          = "POST"
	probePath            = "/echo"
	maxChunkBytes        = 64 * 1024
	maxResponseBytes     = 256 * 1024
	maxIdentifierBytes   = 128
	maxReasonBytes       = 256
)

// ProbeResult captures the bounded response observed by the relay. It contains
// no durable or production routing state.
type ProbeResult struct {
	StatusCode         uint32
	Body               []byte
	ResponseChunks     int
	Cancelled          bool
	CancellationReason string
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
	cancelReason   string
	outcome        chan probeOutcome
	connected      atomic.Bool
}

// NewEchoProbe creates a single-use probe that streams the supplied chunks to
// the node agent's fixed POST /echo endpoint.
func NewEchoProbe(installationID string, chunks [][]byte) (*ProbeServer, error) {
	if installationID == "" || len(installationID) > maxIdentifierBytes {
		return nil, fmt.Errorf("installation ID must contain 1 to %d bytes", maxIdentifierBytes)
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
		if totalBytes > maxResponseBytes {
			return nil, fmt.Errorf("request body exceeds %d bytes", maxResponseBytes)
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
// fixed echo request and waits for the node agent to acknowledge cancellation.
func NewCancellationProbe(installationID, reason string) (*ProbeServer, error) {
	if installationID == "" || len(installationID) > maxIdentifierBytes {
		return nil, fmt.Errorf("installation ID must contain 1 to %d bytes", maxIdentifierBytes)
	}
	if reason == "" || len(reason) > maxReasonBytes {
		return nil, fmt.Errorf("cancellation reason must contain 1 to %d bytes", maxReasonBytes)
	}
	return &ProbeServer{
		installationID: installationID,
		cancelReason:   reason,
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

	request := &relayv1.RelayEnvelope{
		ProtocolVersion: probeProtocolVersion,
		InstallationId:  server.installationID,
		ConnectionId:    "milestone-0-connection",
		RequestId:       "milestone-0-request",
		TraceId:         "milestone-0-trace",
		Payload: &relayv1.RelayEnvelope_RequestStart{
			RequestStart: &relayv1.RequestStart{Method: probeMethod, Path: probePath},
		},
	}
	if err = stream.Send(request); err != nil {
		return fmt.Errorf("send request start: %w", err)
	}

	if server.cancelReason != "" {
		request.Payload = &relayv1.RelayEnvelope_Cancelled{
			Cancelled: &relayv1.Cancelled{Reason: server.cancelReason},
		}
		if err = stream.Send(request); err != nil {
			return fmt.Errorf("send cancellation: %w", err)
		}
	} else {
		for _, chunk := range server.requestChunks {
			request.Payload = &relayv1.RelayEnvelope_BodyChunk{
				BodyChunk: &relayv1.BodyChunk{Data: chunk},
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
			if server.cancelReason != "" {
				return fmt.Errorf("response body received after cancellation")
			}
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
			if server.cancelReason != "" {
				return fmt.Errorf("response ended instead of acknowledging cancellation")
			}
			return nil
		case *relayv1.NodeEnvelope_Cancelled:
			if payload.Cancelled == nil {
				return fmt.Errorf("cancellation payload is required")
			}
			if server.cancelReason == "" {
				return fmt.Errorf("unexpected node cancellation")
			}
			if payload.Cancelled.Reason != server.cancelReason {
				return fmt.Errorf("cancellation reason mismatch")
			}
			result.Cancelled = true
			result.CancellationReason = payload.Cancelled.Reason
			return nil
		case *relayv1.NodeEnvelope_Error:
			if payload.Error == nil {
				return fmt.Errorf("node error payload is required")
			}
			return fmt.Errorf("node probe error %q: %s", payload.Error.ErrorCode, payload.Error.SafeMessage)
		default:
			return fmt.Errorf("unsupported node envelope payload %T", envelope.Payload)
		}
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
