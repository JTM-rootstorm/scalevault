package tunnel

import (
	"fmt"
	"io"

	relayv1 "github.com/JTM-rootstorm/scalevault/gen/relay/v1"
)

const (
	probeProtocolVersion = "1"
	probeMethod          = "POST"
	probePath            = "/echo"
	maxChunkBytes        = 64 * 1024
	maxRequestBytes      = 256 * 1024
	maxIdentifierBytes   = 128
	maxReasonBytes       = 256
)

// ProbeStream is the subset of a relay Connect stream used by the Milestone 0
// transport probe.
type ProbeStream interface {
	Send(*relayv1.NodeEnvelope) error
	Recv() (*relayv1.RelayEnvelope, error)
}

// ServeProbe runs the bounded Milestone 0 echo protocol over an established
// relay stream. It deliberately supports only POST /echo and one request.
func ServeProbe(stream ProbeStream, installationID string) error {
	if installationID == "" || len(installationID) > maxIdentifierBytes {
		return fmt.Errorf("installation ID must contain 1 to %d bytes", maxIdentifierBytes)
	}

	var request *relayv1.RelayEnvelope
	var totalBytes int
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
				BodyChunk: &relayv1.BodyChunk{Data: data},
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
			if len(payload.Cancelled.Reason) > maxReasonBytes {
				return fmt.Errorf("cancellation reason exceeds %d bytes", maxReasonBytes)
			}
			response := nodeEnvelope(request)
			response.Payload = &relayv1.NodeEnvelope_Cancelled{
				Cancelled: &relayv1.Cancelled{Reason: payload.Cancelled.Reason},
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
	if envelope.ConnectionId == "" || envelope.RequestId == "" || envelope.TraceId == "" {
		return fmt.Errorf("connection, request, and trace IDs are required")
	}
	if len(envelope.ConnectionId) > maxIdentifierBytes || len(envelope.RequestId) > maxIdentifierBytes ||
		len(envelope.TraceId) > maxIdentifierBytes {
		return fmt.Errorf("connection, request, and trace IDs may not exceed %d bytes", maxIdentifierBytes)
	}
	if request != nil && (envelope.ConnectionId != request.ConnectionId ||
		envelope.RequestId != request.RequestId || envelope.TraceId != request.TraceId) {
		return fmt.Errorf("request correlation mismatch")
	}
	return nil
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
