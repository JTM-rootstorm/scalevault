package streams_test

import (
	"bytes"
	"context"
	"net"
	"testing"
	"time"

	relayv1 "github.com/JTM-rootstorm/scalevault/gen/relay/v1"
	agentprobe "github.com/JTM-rootstorm/scalevault/services/memory-node-agent/probe"
	"github.com/JTM-rootstorm/scalevault/services/memory-relay/internal/streams"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"
)

const testInstallationID = "01890a5d-ac96-7b10-8000-000000000001"

func TestProbeStreamsEchoResponse(t *testing.T) {
	probe, err := streams.NewEchoProbe(testInstallationID, [][]byte{
		[]byte("streamed "),
		[]byte("echo"),
	})
	if err != nil {
		t.Fatalf("create echo probe: %v", err)
	}

	agentDone, cleanup := runProbe(t, probe)
	defer cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	result, err := probe.Await(ctx)
	if err != nil {
		t.Fatalf("await echo probe: %v", err)
	}
	if result.StatusCode != 200 {
		t.Fatalf("expected status 200, got %d", result.StatusCode)
	}
	if !bytes.Equal(result.Body, []byte("streamed echo")) {
		t.Fatalf("unexpected response body %q", result.Body)
	}
	if result.ResponseChunks != 2 {
		t.Fatalf("expected 2 streamed response chunks, got %d", result.ResponseChunks)
	}
	if err := <-agentDone; err != nil {
		t.Fatalf("node agent probe failed: %v", err)
	}
}

func TestProbePropagatesCancellation(t *testing.T) {
	probe, err := streams.NewCancellationProbe(
		testInstallationID,
		relayv1.CancellationCode_CANCELLATION_CODE_CLIENT_CLOSED,
	)
	if err != nil {
		t.Fatalf("create cancellation probe: %v", err)
	}

	agentDone, cleanup := runProbe(t, probe)
	defer cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	result, err := probe.Await(ctx)
	if err != nil {
		t.Fatalf("await cancellation probe: %v", err)
	}
	if !result.Cancelled {
		t.Fatal("expected node agent to acknowledge cancellation")
	}
	if result.CancellationCode != relayv1.CancellationCode_CANCELLATION_CODE_CLIENT_CLOSED {
		t.Fatalf("unexpected cancellation code %q", result.CancellationCode)
	}
	if err := <-agentDone; err != nil {
		t.Fatalf("node agent probe failed: %v", err)
	}
}

func runProbe(t *testing.T, probe *streams.ProbeServer) (<-chan error, func()) {
	t.Helper()

	listener := bufconn.Listen(1024 * 1024)
	grpcServer := grpc.NewServer()
	relayv1.RegisterRelayServiceServer(grpcServer, probe)
	go func() {
		_ = grpcServer.Serve(listener)
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	connection, err := grpc.NewClient(
		"passthrough:///milestone-0-probe",
		grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) {
			return listener.Dial()
		}),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		cancel()
		grpcServer.Stop()
		_ = listener.Close()
		t.Fatalf("create probe client: %v", err)
	}
	stream, err := relayv1.NewRelayServiceClient(connection).Connect(ctx)
	if err != nil {
		cancel()
		_ = connection.Close()
		grpcServer.Stop()
		_ = listener.Close()
		t.Fatalf("connect node agent probe: %v", err)
	}

	agentDone := make(chan error, 1)
	go func() {
		agentDone <- agentprobe.Serve(stream, testInstallationID)
	}()

	cleanup := func() {
		cancel()
		_ = connection.Close()
		grpcServer.Stop()
		_ = listener.Close()
	}
	return agentDone, cleanup
}
