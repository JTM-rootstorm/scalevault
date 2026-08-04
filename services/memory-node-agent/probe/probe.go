// Package probe exposes only the Milestone 0 relay transport probe.
package probe

import (
	relayv1 "github.com/JTM-rootstorm/scalevault/gen/relay/v1"
	"github.com/JTM-rootstorm/scalevault/services/memory-node-agent/internal/tunnel"
)

// Stream is the subset of a relay Connect stream used by the transport probe.
type Stream interface {
	Send(*relayv1.NodeEnvelope) error
	Recv() (*relayv1.RelayEnvelope, error)
}

// Serve runs the fixed, bounded echo probe for one installation.
func Serve(stream Stream, installationID string) error {
	return tunnel.ServeProbe(stream, installationID)
}
