// Package config validates node-agent runtime configuration.
package config

import (
	"fmt"
	"net"
	"net/url"
	"os"
)

const (
	defaultListenAddress = "127.0.0.1:8091"
	defaultUpstreamURL   = "http://127.0.0.1:8080/mcp"
)

// Config contains immutable node-agent process configuration.
type Config struct {
	ListenAddress string
	UpstreamURL   *url.URL
}

// FromEnvironment loads and validates the node-agent environment.
func FromEnvironment() (Config, error) {
	address := valueOrDefault("KIVRA_NODE_AGENT_LISTEN_ADDRESS", defaultListenAddress)
	if _, _, err := net.SplitHostPort(address); err != nil {
		return Config{}, fmt.Errorf("KIVRA_NODE_AGENT_LISTEN_ADDRESS: %w", err)
	}

	upstream, err := url.Parse(valueOrDefault("KIVRA_NODE_AGENT_UPSTREAM_URL", defaultUpstreamURL))
	if err != nil {
		return Config{}, fmt.Errorf("KIVRA_NODE_AGENT_UPSTREAM_URL: %w", err)
	}
	if upstream.Scheme != "http" && upstream.Scheme != "https" {
		return Config{}, fmt.Errorf("KIVRA_NODE_AGENT_UPSTREAM_URL: unsupported scheme %q", upstream.Scheme)
	}
	if upstream.Hostname() != "127.0.0.1" && upstream.Hostname() != "localhost" {
		return Config{}, fmt.Errorf("KIVRA_NODE_AGENT_UPSTREAM_URL: upstream must be loopback")
	}

	return Config{ListenAddress: address, UpstreamURL: upstream}, nil
}

func valueOrDefault(name, fallback string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}
	return fallback
}
