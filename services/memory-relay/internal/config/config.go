// Package config validates relay runtime configuration.
package config

import (
	"fmt"
	"net"
	"os"
)

const defaultListenAddress = "127.0.0.1:8090"

// Config contains immutable relay process configuration.
type Config struct {
	ListenAddress string
}

// FromEnvironment loads and validates the relay environment.
func FromEnvironment() (Config, error) {
	address := os.Getenv("KIVRA_RELAY_LISTEN_ADDRESS")
	if address == "" {
		address = defaultListenAddress
	}
	if _, _, err := net.SplitHostPort(address); err != nil {
		return Config{}, fmt.Errorf("KIVRA_RELAY_LISTEN_ADDRESS: %w", err)
	}
	return Config{ListenAddress: address}, nil
}
