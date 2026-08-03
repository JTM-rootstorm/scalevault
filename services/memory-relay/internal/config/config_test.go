package config

import "testing"

func TestFromEnvironmentRejectsInvalidAddress(t *testing.T) {
	t.Setenv("KIVRA_RELAY_LISTEN_ADDRESS", "not-an-address")

	if _, err := FromEnvironment(); err == nil {
		t.Fatal("expected invalid address error")
	}
}
