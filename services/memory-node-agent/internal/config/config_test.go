package config

import "testing"

func TestFromEnvironmentRejectsNonLoopbackUpstream(t *testing.T) {
	t.Setenv("KIVRA_NODE_AGENT_UPSTREAM_URL", "https://example.com/mcp")

	if _, err := FromEnvironment(); err == nil {
		t.Fatal("expected non-loopback upstream error")
	}
}
