# Relay protocol

Relay protocol v1 is defined in `proto/relay-v1.proto`. It carries bounded,
multiplexed HTTP request and response streams over an outbound authenticated
node-agent connection. The relay persists identity and operational metadata,
never memory bodies.

The node agent forwards only to its configured loopback MCP endpoint. Arbitrary
destinations, shell execution, and hop-by-hop headers are out of scope.
