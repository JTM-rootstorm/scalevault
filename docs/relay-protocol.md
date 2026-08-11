# Relay protocol v1

> **Superseded deployment path:** ADR 0022 removed the public relay and node
> agent from the active v1 topology. This document preserves the reviewed wire
> contract as dormant implementation history; no selected production service
> may expose or connect it.

The canonical wire definition is [`proto/relay-v1.proto`](../proto/relay-v1.proto).
It carries bounded, numbered HTTP request and response streams over one outbound,
mTLS-authenticated node-agent connection. The relay may persist only the routing,
node-certificate, connection, quota, and health metadata accepted by
[ADR 0020](adr/0020-relay-enrollment-and-transport.md). It never persists request
or response bodies or header values.

## Connection handshake

The first node frame is `NodeEnvelope(node_hello)`. It has protocol version `1`,
the verified-certificate installation UUID, a fresh connection UUIDv7, and empty
request and trace IDs. `NodeHello` contains exactly these three capabilities in
this canonical order:

```text
mcp_streamable_http
relay_assertion_jws
bounded_multiplexing
```

The node also supplies every field in `Limits`. The relay validates the mTLS
identity and all hello fields, then replies with `RelayEnvelope(relay_hello)` for
the same installation and connection. `RelayHello` applies the same capability
set and effective limits selected no more permissively than either peer's
supported values. The probe and initial production profile use the values below.
Missing or zero limit fields, unknown capabilities, request or health frames
before the acknowledgement, and a handshake timeout after 10 seconds fail the
connection closed.

| `Limits` field | Required v1 value |
|---|---:|
| `max_encoded_message_bytes` | 71,680 |
| `max_body_chunk_bytes` | 65,536 |
| `max_request_body_bytes` | 1,048,576 |
| `max_response_body_bytes` | 8,388,608 |
| `max_header_count` | 32 |
| `max_header_name_bytes` | 64 |
| `max_header_value_bytes` | 8,192 |
| `max_aggregate_header_bytes` | 32,768 |
| `max_capability_count` | 3 |
| `max_capability_name_bytes` | 32 |
| `max_in_flight_requests_per_connection` | 32 |
| `max_in_flight_requests_global` | 1,024 |
| `max_queued_chunks_per_request` | 8 |
| `max_queued_bytes_per_request` | 524,288 |
| `max_queued_bytes_per_connection` | 4,194,304 |
| `handshake_timeout_millis` | 10,000 |
| `max_request_lifetime_millis` | 120,000 |
| `heartbeat_interval_millis` | 15,000 |
| `disconnect_timeout_millis` | 30,000 |

The encoded-message ceiling is enforced by gRPC before protobuf unmarshal. All
decoded count and byte bounds are enforced before copying, queueing, or
dispatching a frame.

## Request state machine

After acknowledgement, each request uses one lowercase UUIDv7 request ID and
one fresh lowercase UUIDv7 trace ID. A request proceeds in this order:

```text
RequestStart -> BodyChunk* -> StreamEnd
             -> ResponseStart -> BodyChunk* -> StreamEnd
```

`RequestStart` is `POST` to `/relay/mcp`, contains only the reviewed forwarded
header map, and carries the absolute Unix-millisecond deadline required by ADR
0020. Request bodies and response bodies have independent beginning sequence
number `1`; every body chunk increments its direction's sequence number by one.
Zero-length chunks are still numbered. A missing, zero, repeated, or skipped
sequence is an invalid envelope.

The initial node agent forwards only to the literal loopback HTTP endpoint
`http://127.0.0.1:8080/relay/mcp`. A relay frame cannot select a host, path,
method, query, redirect, or Unix command. Request headers are bounded to the
reviewed `Content-Type`, `Accept`, `MCP-Protocol-Version`, and the internally
created `ScaleVault-Relay-Assertion`. Response headers are bounded to `Content-Type`
and `Cache-Control`. Unknown hop-by-hop, reserved, cookie, authorization, host,
proxy, and forwarding headers are rejected rather than forwarded.

The request-side `StreamEnd` closes input without ending the response. The
response-side `StreamEnd`, `Cancelled`, or `RelayError` completes the request.
Frames after completion are invalid and cannot change canonical state. A
duplicate cancellation is harmless; other post-completion frames fail closed.
A lost connection cancels every in-flight request, and the relay and node agent
never resume or automatically replay it.

## Typed states and failures

Production frames use only these non-zero cancellation codes:

```text
client_closed
deadline_exceeded
queue_exhausted
installation_revoked
relay_shutdown
connection_lost
```

The allowed relay error codes are:

```text
invalid_envelope
unsupported_version
installation_mismatch
request_rejected
upstream_unavailable
upstream_protocol
body_too_large
headers_invalid
deadline_exceeded
queue_exhausted
installation_revoked
internal
```

Health frames use only the typed states `ready`, `degraded`, and `draining`.
When no other valid frame is sent, the node sends health at least every 15
seconds. The relay closes the connection after 30 seconds without a valid
frame.

The original string fields `Cancelled.reason`, `RelayError.error_code`,
`RelayError.safe_message`, `Health.state`, and `Health.capabilities` remain at
their existing protobuf field numbers for additive wire compatibility and are
marked deprecated. Production peers require the typed variants and reject a
non-empty deprecated field. Unspecified or unknown enum values fail closed.

## Backpressure and privacy

Every request and connection has the queue budgets advertised in `Limits`.
Queue exhaustion cancels only the slow request with the typed
`queue_exhausted` code; it does not block the receive dispatcher or unrelated
requests. HTTP/2 flow control is additional protection, not the application
queue contract.

Logs and metrics contain closed error/state codes and aggregate service values,
not request or response bodies, header values, assertions, credentials,
certificate contents, free-text upstream error data, or installation and
request identifiers. Payload tracing, body spooling, request capture, and proxy
buffering are forbidden. A TLS-terminating relay can still observe live
plaintext in process memory; v1 does not claim relay blindness.
