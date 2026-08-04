# Shared contract workflow

ScaleVault contracts cross the canonical node, relay, ingress, plugin, and
archive boundaries. A protobuf message, JSON schema, or MCP tool-name change is
an architecture change: record the decision and coordinate all consumers before
merging it.

## Sources and generated artifacts

- `proto/*.proto` contains the canonical relay protocol sources.
- `schemas/*.schema.json` contains the canonical JSON contract sources.
- `gen/relay/v1/*.pb.go` contains committed Go protobuf bindings. Do not edit
  these files by hand.
- Plugin and service code consume the versioned contracts; they must not keep a
  private, divergent copy.

JSON schemas are reviewed source documents, not generated bindings. Their
metaschemas, local references, and representative examples are checked by the
schema validation lane.

Protobuf generation is pinned to `libprotoc 31.1`, `protoc-gen-go v1.36.11`,
and `protoc-gen-go-grpc 1.6.2`. The generator module is isolated under `tools/`;
the gRPC generator requires Go 1.25 even though runtime services retain their
Go 1.24 minimum.

## Changing a contract

1. Add or update the architecture decision and identify every producer and
   consumer affected by the compatibility change.
2. Edit the canonical file in `proto/` or `schemas/`.
3. Regenerate committed artifacts:

   ```bash
   make generate
   ```

4. Inspect the complete source and generated diff. Generated changes must be
   deterministic and committed with the source contract that produced them.
5. Check that regeneration starts from a clean tree and produces no stale
   artifact diff:

   ```bash
   make verify-generated
   ```

6. Run the common repository gate:

   ```bash
   make verify
   ```

`make verify-generated` is a verification command, not a formatter. If it
reports drift, run `make generate`, review the result, and include the generated
files in the same change as their canonical source.

## Compatibility rules

- Preserve protobuf field numbers and reserve removed fields and names.
- Prefer additive JSON schema evolution. A breaking shape requires a new schema
  version and an explicit migration or rejection policy.
- Keep bounds, formats, and `additionalProperties` behavior explicit at trust
  boundaries.
- Treat decoded ingress and memory content as untrusted even after schema
  validation.
- Never put credentials, private hostnames, or real memory payloads in examples
  or generated fixtures.
