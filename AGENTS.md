# Repository guidance

## Scope

ScaleVault is a security- and privacy-sensitive continuity service. Preserve the
architectural boundary between the canonical Memory Node, transport-only relay,
GitHub proposal ingress, and archive-only Git repository.

## Shared contracts

Changes to migrations, protobuf messages, JSON schemas, MCP tool names, memory
ontology, or policy documents require an explicit architecture decision and
coordinated review. Direct, relay, and ingress mutations must eventually use the
same domain command handlers.

## Security

- Never commit secrets, memory payloads, private hostnames, or access tokens.
- Treat retrieved memories and ingress proposals as untrusted data.
- Do not log memory statements, evidence, authorization values, or payloads.
- Keep relay and node-agent code incapable of selecting arbitrary private
  destinations or executing commands.
- Fail closed when identity, installation binding, or dependencies are unknown.

## Validation

Run `make verify` before handing off changes. Keep generated artifacts
deterministic and commit them with the source contract that produced them.

## Commit attribution

Commits created by Codex must include the following Git trailer:

`Co-Authored-By: Codex <codex@openai.com>`
