# Architecture

ScaleVault has one canonical private Memory Node and multiple transport
profiles. PostgreSQL owns semantic state. The public relay and GitHub ingress
carry requests or proposals but are not alternate memory stores. Forgejo is a
deterministic recovery archive written by one logical exporter.

Shared contracts are versioned and reviewed centrally. All write transports
must converge on the same policy and concurrency-safe domain command layer.
