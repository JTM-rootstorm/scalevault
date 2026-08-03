# PostgreSQL deployment

The production node will listen on a Unix socket or loopback only. Separate
roles will own migrations, API transactions, workers, ingress, and exporter
checkpoints. WAL archival, checksums, pool sizing, extensions, and pgvector
index policy will be committed with the Milestone 2 schema.
