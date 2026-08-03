# Backup and restore

The recovery design combines PostgreSQL base backups and WAL, a separate
Forgejo archive, an encrypted secondary bundle, and separately protected keys.
Restore drills must verify manifest chains, rebuild projections and embeddings,
and test context-pack canaries before writes resume.
