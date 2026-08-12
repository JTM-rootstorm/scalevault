# WAL archive failure

Treat a failed `archive_command`, missing segment, stale WAL status, or growing
`pg_wal` backlog as a recovery-chain incident.

1. Acknowledge the alert and identify only the fixed failure class and first
   observed time. Do not print WAL contents, database URLs, or environment.
2. Confirm the exact backup mount exists and has expected ownership, space,
   inode capacity, and read/write posture. Do not create a fallback directory
   on the canonical filesystem.
3. Review the bounded helper status and PostgreSQL's fixed archive counters.
   Avoid broad journal exports.
4. Keep PostgreSQL running while space remains safe so the failing segment can
   be retried. Do not delete `pg_wal`, call `pg_archivecleanup` on the source,
   disable `archive_mode`, or mark a segment successful manually.
5. Correct only the classified dependency: mount, permissions, capacity,
   encryption recipient, helper installation, or destination atomicity.
6. Force or await a WAL switch, prove the failed segment and its successors
   archive and verify, then create and verify a fresh base backup if continuity
   was ever uncertain.
7. Keep retention disabled until a complete replacement chain exists and an
   isolated restore has validated the affected interval.

If canonical storage is approaching exhaustion, enter
[safe shutdown](shutdown-startup.md) before PostgreSQL loses durability. A
missing or corrupt WAL segment is not repairable by renaming another object;
mark the chain unusable and preserve it for investigation.
