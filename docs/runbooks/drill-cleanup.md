# Recovery-drill cleanup and evidence hygiene

Inventory exact cleanup targets before deleting anything. The target set must
be confined to the named disposable recovery instance and protected scratch;
never use a broad root, wildcard, unresolved variable, production mount, or
exporter worktree.

1. Stop and disable every drill PostgreSQL/application unit and prove no drill
   process, listener, mount user, or network session remains.
2. Preserve only the approved content-free evidence record and fixed failure
   artifacts needed for investigation. Sensitive failure artifacts remain in
   the protected evidence store with restricted access and retention.
3. Remove decrypted bundles, archive clones, restored database files, WAL
   scratch, recovery keys staged for the drill, temporary credentials, socket
   directories, environment/configuration copies, and canary inputs from the
   exact inventory.
4. Verify the inventory paths are absent, the recovery identity returned to its
   independent store, no routine node gained that identity, and no shell
   history, journal, core, swap, temporary directory, or repository file
   contains a planted canary or credential marker.
5. Confirm production service state and backup/archive objects were not
   changed. Record cleanup as complete only after an independent second check.

A cleanup failure keeps the drill status failed or pending. File unlink is not
evidence of physical-media erasure; report only logical cleanup within the
tested storage boundary.
