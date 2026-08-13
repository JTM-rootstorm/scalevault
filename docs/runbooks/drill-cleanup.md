# Recovery-drill cleanup and evidence hygiene

Inventory exact cleanup targets before deleting anything. The target set must
be confined to the named disposable recovery instance and protected scratch;
never use a broad root, wildcard, unresolved variable, production mount, local
signed-archive source, or exporter worktree.

1. Stop and disable every drill PostgreSQL/application unit and prove no drill
   process, listener, mount user, or network session remains.
2. Preserve only the approved content-free evidence record and fixed failure
   artifacts needed for investigation. Sensitive failure artifacts remain in
   the protected evidence store with restricted access and retention.
3. Remove decrypted bundles, drill-owned archive clones, restored database
   files, WAL scratch, recovery keys staged for the drill, temporary
   credentials, socket directories, environment/configuration copies, and
   canary inputs from the exact inventory. Do not delete an accepted encrypted
   base, WAL/history object, restore point, hold, signed-archive source, or
   retained encrypted bundle.
4. Verify the inventory paths are absent, the recovery identity returned to its
   independent store, no routine node gained that identity, and no shell
   history, journal, core, swap, temporary directory, or repository file
   contains a planted canary or credential marker. Remove the protected
   operational-capture list and canary input after recording only the scanner's
   fixed result/counts, then repeat the bounded absence check.
5. Confirm production service state and accepted recovery objects were not
   changed. Record cleanup as complete only after an independent second check.

A cleanup failure keeps the drill status failed or pending. File unlink is not
evidence of physical-media erasure; report only logical cleanup within the
tested storage boundary.
