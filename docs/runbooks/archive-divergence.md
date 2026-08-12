# Archive divergence and signer compromise

Any unexpected remote head, non-first-parent commit, merge, unsigned or
untrusted signature, manifest break, changed pinned host key, rollback against
the external anchor, or exporter checkpoint mismatch is a hard stop.

1. Stop `kivra-memory-archive-exporter.service`; keep PostgreSQL authoritative
   and other services unchanged unless compromise scope requires isolation.
2. Record only expected/observed head digests, signature result codes, manifest
   digest, checkpoint sequence, signer epoch, host-key fingerprint digest, and
   timestamps. Preserve local and remote histories read-only.
3. Determine whether the difference is unexported canonical progress, a
   rejected/non-fast-forward push, stale recovery copy, rollback, unauthorized
   writer, signer compromise, or transport/host-key substitution.
4. Do not fetch with `accept-new`, merge, reset, amend, rebase, force-push,
   delete refs, replace signatures, or move the external anchor.
5. Verify the canonical database/archive prefix relationship from a clean
   reader and the last independently accepted anchor. If neither side can be
   trusted, keep export disabled and initiate the security incident path.
6. Resume only through the accepted continuation/re-anchor or new-target
   policy, after signer and deploy-key posture are reviewed and an isolated
   restore proves the chosen history.

Signer compromise and deploy-key compromise are distinct. Revoking a deploy
key stops future pushes. Removing an archive signer can invalidate historical
recovery. Preserve the old trust decision and transition evidence; do not
silently bless old or new history.
