# Archive divergence and signer compromise

Any unexpected remote head, non-first-parent commit, merge, unsigned or
untrusted signature, manifest break, changed pinned host key, rollback against
the external anchor, or exporter checkpoint mismatch is a hard stop.

1. Stop `kivra-memory-archive-exporter.service`; keep PostgreSQL authoritative
   and other services unchanged unless compromise scope requires isolation.
2. Record only expected/observed heads, signature result codes, manifest
   digest, checkpoint sequence, signer epoch ID, public-key fingerprint,
   transition-record ID, host-key fingerprint digest, and timestamps. Preserve
   local and remote histories plus external trust evidence read-only.
3. Determine whether the difference is unexported canonical progress, a
   rejected/non-fast-forward push, stale recovery copy, rollback, unauthorized
   writer, signer compromise, or transport/host-key substitution.
4. Do not fetch with `accept-new`, merge, reset, amend, rebase, force-push,
   delete refs, replace signatures, or move the external anchor.
5. Verify the canonical database/archive prefix relationship from a clean
   reader and the last independently accepted anchor. If neither side can be
   trusted, keep export disabled and initiate the security incident path.
6. Resume only through `continue-new-target` after signer and deploy-key posture
   are reviewed and an isolated restore proves the chosen history. Existing-
   target re-anchor is absent and forbidden.

Signer compromise and deploy-key compromise are distinct. Revoking a deploy
key stops future pushes. Removing an archive signer can invalidate historical
recovery. For a planned change, preserve the canonical
`scalevault-archive-transition-v1` record and both old/new detached signatures;
the record binds the target, epochs/fingerprints, exact old head/sequence, first
new sequence, and transition ID. For compromise, freeze an independently
anchored exact last-accepted commit/sequence cutoff and reject every later
commit from that signer. An emergency successor needs an independent trust
update; a transition signed only by the compromised key is insufficient.
