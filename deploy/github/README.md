# GitHub proposal fallback

This directory contains the non-secret, disabled configuration contract for
the optional ChatGPT GitHub proposal fallback. It does not contain a GitHub
credential, connector implementation, or live activation.

The only supported target is the private
`JTM-rootstorm/scalevault-memory-ingress` repository on branch `main`. The
numeric repository identity is exactly `1322346959`. Before every create or
duplicate read, the connector must resolve `GET /repositories/1322346959` and
require that exact ID, full name, and default branch; a same-name replacement,
rename, transfer, or branch change fails before the create-file `PUT` or read.
The create request never supplies a blob `sha`, so it cannot update a path. The
history verifier starts at commit
`84233835924ade0e3cf26bb995717c880c75ff5c` and tree
`2de813150fe3952e6538abc5db9c2254d835a70e`. Changing any target or bootstrap
identity requires a reviewed contract change.

The caller validates the exact proposal-v2 bytes before submitting one
create-only request. The deterministic path is derived from the proposal's
installation UUIDv7, UTC creation month, and proposal UUIDv7. A successful
create is exactly HTTP `201`. HTTP `409` and `422` are ambiguous duplicates:
the adapter reads that exact path and accepts it only when the bytes match.
A transport exception or timeout returns `github_create_ambiguous`; callers
may retry only the same proposal bytes, which reproduce the same ingress ID,
path, and request body. Provider exceptions and safe errors must never include
the proposal bytes.

Keep `enabled = false` until all of these activation gates are recorded:

- the target account exposes and re-probes an approved create-file action;
- the GitHub installation UUIDv7 is pinned;
- provider and Memory Node credentials are installed outside this file;
- migration `0010_ingress_provider_heads` and its role grants are active;
- the worker validates the full additive first-parent history before fetching
  proposal content; and
- the synthetic duplicate/concurrency acceptance gate passes without canonical
  promotion from a single GitHub source.

GitHub is a third-party transport. Only non-sensitive proposals with explicit
approval may use this fallback.
