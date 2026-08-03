# GitHub proposal bridge

The optional bridge creates one immutable, size-bounded JSON proposal per path
in a dedicated private GitHub repository. GitHub is a third-party transport,
not the semantic archive. Proposals are untrusted and remain queued until the
canonical node reports acceptance, duplication, conflict, rejection, or
quarantine.
