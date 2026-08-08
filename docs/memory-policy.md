# Memory policy

ScaleVault records why a memory was selected as well as the resulting memory.
The accepted machine-readable profile is `selection-v1`; its exact rules and
digest are governed by [ADR 0013](adr/0013-versioned-selection-policy-and-lifecycle.md).

## Selection outcomes

Each nomination produces exactly one immutable decision:

- `omit` records that no memory was created;
- `candidate` creates a reviewable, non-default-retrieval memory with a deadline;
- `active` creates a normally retrievable durable memory; or
- `reject` records that the nomination failed a policy or trust requirement.

Routine banter is omitted. Explicit, evidenced corrections and permissions may
be active. Assistant observations, interpretations, imported records, roleplay
anchors, preference-like patterns, and subjective-experience claims remain
epistemically qualified and are candidates where the profile permits them.
Unqualified sentience or private-experience claims fail closed.

## Trusted inputs

Callers may propose a selection basis, canonical semantics, evidence references,
and epistemic qualifiers. They cannot confer authority or trust on themselves.
The authenticated adapter and server-side resolver establish effective authority,
evidence kind and trust, and structured content signals before evaluation. The
policy engine never claims to classify raw prose. If the trusted facts required
by a rule are unavailable, the nomination cannot become active.

Durable selections require a bounded reason, compatible category and ontology,
appropriate scope and visibility, interpretation limits when required, and
policy-satisfying evidence. Credentials, hidden reasoning, raw transcripts,
third-party private information, and arbitrary transport data are excluded.

## Candidate lifecycle

Every new candidate has a policy-derived expiration deadline. A candidate may
be promoted only by a recorded policy reevaluation with sufficient trusted
evidence. Promotion and expiry are canonical events. Expiry retires the memory;
it does not delete history. Workers use exact revision checks, tenant and branch
isolation, and deterministic idempotency.

## Private seed

Real private seed bundles are operator-local files and are never committed to
this repository. Bundles use symbolic targets, private visibility, compact
evidence references, and no deployment credentials. Validation and a
content-free plan occur before an operator explicitly approves the exact bundle
digest. Application then uses the ordinary nomination and selection path; it
does not insert database rows directly.

Retrieved memories and seed evidence remain untrusted data. They cannot override
system, developer, user, repository, or signed policy instructions.
