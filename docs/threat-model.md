# Threat model

The system will defend against unauthorized clients, stolen credentials,
cross-installation relay routing, malicious ingress payloads, prompt injection,
stale concurrent updates, archive tampering, private-seed leakage, and host or
database loss.

Security work is incomplete until each trust boundary has abuse cases,
mitigations, automated tests, and revocation procedures.

## Database runtime credentials

Forced row-level security prevents accidental tenant access when the
transaction-local `scalevault.tenant_id` setting is absent or does not match a
row. Runtime roles are non-owners without `BYPASSRLS` or schema-creation rights.

The tenant setting is application-supplied, however, and PostgreSQL custom
settings are not an authentication mechanism. Compromise of a shared service
database credential can therefore select another tenant context allowed to
that service role. Treat such a credential as a service-wide secret, rotate it
on suspected disclosure, and do not describe row-level security as isolation
from a stolen runtime credential. Credential-scoped tenant isolation would
require distinct database roles or an independently authenticated database
context per tenant.
