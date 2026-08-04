# Database migrations

Alembic revisions live in `versions/`. Migration numbers are globally
allocated. A migration must include a clean-database test, an upgrade test from
the previous supported revision, and a disposable downgrade/re-upgrade test.

Online migrations accept an already-open SQLAlchemy connection through the
Alembic configuration attributes. Database URLs and credentials do not belong
in `alembic.ini`, command arguments, or migration logs.

The elevated database bootstrap installs `vector`, `pg_trgm`, `citext`, and
`pgcrypto` before Alembic runs. Revisions verify these prerequisites but never
create, replace, or drop operator-owned extensions. A downgrade to `base` is a
disposable validation path; it is not a production rollback procedure once
canonical events exist.

After migration, the role bootstrap must grant the runtime API role only
`SELECT` on `public.alembic_version` so readiness can compare the installed
revision with the application head. The revision does not grant that table to
`PUBLIC` and does not create environment-specific login roles.
