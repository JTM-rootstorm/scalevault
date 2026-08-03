# Database migrations

Alembic revisions live in `versions/`. The initial domain migration will be
added after the ontology, identity model, and event contracts are frozen.

Migration numbers are globally allocated. A migration must include a clean
database test and an upgrade test from the previous supported revision.
