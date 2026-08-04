# Development PostgreSQL

The development Compose profile runs PostgreSQL 17 with pgvector using the
credentials in the repository's `.env.example` file. These credentials are for
loopback-only development and must not be reused in another environment.

Start the database and wait for its health check:

```bash
docker compose -f deploy/development/compose.yaml up -d --wait
```

The named volume intentionally preserves developer data across ordinary
container restarts. To dispose of both the container and all database data:

```bash
docker compose -f deploy/development/compose.yaml down --volumes --remove-orphans
```

The integration tests do not use this persistent volume. When local PostgreSQL
binaries are installed, they create an isolated cluster under the system
temporary directory, select a run-scoped port, and remove the cluster after
each test. Set `SCALEVAULT_TEST_PG_BINDIR` to a PostgreSQL `bin` directory when
the intended PostgreSQL 17-or-newer tools are not first on `PATH`.
