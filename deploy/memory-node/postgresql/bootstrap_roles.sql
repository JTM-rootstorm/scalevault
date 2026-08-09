-- ScaleVault PostgreSQL role, ownership, and least-privilege bootstrap.
--
-- Run this file as a PostgreSQL superuser while connected to the canonical
-- ScaleVault database. It is safe to run before migrations, after migrations,
-- and repeatedly. Credentials are provisioned separately and never belong in
-- this file.

\set ON_ERROR_STOP on

-- A database name must be supplied explicitly so an operator cannot apply the
-- ownership cutover to whichever database happens to be selected by defaults.
\if :{?expected_database}
\else
    DO $guard$
    BEGIN
        RAISE EXCEPTION 'expected_database psql variable is required; no changes were made'
            USING ERRCODE = '22023';
    END
    $guard$;
\endif

SELECT pg_catalog.current_database() = :'expected_database'
    AS scalevault_expected_database_matches
\gset
\if :scalevault_expected_database_matches
\else
    DO $guard$
    BEGIN
        RAISE EXCEPTION
            'connected database does not match expected_database; no changes were made'
            USING ERRCODE = '22023';
    END
    $guard$;
\endif

BEGIN;

DO $bootstrap$
DECLARE
    role_name text;
    login_role boolean;
BEGIN
    FOR role_name, login_role IN
        SELECT *
        FROM (VALUES
            ('kivra_memory_owner', false),
            ('kivra_memory_migrator', true),
            ('kivra_memory_credential_admin', true),
            ('kivra_memory_api', true),
            ('kivra_memory_policy', true),
            ('kivra_memory_genesis_importer', true),
            ('kivra_memory_worker', true),
            ('kivra_memory_purge', true),
            ('kivra_memory_ingress', true),
            ('kivra_memory_exporter', true)
        ) AS roles(name, can_login)
    LOOP
        IF NOT EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname = role_name) THEN
            EXECUTE format(
                'CREATE ROLE %I %s',
                role_name,
                CASE WHEN login_role THEN 'LOGIN' ELSE 'NOLOGIN' END
            );
        END IF;
    END LOOP;
END
$bootstrap$;

ALTER ROLE kivra_memory_owner
    NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOINHERIT NOBYPASSRLS;
ALTER ROLE kivra_memory_migrator
    LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOINHERIT NOBYPASSRLS;
ALTER ROLE kivra_memory_credential_admin
    LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOINHERIT NOBYPASSRLS;
ALTER ROLE kivra_memory_api
    LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOINHERIT NOBYPASSRLS;
ALTER ROLE kivra_memory_policy
    LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOINHERIT NOBYPASSRLS;
ALTER ROLE kivra_memory_genesis_importer
    LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOINHERIT NOBYPASSRLS;
ALTER ROLE kivra_memory_worker
    LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOINHERIT NOBYPASSRLS;
ALTER ROLE kivra_memory_purge
    LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOINHERIT NOBYPASSRLS;
ALTER ROLE kivra_memory_ingress
    LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOINHERIT NOBYPASSRLS;
ALTER ROLE kivra_memory_exporter
    LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOINHERIT NOBYPASSRLS;

REVOKE kivra_memory_owner FROM
    kivra_memory_credential_admin,
    kivra_memory_api,
    kivra_memory_policy,
    kivra_memory_genesis_importer,
    kivra_memory_worker,
    kivra_memory_purge,
    kivra_memory_ingress,
    kivra_memory_exporter;
REVOKE kivra_memory_migrator FROM
    kivra_memory_credential_admin,
    kivra_memory_api,
    kivra_memory_policy,
    kivra_memory_genesis_importer,
    kivra_memory_worker,
    kivra_memory_purge,
    kivra_memory_ingress,
    kivra_memory_exporter;
GRANT kivra_memory_owner TO kivra_memory_migrator
    WITH ADMIN FALSE, INHERIT FALSE, SET TRUE;

-- M1 created the database with kivra_memory_api as its owner. Transfer every
-- object that role owns in this database before removing its broad authority.
REASSIGN OWNED BY kivra_memory_api TO kivra_memory_owner;

DO $bootstrap$
BEGIN
    EXECUTE format(
        'ALTER DATABASE %I OWNER TO kivra_memory_owner',
        pg_catalog.current_database()
    );
    EXECUTE format(
        'ALTER ROLE kivra_memory_migrator IN DATABASE %I SET role = %L',
        pg_catalog.current_database(),
        'kivra_memory_owner'
    );
END
$bootstrap$;

ALTER SCHEMA public OWNER TO kivra_memory_owner;

DO $bootstrap$
BEGIN
    EXECUTE format(
        'REVOKE ALL ON DATABASE %I FROM PUBLIC',
        pg_catalog.current_database()
    );
    EXECUTE format(
        'GRANT CONNECT ON DATABASE %I TO kivra_memory_migrator, '
        'kivra_memory_credential_admin, '
        'kivra_memory_api, kivra_memory_worker, kivra_memory_ingress, '
        'kivra_memory_exporter, kivra_memory_policy, kivra_memory_purge, '
        'kivra_memory_genesis_importer',
        pg_catalog.current_database()
    );
END
$bootstrap$;

REVOKE ALL ON SCHEMA public FROM PUBLIC;
REVOKE ALL ON SCHEMA public FROM
    kivra_memory_credential_admin,
    kivra_memory_api,
    kivra_memory_policy,
    kivra_memory_genesis_importer,
    kivra_memory_worker,
    kivra_memory_purge,
    kivra_memory_ingress,
    kivra_memory_exporter;
GRANT USAGE ON SCHEMA public TO
    kivra_memory_migrator,
    kivra_memory_credential_admin,
    kivra_memory_api,
    kivra_memory_policy,
    kivra_memory_genesis_importer,
    kivra_memory_worker,
    kivra_memory_purge,
    kivra_memory_ingress,
    kivra_memory_exporter;

REVOKE ALL ON ALL TABLES IN SCHEMA public FROM
    kivra_memory_credential_admin,
    kivra_memory_api,
    kivra_memory_policy,
    kivra_memory_genesis_importer,
    kivra_memory_worker,
    kivra_memory_purge,
    kivra_memory_ingress,
    kivra_memory_exporter;
REVOKE ALL ON ALL SEQUENCES IN SCHEMA public FROM
    kivra_memory_credential_admin,
    kivra_memory_api,
    kivra_memory_policy,
    kivra_memory_genesis_importer,
    kivra_memory_worker,
    kivra_memory_purge,
    kivra_memory_ingress,
    kivra_memory_exporter;
REVOKE ALL ON ALL TABLES IN SCHEMA public FROM PUBLIC;
REVOKE ALL ON ALL SEQUENCES IN SCHEMA public FROM PUBLIC;

DO $bootstrap$
DECLARE
    table_name text;
BEGIN
    -- Every service can perform its own schema revision readiness check.
    IF pg_catalog.to_regclass('public.alembic_version') IS NOT NULL THEN
        EXECUTE
            'GRANT SELECT ON TABLE public.alembic_version TO '
            'kivra_memory_credential_admin, kivra_memory_api, '
            'kivra_memory_worker, kivra_memory_ingress, '
            'kivra_memory_exporter, kivra_memory_policy, '
            'kivra_memory_genesis_importer';
    END IF;

    -- Credential administration owns only distinguishable direct-private
    -- identity issuance and bearer lifecycle audit. It cannot read verifier
    -- material back, delete identity, or reach memory/event payload tables.
    IF pg_catalog.to_regclass('public.alembic_compatibility') IS NOT NULL THEN
        GRANT SELECT ON TABLE public.alembic_compatibility
            TO kivra_memory_credential_admin;
    END IF;
    IF pg_catalog.to_regclass('public.tenants') IS NOT NULL THEN
        GRANT SELECT (
            tenant_id,
            state
        ) ON TABLE public.tenants TO kivra_memory_credential_admin;
    END IF;
    IF pg_catalog.to_regclass('public.actors') IS NOT NULL THEN
        GRANT SELECT (
            tenant_id,
            actor_id,
            metadata
        ) ON TABLE public.actors TO kivra_memory_credential_admin;
        GRANT INSERT (
            actor_id,
            tenant_id,
            handle,
            display_name,
            kind,
            metadata,
            created_at
        ) ON TABLE public.actors TO kivra_memory_credential_admin;
    END IF;
    IF pg_catalog.to_regclass('public.clients') IS NOT NULL THEN
        GRANT SELECT (
            tenant_id,
            client_id,
            scopes,
            capability_profile
        ) ON TABLE public.clients TO kivra_memory_credential_admin;
        GRANT INSERT (
            client_id,
            tenant_id,
            public_id,
            display_name,
            kind,
            transport_kind,
            scopes,
            capability_profile,
            created_at
        ) ON TABLE public.clients TO kivra_memory_credential_admin;
    END IF;
    IF pg_catalog.to_regclass('public.transport_bindings') IS NOT NULL THEN
        GRANT INSERT (
            transport_binding_id,
            tenant_id,
            actor_id,
            client_id,
            transport_kind,
            disclosure_boundary,
            installation_id,
            authorized_operations,
            created_at,
            valid_until
        ) ON TABLE public.transport_bindings TO kivra_memory_credential_admin;
    END IF;
    -- These attribution and audit columns arrive in migration 0008. The
    -- bootstrap must remain safe at older revisions so it can establish the
    -- migration owner before Alembic advances the schema.
    IF pg_catalog.to_regclass('public.client_credentials') IS NOT NULL
       AND (
            SELECT count(*) = 4
            FROM pg_catalog.pg_attribute
            WHERE attrelid = pg_catalog.to_regclass('public.client_credentials')
              AND attname = ANY (ARRAY[
                  'actor_id',
                  'transport_binding_id',
                  'secret_hash_key_id',
                  'last_used_at'
              ])
              AND NOT attisdropped
       ) THEN
        GRANT SELECT (
            credential_id,
            tenant_id,
            actor_id,
            client_id,
            transport_binding_id,
            kind,
            public_hint,
            created_at,
            expires_at,
            last_used_at,
            revoked_at
        ) ON TABLE public.client_credentials TO kivra_memory_credential_admin;
        GRANT INSERT (
            credential_id,
            tenant_id,
            actor_id,
            client_id,
            transport_binding_id,
            kind,
            public_hint,
            secret_hash,
            secret_hash_key_id,
            created_at,
            expires_at
        ) ON TABLE public.client_credentials TO kivra_memory_credential_admin;
        GRANT UPDATE (
            revoked_at
        ) ON TABLE public.client_credentials TO kivra_memory_credential_admin;
    END IF;

    -- The API reads canonical state, appends events/receipts/outbox work,
    -- atomically stages live projections, and maintains sessions. Workers
    -- retain the broader rebuild and derived-state mutation privileges.
    FOREACH table_name IN ARRAY ARRAY[
        'alembic_compatibility', 'tenants', 'actors', 'clients',
        'client_credentials', 'transport_installations', 'transport_bindings',
        'personas', 'lineages', 'branches', 'sessions', 'subjects',
        'subject_aliases', 'ingress_items', 'memory_event_counter',
        'selection_decision_counter', 'selection_decisions',
        'memory_events', 'command_receipts', 'memories', 'memory_evidence',
        'memory_links', 'memory_conflicts', 'memory_conflict_members',
        'memory_content_keys', 'embedding_models', 'memory_embeddings_v1', 'outbox_jobs',
        'archive_targets', 'archive_export_checkpoints'
    ]
    LOOP
        IF pg_catalog.to_regclass(format('public.%I', table_name)) IS NOT NULL THEN
            EXECUTE format(
                'GRANT SELECT ON TABLE public.%I TO kivra_memory_api',
                table_name
            );
        END IF;
    END LOOP;
    FOREACH table_name IN ARRAY ARRAY[
        'memory_events', 'command_receipts', 'selection_decisions', 'outbox_jobs'
    ]
    LOOP
        IF pg_catalog.to_regclass(format('public.%I', table_name)) IS NOT NULL THEN
            EXECUTE format(
                'GRANT INSERT ON TABLE public.%I TO kivra_memory_api',
                table_name
            );
        END IF;
    END LOOP;
    IF pg_catalog.to_regclass('public.memory_evidence') IS NOT NULL THEN
        GRANT INSERT ON TABLE public.memory_evidence TO kivra_memory_api;
    END IF;
    IF pg_catalog.to_regclass('public.memory_content_keys') IS NOT NULL THEN
        GRANT INSERT ON TABLE public.memory_content_keys TO kivra_memory_api;
        GRANT UPDATE (
            state,
            destruction_requested_at
        ) ON TABLE public.memory_content_keys TO kivra_memory_api;
    END IF;
    IF pg_catalog.to_regclass('public.client_credentials') IS NOT NULL
       AND EXISTS (
            SELECT 1
            FROM pg_catalog.pg_attribute
            WHERE attrelid = pg_catalog.to_regclass('public.client_credentials')
              AND attname = 'last_used_at'
              AND NOT attisdropped
       ) THEN
        GRANT UPDATE (
            last_used_at
        ) ON TABLE public.client_credentials TO kivra_memory_api;
    END IF;
    FOREACH table_name IN ARRAY ARRAY[
        'memories', 'memory_links', 'memory_conflicts',
        'memory_conflict_members'
    ]
    LOOP
        IF pg_catalog.to_regclass(format('public.%I', table_name)) IS NOT NULL THEN
            EXECUTE format(
                'GRANT INSERT, UPDATE ON TABLE public.%I TO kivra_memory_api',
                table_name
            );
        END IF;
    END LOOP;
    IF pg_catalog.to_regclass('public.memory_event_counter') IS NOT NULL THEN
        GRANT UPDATE ON TABLE public.memory_event_counter TO kivra_memory_api;
    END IF;
    IF pg_catalog.to_regclass('public.selection_decision_counter') IS NOT NULL THEN
        GRANT UPDATE ON TABLE public.selection_decision_counter TO kivra_memory_api;
    END IF;
    IF pg_catalog.to_regclass('public.sessions') IS NOT NULL THEN
        GRANT INSERT, UPDATE ON TABLE public.sessions TO kivra_memory_api;
    END IF;
    IF pg_catalog.to_regclass('public.ingress_items') IS NOT NULL THEN
        GRANT UPDATE (
            state,
            result_event_id,
            result_memory_id,
            error_code,
            safe_diagnostic,
            processed_at
        ) ON TABLE public.ingress_items TO kivra_memory_api;
    END IF;

    -- Policy decisions use the same canonical event/projection transaction,
    -- but this role cannot read credentials, content keys, ingress provenance,
    -- embeddings, or archive state and cannot update immutable audit rows.
    FOREACH table_name IN ARRAY ARRAY[
        'alembic_compatibility', 'tenants', 'actors', 'clients',
        'transport_installations', 'transport_bindings', 'personas', 'lineages',
        'branches', 'sessions', 'subjects', 'memory_event_counter',
        'selection_decision_counter', 'memory_events', 'command_receipts',
        'selection_decisions', 'memories', 'memory_evidence', 'outbox_jobs'
    ]
    LOOP
        IF pg_catalog.to_regclass(format('public.%I', table_name)) IS NOT NULL THEN
            EXECUTE format(
                'GRANT SELECT ON TABLE public.%I TO kivra_memory_policy',
                table_name
            );
        END IF;
    END LOOP;
    FOREACH table_name IN ARRAY ARRAY[
        'memory_events', 'command_receipts', 'selection_decisions', 'outbox_jobs'
    ]
    LOOP
        IF pg_catalog.to_regclass(format('public.%I', table_name)) IS NOT NULL THEN
            EXECUTE format(
                'GRANT INSERT ON TABLE public.%I TO kivra_memory_policy',
                table_name
            );
        END IF;
    END LOOP;
    FOREACH table_name IN ARRAY ARRAY[
        'memories', 'memory_evidence'
    ]
    LOOP
        IF pg_catalog.to_regclass(format('public.%I', table_name)) IS NOT NULL THEN
            EXECUTE format(
                'GRANT INSERT, UPDATE ON TABLE public.%I TO kivra_memory_policy',
                table_name
            );
        END IF;
    END LOOP;
    IF pg_catalog.to_regclass('public.memory_event_counter') IS NOT NULL THEN
        GRANT UPDATE ON TABLE public.memory_event_counter TO kivra_memory_policy;
    END IF;
    IF pg_catalog.to_regclass('public.selection_decision_counter') IS NOT NULL THEN
        GRANT UPDATE ON TABLE public.selection_decision_counter TO kivra_memory_policy;
    END IF;
    IF pg_catalog.to_regclass('public.outbox_jobs') IS NOT NULL THEN
        GRANT UPDATE (
            state,
            lease_owner,
            lease_expires_at,
            attempt_count,
            available_at,
            updated_at,
            completed_at,
            last_error_code,
            last_error_summary
        ) ON TABLE public.outbox_jobs TO kivra_memory_policy;
    END IF;

    -- The pinned Genesis importer alone archives protected source provenance
    -- and participates in the ordinary selection transaction. Other runtime
    -- roles receive no privileges on Genesis relations.
    FOREACH table_name IN ARRAY ARRAY[
        'alembic_compatibility', 'tenants', 'actors', 'clients',
        'transport_installations', 'transport_bindings', 'personas', 'lineages',
        'branches', 'sessions', 'subjects', 'memory_event_counter',
        'selection_decision_counter', 'memory_events', 'command_receipts',
        'selection_decisions', 'memories', 'memory_evidence', 'outbox_jobs',
        'genesis_import_runs', 'genesis_import_sources', 'genesis_import_records',
        'genesis_import_exclusions', 'genesis_import_supersessions',
        'genesis_import_run_results'
    ]
    LOOP
        IF pg_catalog.to_regclass(format('public.%I', table_name)) IS NOT NULL THEN
            EXECUTE format(
                'GRANT SELECT ON TABLE public.%I TO kivra_memory_genesis_importer',
                table_name
            );
        END IF;
    END LOOP;
    FOREACH table_name IN ARRAY ARRAY[
        'memory_events', 'command_receipts', 'selection_decisions', 'outbox_jobs',
        'genesis_import_runs', 'genesis_import_sources', 'genesis_import_records',
        'genesis_import_exclusions', 'genesis_import_supersessions',
        'genesis_import_run_results'
    ]
    LOOP
        IF pg_catalog.to_regclass(format('public.%I', table_name)) IS NOT NULL THEN
            EXECUTE format(
                'GRANT INSERT ON TABLE public.%I TO kivra_memory_genesis_importer',
                table_name
            );
        END IF;
    END LOOP;
    FOREACH table_name IN ARRAY ARRAY['memories', 'memory_evidence']
    LOOP
        IF pg_catalog.to_regclass(format('public.%I', table_name)) IS NOT NULL THEN
            EXECUTE format(
                'GRANT INSERT ON TABLE public.%I '
                'TO kivra_memory_genesis_importer',
                table_name
            );
        END IF;
    END LOOP;
    IF pg_catalog.to_regclass('public.genesis_import_records') IS NOT NULL THEN
        GRANT UPDATE (
            processing_state,
            selection_decision_id,
            event_id,
            memory_id,
            processed_at
        ) ON TABLE public.genesis_import_records TO kivra_memory_genesis_importer;
    END IF;
    IF pg_catalog.to_regclass('public.memory_event_counter') IS NOT NULL THEN
        GRANT UPDATE ON TABLE public.memory_event_counter TO kivra_memory_genesis_importer;
    END IF;
    IF pg_catalog.to_regclass('public.selection_decision_counter') IS NOT NULL THEN
        GRANT UPDATE ON TABLE public.selection_decision_counter
            TO kivra_memory_genesis_importer;
    END IF;

    -- Workers read event/domain state and maintain ordinary derived state,
    -- embeddings, and outbox leases. Key destruction completion belongs only
    -- to the dedicated purge role below.
    FOREACH table_name IN ARRAY ARRAY[
        'alembic_compatibility', 'tenants', 'actors', 'clients',
        'transport_installations', 'transport_bindings', 'personas', 'lineages',
        'branches', 'sessions', 'subjects', 'subject_aliases', 'memory_events',
        'memories', 'memory_evidence', 'memory_links', 'memory_conflicts',
        'memory_conflict_members', 'memory_content_keys', 'embedding_models',
        'memory_embeddings_v1',
        'outbox_jobs', 'archive_targets', 'archive_export_checkpoints'
    ]
    LOOP
        IF pg_catalog.to_regclass(format('public.%I', table_name)) IS NOT NULL THEN
            EXECUTE format(
                'GRANT SELECT ON TABLE public.%I TO kivra_memory_worker',
                table_name
            );
        END IF;
    END LOOP;
    FOREACH table_name IN ARRAY ARRAY[
        'memories', 'memory_evidence', 'memory_links', 'memory_conflicts',
        'memory_conflict_members'
    ]
    LOOP
        IF pg_catalog.to_regclass(format('public.%I', table_name)) IS NOT NULL THEN
            EXECUTE format(
                'GRANT INSERT, UPDATE, DELETE ON TABLE public.%I TO kivra_memory_worker',
                table_name
            );
        END IF;
    END LOOP;
    FOREACH table_name IN ARRAY ARRAY['memory_embeddings_v1', 'outbox_jobs']
    LOOP
        IF pg_catalog.to_regclass(format('public.%I', table_name)) IS NOT NULL THEN
            EXECUTE format(
                'GRANT INSERT, UPDATE ON TABLE public.%I TO kivra_memory_worker',
                table_name
            );
        END IF;
    END LOOP;
    IF pg_catalog.to_regclass('public.memory_embeddings_v1') IS NOT NULL THEN
        GRANT DELETE ON TABLE public.memory_embeddings_v1 TO kivra_memory_worker;
    END IF;
    IF pg_catalog.to_regclass('public.branches') IS NOT NULL THEN
        GRANT INSERT ON TABLE public.branches TO kivra_memory_worker;
    END IF;

    -- Hard-forget key destruction uses a separate exact-scope worker. It can
    -- append only the purge-completion event/outbox record, update the one
    -- projection and key lifecycle, and remove the forgotten embedding.
    FOREACH table_name IN ARRAY ARRAY[
        'actors', 'clients',
        'transport_installations', 'transport_bindings', 'branches',
        'memory_event_counter', 'memory_events', 'memories',
        'memory_content_keys', 'outbox_jobs'
    ]
    LOOP
        IF pg_catalog.to_regclass(format('public.%I', table_name)) IS NOT NULL THEN
            EXECUTE format(
                'GRANT SELECT ON TABLE public.%I TO kivra_memory_purge',
                table_name
            );
        END IF;
    END LOOP;
    FOREACH table_name IN ARRAY ARRAY['memory_events', 'outbox_jobs']
    LOOP
        IF pg_catalog.to_regclass(format('public.%I', table_name)) IS NOT NULL THEN
            EXECUTE format(
                'GRANT INSERT ON TABLE public.%I TO kivra_memory_purge',
                table_name
            );
        END IF;
    END LOOP;
    IF pg_catalog.to_regclass('public.memory_event_counter') IS NOT NULL THEN
        GRANT UPDATE ON TABLE public.memory_event_counter TO kivra_memory_purge;
    END IF;
    IF pg_catalog.to_regclass('public.memories') IS NOT NULL THEN
        GRANT UPDATE (
            revision,
            content_protection,
            updated_at,
            last_event_id
        ) ON TABLE public.memories TO kivra_memory_purge;
    END IF;
    IF pg_catalog.to_regclass('public.memory_content_keys') IS NOT NULL THEN
        GRANT UPDATE (
            state,
            destroyed_at,
            destruction_receipt_sha256
        ) ON TABLE public.memory_content_keys TO kivra_memory_purge;
    END IF;
    IF pg_catalog.to_regclass('public.memory_embeddings_v1') IS NOT NULL THEN
        GRANT SELECT (
            tenant_id,
            memory_id
        ) ON TABLE public.memory_embeddings_v1 TO kivra_memory_purge;
        GRANT DELETE ON TABLE public.memory_embeddings_v1 TO kivra_memory_purge;
    END IF;
    IF pg_catalog.to_regclass('public.outbox_jobs') IS NOT NULL THEN
        GRANT UPDATE (
            state,
            lease_owner,
            lease_expires_at,
            attempt_count,
            available_at,
            updated_at,
            completed_at,
            last_error_code,
            last_error_summary
        ) ON TABLE public.outbox_jobs TO kivra_memory_purge;
    END IF;

    -- Ingress discovers and validates immutable external proposals. The API is
    -- the only runtime role that can accept them through the canonical event
    -- path and publish result identifiers.
    FOREACH table_name IN ARRAY ARRAY[
        'alembic_compatibility', 'tenants', 'actors', 'clients',
        'transport_installations', 'transport_bindings', 'branches', 'sessions',
        'ingress_items', 'ingress_provider_violations'
    ]
    LOOP
        IF pg_catalog.to_regclass(format('public.%I', table_name)) IS NOT NULL THEN
            EXECUTE format(
                'GRANT SELECT ON TABLE public.%I TO kivra_memory_ingress',
                table_name
            );
        END IF;
    END LOOP;
    IF pg_catalog.to_regclass('public.ingress_items') IS NOT NULL THEN
        GRANT INSERT (
            ingress_id,
            tenant_id,
            transport_binding_id,
            installation_id,
            actor_id,
            client_id,
            provider,
            repository_external_id,
            branch_name,
            immutable_path,
            external_object_id,
            commit_id,
            blob_id,
            discovered_at
        ) ON TABLE public.ingress_items TO kivra_memory_ingress;
        GRANT UPDATE (
            state,
            declared_idempotency_key,
            payload_sha256,
            error_code,
            safe_diagnostic,
            validated_at,
            processed_at
        ) ON TABLE public.ingress_items TO kivra_memory_ingress;
    END IF;
    IF pg_catalog.to_regclass('public.ingress_provider_violations') IS NOT NULL THEN
        GRANT INSERT (
            tenant_id,
            ingress_id,
            violation_code,
            expected_provenance_sha256,
            observed_provenance_sha256
        ) ON TABLE public.ingress_provider_violations TO kivra_memory_ingress;
    END IF;

    -- Export is read-only except for its append-only checkpoint ledger.
    FOREACH table_name IN ARRAY ARRAY[
        'alembic_compatibility', 'tenants', 'actors', 'clients',
        'transport_installations', 'transport_bindings', 'personas', 'lineages',
        'branches', 'sessions', 'subjects', 'subject_aliases',
        'genesis_import_runs', 'genesis_import_sources',
        'genesis_import_exclusions', 'genesis_import_records',
        'genesis_import_supersessions', 'genesis_import_run_results',
        'ingress_items', 'ingress_provider_violations', 'memory_events',
        'command_receipts', 'memories',
        'memory_evidence', 'memory_links', 'memory_conflicts',
        'memory_conflict_members', 'selection_decisions', 'memory_content_keys',
        'archive_targets', 'archive_export_checkpoints'
    ]
    LOOP
        IF pg_catalog.to_regclass(format('public.%I', table_name)) IS NOT NULL THEN
            EXECUTE format(
                'GRANT SELECT ON TABLE public.%I TO kivra_memory_exporter',
                table_name
            );
        END IF;
    END LOOP;
    IF pg_catalog.to_regclass('public.archive_export_checkpoints') IS NOT NULL THEN
        GRANT INSERT ON TABLE public.archive_export_checkpoints TO kivra_memory_exporter;
        GRANT UPDATE (
            state,
            git_commit_sha,
            remote_git_commit_sha,
            committed_at,
            pushed_at
        ) ON TABLE public.archive_export_checkpoints TO kivra_memory_exporter;
    END IF;

END
$bootstrap$;

-- Column privileges keep result identifiers in the API boundary. This trigger
-- also prevents the ingress login from manufacturing an accepted or otherwise
-- processed state through its validation-state column grant.
SET ROLE kivra_memory_owner;
CREATE OR REPLACE FUNCTION public.scalevault_enforce_ingress_validation_write()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog
AS $function$
BEGIN
    IF CURRENT_USER = 'kivra_memory_ingress' THEN
        IF NOT (
            (OLD.state = 'discovered' AND NEW.state IN (
                'discovered', 'validated', 'rejected', 'quarantined'
            ))
            OR (OLD.state = 'validated' AND NEW.state IN (
                'validated', 'rejected', 'quarantined'
            ))
            OR (OLD.state = 'rejected' AND NEW.state = 'rejected')
            OR (OLD.state = 'quarantined' AND NEW.state = 'quarantined')
        ) THEN
            RAISE EXCEPTION 'ingress role cannot perform canonical processing transition'
                USING ERRCODE = '42501';
        END IF;
        IF NEW.state IN ('rejected', 'quarantined') AND NEW.processed_at IS NULL THEN
            RAISE EXCEPTION 'terminal ingress validation state requires processed_at'
                USING ERRCODE = '23514';
        END IF;
    END IF;
    RETURN NEW;
END
$function$;
RESET ROLE;

DO $bootstrap$
BEGIN
    IF pg_catalog.to_regclass('public.ingress_items') IS NOT NULL THEN
        -- PostgreSQL fires triggers for the same event in name order. Keep the
        -- role authorization barrier ahead of the generic lifecycle barrier
        -- so an ingress-role acceptance attempt fails as an authorization
        -- error even when its result shape is also invalid.
        EXECUTE
            'DROP TRIGGER IF EXISTS trg_ingress_items_validation_write '
            'ON public.ingress_items';
        EXECUTE
            'DROP TRIGGER IF EXISTS trg_ingress_items_00_validation_write '
            'ON public.ingress_items';
        EXECUTE
            'CREATE TRIGGER trg_ingress_items_00_validation_write '
            'BEFORE UPDATE ON public.ingress_items '
            'FOR EACH ROW '
            'EXECUTE FUNCTION public.scalevault_enforce_ingress_validation_write()';
    END IF;
END
$bootstrap$;

DO $bootstrap$
DECLARE
    function_signature text;
    runtime_role text;
BEGIN
    FOREACH function_signature IN ARRAY ARRAY[
        'scalevault_is_uuid_v7(uuid)',
        'scalevault_reject_immutable_mutation()',
        'scalevault_reject_immutable_field_mutation()',
        'scalevault_enforce_branch_visibility()',
        'scalevault_enforce_client_credential_lifecycle()',
        'scalevault_enforce_content_key_lifecycle()',
        'scalevault_enforce_event_ingress_provenance()',
        'scalevault_enforce_ingress_validation_write()',
        'scalevault_enforce_genesis_record_terminalization()',
        'scalevault_enforce_genesis_run_completion()'
    ]
    LOOP
        IF pg_catalog.to_regprocedure('public.' || function_signature) IS NOT NULL THEN
            EXECUTE format(
                'REVOKE ALL ON FUNCTION public.%s FROM PUBLIC, '
                'kivra_memory_credential_admin, kivra_memory_api, '
                'kivra_memory_worker, kivra_memory_ingress, '
                'kivra_memory_exporter, kivra_memory_policy, kivra_memory_purge, '
                'kivra_memory_genesis_importer',
                function_signature
            );
        END IF;
    END LOOP;

    -- UUIDv7 is a CHECK helper, not a general RPC surface. Trigger functions
    -- remain executable only through their installed triggers.
    FOREACH runtime_role IN ARRAY ARRAY[
        'kivra_memory_credential_admin', 'kivra_memory_api',
        'kivra_memory_worker', 'kivra_memory_ingress',
        'kivra_memory_exporter', 'kivra_memory_policy', 'kivra_memory_purge',
        'kivra_memory_genesis_importer'
    ]
    LOOP
        IF pg_catalog.to_regprocedure('public.scalevault_is_uuid_v7(uuid)') IS NOT NULL THEN
            EXECUTE format(
                'GRANT EXECUTE ON FUNCTION public.scalevault_is_uuid_v7(uuid) TO %I',
                runtime_role
            );
        END IF;
    END LOOP;
END
$bootstrap$;

-- Outbox insertion is the only current use of a generated sequence. Resolve
-- its actual sequence name instead of assuming a naming convention.
DO $bootstrap$
DECLARE
    sequence_name text;
BEGIN
    IF pg_catalog.to_regclass('public.outbox_jobs') IS NOT NULL THEN
        sequence_name := pg_catalog.pg_get_serial_sequence(
            'public.outbox_jobs',
            'job_id'
        );
    END IF;
    IF sequence_name IS NOT NULL THEN
        EXECUTE format(
            'GRANT USAGE ON SEQUENCE %s TO '
            'kivra_memory_api, kivra_memory_worker, kivra_memory_purge',
            sequence_name
        );
        EXECUTE format(
            'GRANT USAGE ON SEQUENCE %s TO kivra_memory_policy',
            sequence_name
        );
        EXECUTE format(
            'GRANT USAGE ON SEQUENCE %s TO kivra_memory_genesis_importer',
            sequence_name
        );
    END IF;
END
$bootstrap$;

SET ROLE kivra_memory_owner;
ALTER DEFAULT PRIVILEGES IN SCHEMA public REVOKE ALL ON TABLES FROM PUBLIC;
ALTER DEFAULT PRIVILEGES IN SCHEMA public REVOKE ALL ON SEQUENCES FROM PUBLIC;
ALTER DEFAULT PRIVILEGES IN SCHEMA public REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC;
RESET ROLE;

COMMIT;
