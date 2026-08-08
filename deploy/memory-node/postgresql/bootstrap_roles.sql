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
            ('kivra_memory_api', true),
            ('kivra_memory_worker', true),
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
ALTER ROLE kivra_memory_api
    LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOINHERIT NOBYPASSRLS;
ALTER ROLE kivra_memory_worker
    LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOINHERIT NOBYPASSRLS;
ALTER ROLE kivra_memory_ingress
    LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOINHERIT NOBYPASSRLS;
ALTER ROLE kivra_memory_exporter
    LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOINHERIT NOBYPASSRLS;

REVOKE kivra_memory_owner FROM
    kivra_memory_api,
    kivra_memory_worker,
    kivra_memory_ingress,
    kivra_memory_exporter;
REVOKE kivra_memory_migrator FROM
    kivra_memory_api,
    kivra_memory_worker,
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
        'kivra_memory_api, kivra_memory_worker, kivra_memory_ingress, '
        'kivra_memory_exporter',
        pg_catalog.current_database()
    );
END
$bootstrap$;

REVOKE ALL ON SCHEMA public FROM PUBLIC;
REVOKE ALL ON SCHEMA public FROM
    kivra_memory_api,
    kivra_memory_worker,
    kivra_memory_ingress,
    kivra_memory_exporter;
GRANT USAGE ON SCHEMA public TO
    kivra_memory_migrator,
    kivra_memory_api,
    kivra_memory_worker,
    kivra_memory_ingress,
    kivra_memory_exporter;

REVOKE ALL ON ALL TABLES IN SCHEMA public FROM
    kivra_memory_api,
    kivra_memory_worker,
    kivra_memory_ingress,
    kivra_memory_exporter;
REVOKE ALL ON ALL SEQUENCES IN SCHEMA public FROM
    kivra_memory_api,
    kivra_memory_worker,
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
            'kivra_memory_api, kivra_memory_worker, kivra_memory_ingress, '
            'kivra_memory_exporter';
    END IF;

    -- The API reads canonical state, appends events/receipts/outbox work,
    -- atomically stages live projections, and maintains sessions. Workers
    -- retain the broader rebuild and derived-state mutation privileges.
    FOREACH table_name IN ARRAY ARRAY[
        'alembic_compatibility', 'tenants', 'actors', 'clients',
        'client_credentials', 'transport_installations', 'transport_bindings',
        'personas', 'lineages', 'branches', 'sessions', 'subjects',
        'subject_aliases', 'ingress_items', 'memory_event_counter',
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
    FOREACH table_name IN ARRAY ARRAY['memory_events', 'command_receipts', 'outbox_jobs']
    LOOP
        IF pg_catalog.to_regclass(format('public.%I', table_name)) IS NOT NULL THEN
            EXECUTE format(
                'GRANT INSERT ON TABLE public.%I TO kivra_memory_api',
                table_name
            );
        END IF;
    END LOOP;
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

    -- Workers read event/domain state and exclusively maintain derived state,
    -- key-destruction metadata, embeddings, and outbox leases.
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
        'memory_conflict_members', 'memory_content_keys'
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

    -- Ingress discovers and validates immutable external proposals. The API is
    -- the only runtime role that can accept them through the canonical event
    -- path and publish result identifiers.
    FOREACH table_name IN ARRAY ARRAY[
        'alembic_compatibility', 'tenants', 'actors', 'clients',
        'transport_installations', 'transport_bindings', 'branches', 'sessions',
        'ingress_items'
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
            declared_idempotency_key,
            payload_sha256
        ) ON TABLE public.ingress_items TO kivra_memory_ingress;
        GRANT UPDATE (
            state,
            error_code,
            safe_diagnostic,
            validated_at,
            processed_at
        ) ON TABLE public.ingress_items TO kivra_memory_ingress;
    END IF;

    -- Export is read-only except for its append-only checkpoint ledger.
    FOREACH table_name IN ARRAY ARRAY[
        'alembic_compatibility', 'tenants', 'lineages', 'branches', 'subjects',
        'memory_events', 'memories', 'memory_evidence', 'memory_links',
        'memory_conflicts', 'memory_conflict_members', 'archive_targets',
        'archive_export_checkpoints'
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
        'scalevault_enforce_event_ingress_provenance()',
        'scalevault_enforce_ingress_validation_write()'
    ]
    LOOP
        IF pg_catalog.to_regprocedure('public.' || function_signature) IS NOT NULL THEN
            EXECUTE format(
                'REVOKE ALL ON FUNCTION public.%s FROM PUBLIC, '
                'kivra_memory_api, kivra_memory_worker, kivra_memory_ingress, '
                'kivra_memory_exporter',
                function_signature
            );
        END IF;
    END LOOP;

    -- UUIDv7 is a CHECK helper, not a general RPC surface. Trigger functions
    -- remain executable only through their installed triggers.
    FOREACH runtime_role IN ARRAY ARRAY[
        'kivra_memory_api', 'kivra_memory_worker', 'kivra_memory_ingress',
        'kivra_memory_exporter'
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
            'GRANT USAGE ON SEQUENCE %s TO kivra_memory_api, kivra_memory_worker',
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
