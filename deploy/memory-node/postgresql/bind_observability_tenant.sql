\set ON_ERROR_STOP on

\if :{?expected_database}
\else
    DO $guard$
    BEGIN
        RAISE EXCEPTION 'expected_database psql variable is required; no changes were made'
            USING ERRCODE = '22023';
    END
    $guard$;
\endif

\if :{?tenant_id}
\else
\prompt 'Authorized tenant UUIDv7: ' tenant_id
\endif

BEGIN;
SET LOCAL ROLE kivra_memory_owner;

SELECT
    pg_catalog.current_database() = :'expected_database' AS database_ok,
    public.scalevault_is_uuid_v7(:'tenant_id'::uuid) AS tenant_ok
\gset binding_
\if :binding_database_ok
\else
    DO $guard$
    BEGIN
        RAISE EXCEPTION 'observability binding must target expected_database'
            USING ERRCODE = '22023';
    END
    $guard$;
\endif
\if :binding_tenant_ok
\else
    DO $guard$
    BEGIN
        RAISE EXCEPTION 'observability tenant binding requires UUIDv7'
            USING ERRCODE = '22023';
    END
    $guard$;
\endif

INSERT INTO public.observability_tenant_bindings (login_role, tenant_id)
VALUES
    ('kivra_memory_metrics', :'tenant_id'::uuid),
    ('kivra_memory_operator_report_login', :'tenant_id'::uuid)
ON CONFLICT (login_role) DO UPDATE
SET tenant_id = EXCLUDED.tenant_id;

COMMIT;
