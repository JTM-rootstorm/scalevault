\set ON_ERROR_STOP on

\if :{?tenant_id}
\else
\prompt 'Authorized tenant UUIDv7: ' tenant_id
\endif

BEGIN;
SET LOCAL ROLE kivra_memory_owner;

SELECT
    pg_catalog.current_database() = 'kivra_memory' AS database_ok,
    public.scalevault_is_uuid_v7(:'tenant_id'::uuid) AS tenant_ok
\gset binding_
\if :binding_database_ok
\else
\error 'observability binding must target kivra_memory'
\endif
\if :binding_tenant_ok
\else
\error 'observability tenant binding requires UUIDv7'
\endif

INSERT INTO public.observability_tenant_bindings (login_role, tenant_id)
VALUES
    ('kivra_memory_metrics', :'tenant_id'::uuid),
    ('kivra_memory_operator_report_login', :'tenant_id'::uuid)
ON CONFLICT (login_role) DO UPDATE
SET tenant_id = EXCLUDED.tenant_id;

COMMIT;
