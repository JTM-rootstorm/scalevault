"""Add payload-blind observability and protected operator-report functions.

Revision ID: 0011_observability_aggregates
Revises: 0010_ingress_provider_heads
Create Date: 2026-08-12
"""

# ruff: noqa: E501 -- SQL function bodies remain contiguous for migration review.

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0011_observability_aggregates"
down_revision: str | None = "0010_ingress_provider_heads"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


_FUNCTIONS: tuple[str, ...] = (
    "scalevault_observability_snapshot(uuid)",
    "scalevault_operator_report_selection(uuid,timestamp with time zone,integer)",
    "scalevault_operator_report_writes(uuid,timestamp with time zone,integer)",
    "scalevault_operator_report_conflicts(uuid,integer)",
    "scalevault_operator_report_memories(uuid,integer)",
    "scalevault_operator_report_branches(uuid,integer)",
    "scalevault_operator_report_credentials(uuid,timestamp with time zone,integer)",
    "scalevault_operator_report_queues(uuid,integer)",
    "scalevault_operator_report_archive(uuid,integer)",
    "scalevault_operator_report_consistency(uuid)",
)


def _create_function(signature: str, returns: str, body: str) -> None:
    op.execute(
        sa.text(
            f"CREATE FUNCTION public.{signature} RETURNS TABLE ({returns}) "
            "LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog "
            f"AS $function$ BEGIN {body} END $function$"
        )
    )


def _scope() -> str:
    return (
        "IF pg_catalog.current_setting('scalevault.tenant_id', true) "
        "IS DISTINCT FROM p_tenant_id::text THEN "
        "RAISE EXCEPTION 'tenant scope mismatch' USING ERRCODE = '42501'; END IF; "
        "IF NOT EXISTS (SELECT 1 FROM public.observability_tenant_bindings AS binding "
        "WHERE binding.login_role = SESSION_USER::name "
        "AND binding.tenant_id = p_tenant_id) THEN "
        "RAISE EXCEPTION 'tenant binding mismatch' USING ERRCODE = '42501'; END IF; "
    )


def _limit() -> str:
    return (
        "IF p_limit < 1 OR p_limit > 500 THEN "
        "RAISE EXCEPTION 'invalid operator report limit' USING ERRCODE = '22023'; END IF; "
    )


def upgrade() -> None:
    op.execute(
        sa.text(
            "CREATE TABLE public.observability_tenant_bindings ("
            "login_role name PRIMARY KEY, tenant_id uuid NOT NULL, "
            "CONSTRAINT tenant FOREIGN KEY (tenant_id) REFERENCES public.tenants(tenant_id) "
            "ON DELETE RESTRICT, CONSTRAINT fixed_login CHECK (login_role IN "
            "('kivra_memory_metrics'::name, 'kivra_memory_operator_report_login'::name)))"
        )
    )
    op.execute(sa.text("REVOKE ALL ON TABLE public.observability_tenant_bindings FROM PUBLIC"))
    _create_function(
        "scalevault_observability_snapshot(p_tenant_id uuid)",
        "metric_name text, label_one text, label_two text, label_three text, metric_value double precision",
        _scope() + "RETURN QUERY "
        "SELECT 'queue_depth'::text, "
        "CASE WHEN job.job_type = 'embed_memory' THEN 'embedding' "
        "WHEN job.job_type = 'rebuild_projection' THEN 'projection' "
        "WHEN job.job_type = 'export_git_batch' THEN 'archive' "
        "WHEN job.job_type = 'purge_payload' THEN 'purge' "
        "WHEN job.job_type IN ('ingest_github_proposal','refresh_ingress_status') THEN 'github' "
        "ELSE 'lifecycle' END, job.state::text, NULL::text, count(*)::double precision "
        "FROM public.outbox_jobs AS job WHERE job.tenant_id = p_tenant_id "
        "AND job.state IN ('pending','leased','dead') GROUP BY 2, job.state "
        "UNION ALL SELECT 'queue_oldest_age', "
        "CASE WHEN job.job_type = 'embed_memory' THEN 'embedding' "
        "WHEN job.job_type = 'rebuild_projection' THEN 'projection' "
        "WHEN job.job_type = 'export_git_batch' THEN 'archive' "
        "WHEN job.job_type = 'purge_payload' THEN 'purge' "
        "WHEN job.job_type IN ('ingest_github_proposal','refresh_ingress_status') THEN 'github' "
        "ELSE 'lifecycle' END, NULL::text, NULL::text, "
        "greatest(0, pg_catalog.extract(epoch FROM "
        "(pg_catalog.clock_timestamp() - min(job.available_at))))::double precision "
        "FROM public.outbox_jobs AS job WHERE job.tenant_id = p_tenant_id "
        "AND job.state IN ('pending','leased','dead') GROUP BY 2 "
        "UNION ALL SELECT 'credential_count', "
        "CASE client.transport_kind WHEN 'direct_private' THEN 'direct_private' "
        "WHEN 'secure_tunnel' THEN 'secure_tunnel' WHEN 'github_ingress' THEN 'github' "
        "ELSE 'service' END, "
        "CASE WHEN credential.expires_at IS NULL THEN 'none' "
        "WHEN credential.expires_at <= pg_catalog.clock_timestamp() THEN 'expired' "
        "WHEN credential.expires_at <= pg_catalog.clock_timestamp() + interval '1 day' THEN 'le_1d' "
        "WHEN credential.expires_at <= pg_catalog.clock_timestamp() + interval '7 days' THEN 'le_7d' "
        "WHEN credential.expires_at <= pg_catalog.clock_timestamp() + interval '30 days' THEN 'le_30d' "
        "ELSE 'gt_30d' END, "
        "CASE WHEN credential.revoked_at IS NULL THEN 'active' ELSE 'revoked' END, "
        "count(*)::double precision FROM public.client_credentials AS credential "
        "JOIN public.clients AS client ON client.tenant_id = credential.tenant_id "
        "AND client.client_id = credential.client_id "
        "WHERE credential.tenant_id = p_tenant_id GROUP BY 2,3,4 "
        "UNION ALL SELECT 'archive_lag_events', stage.name, NULL::text, NULL::text, "
        "CASE stage.name WHEN 'source' THEN (SELECT count(*) FROM public.memory_events AS event "
        "WHERE event.tenant_id = p_tenant_id) ELSE (SELECT count(*) "
        "FROM public.memory_events AS event WHERE event.tenant_id = p_tenant_id "
        "AND event.event_sequence > pg_catalog.coalesce((SELECT max(checkpoint.last_event_sequence) "
        "FROM public.archive_export_checkpoints AS checkpoint "
        "WHERE checkpoint.tenant_id = p_tenant_id AND ((stage.name = 'export' "
        "AND checkpoint.state IN ('committed','pushed')) OR "
        "(stage.name = 'push' AND checkpoint.state = 'pushed'))), 0)) END::double precision "
        "FROM (VALUES ('source'::text),('export'::text),('push'::text)) AS stage(name);",
    )
    _create_function(
        "scalevault_operator_report_selection(p_tenant_id uuid, p_since timestamp with time zone, p_limit integer)",
        "period_start timestamp with time zone, actor_id uuid, client_id uuid, outcome text, count bigint",
        _limit()
        + _scope()
        + "RETURN QUERY SELECT pg_catalog.date_trunc('day', d.decided_at), d.actor_id, d.client_id, d.outcome::text, count(*) FROM public.selection_decisions AS d WHERE d.tenant_id = p_tenant_id AND d.decided_at >= p_since GROUP BY 1,2,3,4 ORDER BY 1 DESC,2,3,4 LIMIT p_limit;",
    )
    _create_function(
        "scalevault_operator_report_writes(p_tenant_id uuid, p_since timestamp with time zone, p_limit integer)",
        "client_id uuid, profile text, operation text, count bigint",
        _limit()
        + _scope()
        + "RETURN QUERY SELECT e.client_id, c.transport_kind::text, e.operation::text, count(*) FROM public.memory_events AS e JOIN public.clients AS c ON c.tenant_id=e.tenant_id AND c.client_id=e.client_id WHERE e.tenant_id=p_tenant_id AND e.created_at >= p_since GROUP BY 1,2,3 ORDER BY 4 DESC,1,3 LIMIT p_limit;",
    )
    _create_function(
        "scalevault_operator_report_conflicts(p_tenant_id uuid, p_limit integer)",
        "conflict_id uuid, lineage_id uuid, branch_id uuid, subject_id uuid, status text, opened_at timestamp with time zone",
        _limit()
        + _scope()
        + "RETURN QUERY SELECT c.conflict_id,c.lineage_id,c.branch_id,c.subject_id,c.status::text,c.opened_at FROM public.memory_conflicts AS c WHERE c.tenant_id=p_tenant_id AND c.status='open' ORDER BY c.opened_at DESC,c.conflict_id LIMIT p_limit;",
    )
    _create_function(
        "scalevault_operator_report_memories(p_tenant_id uuid, p_limit integer)",
        "memory_id uuid,lineage_id uuid,branch_id uuid,subject_id uuid,subject_kind text,category text,scope text,visibility text,status text,sensitivity smallint,content_protection text,revision integer,updated_at timestamp with time zone",
        _limit()
        + _scope()
        + "RETURN QUERY SELECT m.memory_id,m.lineage_id,m.branch_id,m.subject_id,m.subject_kind::text,m.category::text,m.scope::text,m.visibility::text,m.status::text,m.sensitivity,m.content_protection::text,m.revision,m.updated_at FROM public.memories AS m WHERE m.tenant_id=p_tenant_id AND (m.sensitivity>=3 OR m.visibility='public_seed' OR m.status IN ('candidate','retired','tombstoned')) ORDER BY m.updated_at DESC,m.memory_id LIMIT p_limit;",
    )
    _create_function(
        "scalevault_operator_report_branches(p_tenant_id uuid, p_limit integer)",
        "lineage_id uuid,branch_id uuid,parent_branch_id uuid,fork_event_sequence bigint,visibility_ceiling text,created_at timestamp with time zone,sealed_at timestamp with time zone",
        _limit()
        + _scope()
        + "RETURN QUERY SELECT b.lineage_id,b.branch_id,b.parent_branch_id,b.fork_event_sequence,b.visibility_ceiling::text,b.created_at,b.sealed_at FROM public.branches AS b WHERE b.tenant_id=p_tenant_id ORDER BY b.created_at DESC,b.branch_id LIMIT p_limit;",
    )
    _create_function(
        "scalevault_operator_report_credentials(p_tenant_id uuid, p_expiry_cutoff timestamp with time zone, p_limit integer)",
        "credential_id uuid,client_id uuid,profile text,kind text,expires_at timestamp with time zone,revoked_at timestamp with time zone",
        _limit()
        + _scope()
        + "RETURN QUERY SELECT credential.credential_id,credential.client_id,client.transport_kind::text,credential.kind::text,credential.expires_at,credential.revoked_at FROM public.client_credentials AS credential JOIN public.clients AS client ON client.tenant_id=credential.tenant_id AND client.client_id=credential.client_id WHERE credential.tenant_id=p_tenant_id AND (credential.revoked_at IS NOT NULL OR (credential.expires_at IS NOT NULL AND credential.expires_at <= p_expiry_cutoff)) ORDER BY credential.expires_at NULLS LAST,credential.credential_id LIMIT p_limit;",
    )
    _create_function(
        "scalevault_operator_report_queues(p_tenant_id uuid, p_limit integer)",
        "job_type text,state text,count bigint,oldest_available_at timestamp with time zone",
        _limit()
        + _scope()
        + "RETURN QUERY SELECT job.job_type::text,job.state::text,count(*),min(job.available_at) FROM public.outbox_jobs AS job WHERE job.tenant_id=p_tenant_id AND job.state IN ('pending','leased','dead') GROUP BY 1,2 ORDER BY 1,2 LIMIT p_limit;",
    )
    _create_function(
        "scalevault_operator_report_archive(p_tenant_id uuid, p_limit integer)",
        "archive_target_id uuid,target_state text,checkpoint_state text,last_event_sequence bigint,last_pushed_at timestamp with time zone,failed_count bigint",
        _limit()
        + _scope()
        + "RETURN QUERY SELECT target.archive_target_id,target.state::text,checkpoint.state::text,max(checkpoint.last_event_sequence),max(checkpoint.pushed_at),count(*) FILTER (WHERE checkpoint.state='failed') FROM public.archive_targets AS target LEFT JOIN public.archive_export_checkpoints AS checkpoint ON checkpoint.tenant_id=target.tenant_id AND checkpoint.archive_target_id=target.archive_target_id WHERE target.tenant_id=p_tenant_id GROUP BY 1,2,3 ORDER BY 1,3 LIMIT p_limit;",
    )
    _create_function(
        "scalevault_operator_report_consistency(p_tenant_id uuid)",
        "check_name text,state text",
        _scope()
        + "RETURN QUERY SELECT 'memory_last_event'::text, CASE WHEN EXISTS (SELECT 1 FROM public.memories AS m LEFT JOIN public.memory_events AS e ON e.tenant_id=m.tenant_id AND e.event_id=m.last_event_id WHERE m.tenant_id=p_tenant_id AND e.event_id IS NULL) THEN 'inconsistent' ELSE 'ok' END::text UNION ALL SELECT 'selection_event', CASE WHEN EXISTS (SELECT 1 FROM public.selection_decisions AS d LEFT JOIN public.memory_events AS e ON e.tenant_id=d.tenant_id AND e.event_id=d.event_id WHERE d.tenant_id=p_tenant_id AND d.event_id IS NOT NULL AND e.event_id IS NULL) THEN 'inconsistent' ELSE 'ok' END::text ORDER BY 1;",
    )
    for signature in _FUNCTIONS:
        op.execute(sa.text(f"REVOKE ALL ON FUNCTION public.{signature} FROM PUBLIC"))
    op.execute(
        sa.text(
            "DO $grant$ BEGIN "
            "IF pg_catalog.to_regrole('kivra_memory_observability') IS NOT NULL THEN "
            "GRANT EXECUTE ON FUNCTION public.scalevault_observability_snapshot(uuid) TO kivra_memory_observability; END IF; "
            "IF pg_catalog.to_regrole('kivra_memory_operator_report') IS NOT NULL THEN "
            + " ".join(
                f"GRANT EXECUTE ON FUNCTION public.{signature} TO kivra_memory_operator_report;"
                for signature in _FUNCTIONS[1:]
            )
            + " END IF; END $grant$"
        )
    )
    op.execute(
        sa.text(
            "UPDATE alembic_compatibility SET contract_version = 11, "
            "minimum_reader_revision = '0011_observability_aggregates', "
            "minimum_writer_revision = '0011_observability_aggregates' "
            "WHERE component = 'memory_node'"
        )
    )


def downgrade() -> None:
    op.execute(
        sa.text(
            "UPDATE alembic_compatibility SET contract_version = 10, "
            "minimum_reader_revision = '0010_ingress_provider_heads', "
            "minimum_writer_revision = '0010_ingress_provider_heads' "
            "WHERE component = 'memory_node'"
        )
    )
    for signature in reversed(_FUNCTIONS):
        op.execute(sa.text(f"DROP FUNCTION public.{signature}"))
    op.drop_table("observability_tenant_bindings")
