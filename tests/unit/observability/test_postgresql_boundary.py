from pathlib import Path
from typing import cast

from kivra_memory.storage.models import TENANT_TABLE_NAMES, ObservabilityTenantBinding
from sqlalchemy import Table

REPOSITORY_ROOT = Path(__file__).parents[3]
MIGRATION = REPOSITORY_ROOT / "migrations/versions/0011_observability_aggregates.py"
BINDING_SCRIPT = REPOSITORY_ROOT / "deploy/memory-node/postgresql/bind_observability_tenant.sql"


def test_security_definer_functions_validate_preexisting_tenant_scope() -> None:
    source = MIGRATION.read_text()
    assert "current_setting('scalevault.tenant_id', true)" in source
    assert "IS DISTINCT FROM p_tenant_id::text" in source
    assert "ERRCODE = '42501'" in source
    assert "set_config('scalevault.tenant_id'" not in source
    assert "binding.login_role = SESSION_USER::text" in source
    assert "observability_tenant_bindings" in source
    assert source.count("_scope()") == 11  # definition plus all ten function bodies


def test_binding_activation_is_owner_only_and_fixed_to_wrapper_logins() -> None:
    source = BINDING_SCRIPT.read_text()
    assert "SET LOCAL ROLE kivra_memory_owner" in source
    assert "kivra_memory_metrics" in source
    assert "kivra_memory_operator_report_login" in source
    assert "scalevault_is_uuid_v7" in source
    assert "ON CONFLICT (login_role) DO UPDATE" in source


def test_binding_table_is_in_metadata_but_not_runtime_tenant_crud_surface() -> None:
    table = cast(Table, ObservabilityTenantBinding.__table__)
    assert table.name == "observability_tenant_bindings"
    assert tuple(table.columns.keys()) == ("login_role", "tenant_id")
    assert table.name not in TENANT_TABLE_NAMES
