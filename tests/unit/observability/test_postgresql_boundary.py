from pathlib import Path

REPOSITORY_ROOT = Path(__file__).parents[3]
MIGRATION = REPOSITORY_ROOT / "migrations/versions/0011_observability_aggregates.py"


def test_security_definer_functions_validate_preexisting_tenant_scope() -> None:
    source = MIGRATION.read_text()
    assert "current_setting('scalevault.tenant_id', true)" in source
    assert "IS DISTINCT FROM p_tenant_id::text" in source
    assert "ERRCODE = '42501'" in source
    assert "set_config('scalevault.tenant_id'" not in source
    assert source.count("_scope()") == 11  # definition plus all ten function bodies
