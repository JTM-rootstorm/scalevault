from __future__ import annotations

import importlib
from collections.abc import Sequence
from typing import cast
from unittest.mock import Mock

import pytest
from alembic import command
from alembic.autogenerate import compare_metadata
from alembic.migration import MigrationContext
from alembic.script import ScriptDirectory
from kivra_memory.domain.identifiers import new_uuid7
from kivra_memory.storage import metadata
from sqlalchemy import inspect, text
from sqlalchemy.engine import Connection
from sqlalchemy.exc import DBAPIError
from sqlalchemy.orm import Session

from tests.fixtures.database_seed import seed_model_layers, seed_rows

from .conftest import (
    REQUIRED_EXTENSIONS,
    AlembicRunner,
    _alembic_config,
    installed_extensions,
)

EXPECTED_HEAD = "0010_ingress_provider_heads"
revision_module = importlib.import_module("migrations.versions.0001_initial_domain")


def _schema_differences(connection: Connection) -> Sequence[object]:
    context = MigrationContext.configure(connection)
    return cast(Sequence[object], compare_metadata(context, metadata))


def _current_revision(connection: Connection) -> str | None:
    if not inspect(connection).has_table("alembic_version"):
        return None
    return connection.execute(text("SELECT version_num FROM alembic_version")).scalar_one_or_none()


def test_revision_history_has_one_expected_head() -> None:
    heads = ScriptDirectory.from_config(_alembic_config()).get_heads()
    assert heads == [EXPECTED_HEAD]


def test_online_migration_requires_injected_connection(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(RuntimeError, match="injected SQLAlchemy connection"):
        command.current(_alembic_config())

    captured = capsys.readouterr()
    assert "postgresql://" not in captured.out
    assert "postgresql://" not in captured.err


def test_migration_fails_before_ddl_when_extensions_are_missing(
    alembic_runner: AlembicRunner,
) -> None:
    with pytest.raises(RuntimeError, match="required PostgreSQL extensions are not installed"):
        alembic_runner.upgrade()

    with alembic_runner.connect() as connection:
        assert set(inspect(connection).get_table_names()) <= {"alembic_version"}
        assert _current_revision(connection) is None


def test_migration_rejects_unsupported_extension_versions(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    bind = Mock()
    bind.execute.return_value = [
        ("citext", "1.6"),
        ("pg_trgm", "1.6"),
        ("pgcrypto", "1.3"),
        ("vector", "0.7.4"),
    ]
    monkeypatch.setattr(revision_module.op, "get_bind", lambda: bind)

    with pytest.raises(RuntimeError, match=r"vector 0\.7\.4 \(requires >= 0\.8\.0\)"):
        revision_module._require_extensions()


@pytest.mark.parametrize(
    ("installed", "minimum", "supported"),
    [
        ("0.8.0", "0.8.0", True),
        ("0.8.1", "0.8.0", True),
        ("1.6", "1.6.0", True),
        ("1.5.9", "1.6", False),
    ],
)
def test_extension_version_comparison(
    installed: str,
    minimum: str,
    supported: bool,
) -> None:
    assert revision_module._extension_version_is_supported(installed, minimum) is supported


def test_zero_to_head_and_full_round_trip(
    bootstrapped_alembic_runner: AlembicRunner,
) -> None:
    runner = bootstrapped_alembic_runner
    with runner.connect() as connection:
        assert set(installed_extensions(connection)) == REQUIRED_EXTENSIONS
        assert set(inspect(connection).get_table_names()) == set()

    runner.upgrade()
    with runner.connect() as connection:
        assert _current_revision(connection) == EXPECTED_HEAD
        assert _schema_differences(connection) == []
        first_head_tables = set(inspect(connection).get_table_names())
        assert set(metadata.tables).issubset(first_head_tables)
        assert connection.execute(text("SELECT count(*) FROM tenants")).scalar_one() == 0
        assert connection.execute(
            text("SELECT counter_id, next_sequence FROM memory_event_counter")
        ).one() == (1, 1)
        assert connection.execute(
            text("SELECT counter_id, next_sequence FROM selection_decision_counter")
        ).one() == (1, 1)
        assert (
            connection.execute(text("SELECT count(*) FROM selection_decisions")).scalar_one() == 0
        )
        assert connection.execute(
            text(
                "SELECT contract_version, minimum_reader_revision, minimum_writer_revision "
                "FROM alembic_compatibility WHERE component = 'memory_node'"
            )
        ).one() == (10, EXPECTED_HEAD, EXPECTED_HEAD)

    runner.downgrade("base")
    with runner.connect() as connection:
        assert _current_revision(connection) is None
        assert set(inspect(connection).get_table_names()) <= {"alembic_version"}
        assert set(installed_extensions(connection)) == REQUIRED_EXTENSIONS

    runner.upgrade()
    with runner.connect() as connection:
        assert _current_revision(connection) == EXPECTED_HEAD
        assert _schema_differences(connection) == []
        assert set(inspect(connection).get_table_names()) == first_head_tables


def test_existing_0001_database_upgrades_to_hybrid_retrieval(
    bootstrapped_alembic_runner: AlembicRunner,
) -> None:
    runner = bootstrapped_alembic_runner
    runner.upgrade("0001_initial_domain")
    with runner.connect() as connection:
        assert _current_revision(connection) == "0001_initial_domain"
        assert "memory_embeddings_v1" not in inspect(connection).get_table_names()

    runner.upgrade()
    with runner.connect() as connection:
        assert _current_revision(connection) == EXPECTED_HEAD
        assert "memory_embeddings_v1" in inspect(connection).get_table_names()
        assert _schema_differences(connection) == []
        assert connection.execute(
            text(
                "SELECT contract_version, minimum_reader_revision, minimum_writer_revision "
                "FROM alembic_compatibility WHERE component = 'memory_node'"
            )
        ).one() == (10, EXPECTED_HEAD, EXPECTED_HEAD)


def test_existing_0007_live_like_identity_rows_upgrade_with_no_credentials(
    bootstrapped_alembic_runner: AlembicRunner,
) -> None:
    runner = bootstrapped_alembic_runner
    runner.upgrade("0007_persistence_hardening")
    with Session(runner.engine) as session:
        for layer in seed_model_layers():
            session.add_all(layer)
            session.flush()
        session.commit()

    runner.upgrade()

    with runner.connect() as connection:
        assert _current_revision(connection) == EXPECTED_HEAD
        credential_columns = {
            column["name"] for column in inspect(connection).get_columns("client_credentials")
        }
        assert {
            "actor_id",
            "transport_binding_id",
            "secret_hash_key_id",
            "last_used_at",
        } <= credential_columns
        assert connection.execute(text("SELECT count(*) FROM client_credentials")).scalar_one() == 0


def test_existing_0007_legacy_bearer_requires_operator_reissue(
    bootstrapped_alembic_runner: AlembicRunner,
) -> None:
    runner = bootstrapped_alembic_runner
    runner.upgrade("0007_persistence_hardening")
    rows = seed_rows()
    tenant_id = rows["tenants"][0]["tenant_id"]
    client_id = rows["clients"][0]["client_id"]
    with Session(runner.engine) as session:
        for layer in seed_model_layers():
            session.add_all(layer)
            session.flush()
        session.execute(
            text(
                "INSERT INTO client_credentials ("
                "credential_id, tenant_id, client_id, kind, public_hint, secret_hash"
                ") VALUES ("
                ":credential_id, :tenant_id, :client_id, 'bearer_token', "
                "'legacy-public-hint', 'legacy-verifier-material'"
                ")"
            ),
            {
                "credential_id": new_uuid7(
                    timestamp_ms=1_767_225_600_000,
                    random_bits=401,
                ),
                "tenant_id": tenant_id,
                "client_id": client_id,
            },
        )
        session.commit()

    with pytest.raises(DBAPIError, match="legacy bearer credentials require operator reissue"):
        runner.upgrade()

    with runner.connect() as connection:
        assert _current_revision(connection) == "0007_persistence_hardening"
        assert "actor_id" not in {
            column["name"] for column in inspect(connection).get_columns("client_credentials")
        }


def test_existing_0008_secure_tunnel_binding_without_installation_fails_closed(
    bootstrapped_alembic_runner: AlembicRunner,
) -> None:
    runner = bootstrapped_alembic_runner
    runner.upgrade("0008_codex_credentials")
    tenant_id = new_uuid7(timestamp_ms=1_767_225_600_000, random_bits=501)
    actor_id = new_uuid7(timestamp_ms=1_767_225_600_000, random_bits=502)
    client_id = new_uuid7(timestamp_ms=1_767_225_600_000, random_bits=503)
    binding_id = new_uuid7(timestamp_ms=1_767_225_600_000, random_bits=504)
    with runner.engine.begin() as connection:
        connection.execute(
            text(
                "INSERT INTO tenants (tenant_id, slug, display_name) "
                "VALUES (:tenant_id, 'm8-invalid-binding', 'M8 invalid binding')"
            ),
            {"tenant_id": tenant_id},
        )
        connection.execute(
            text(
                "INSERT INTO actors (actor_id, tenant_id, handle, display_name, kind) "
                "VALUES (:actor_id, :tenant_id, 'm8-service', 'M8 service', 'service')"
            ),
            {"actor_id": actor_id, "tenant_id": tenant_id},
        )
        connection.execute(
            text(
                "INSERT INTO clients (client_id, tenant_id, public_id, display_name, kind, "
                "transport_kind, scopes, capability_profile) VALUES ("
                ":client_id, :tenant_id, 'm8-secure-client', 'M8 secure client', "
                "'interactive', 'secure_tunnel', ARRAY['memory.read.get'], "
                '\'{"contract_version":"scalevault-client-capability-v1",'
                '"read":null}\'::jsonb)'
            ),
            {"client_id": client_id, "tenant_id": tenant_id},
        )
        connection.execute(
            text(
                "INSERT INTO transport_bindings (transport_binding_id, tenant_id, actor_id, "
                "client_id, transport_kind, disclosure_boundary, installation_id, "
                "authorized_operations) VALUES ("
                ":binding_id, :tenant_id, :actor_id, :client_id, 'secure_tunnel', "
                "'openai_secure_tunnel', NULL, '{\"operations\":[]}'::jsonb)"
            ),
            {
                "binding_id": binding_id,
                "tenant_id": tenant_id,
                "actor_id": actor_id,
                "client_id": client_id,
            },
        )

    with pytest.raises(DBAPIError, match="remote_has_installation"):
        runner.upgrade()

    with runner.connect() as connection:
        assert _current_revision(connection) == "0008_codex_credentials"


def test_existing_0002_database_upgrades_and_downgrades_policy_lifecycle(
    bootstrapped_alembic_runner: AlembicRunner,
) -> None:
    runner = bootstrapped_alembic_runner
    runner.upgrade("0002_hybrid_retrieval")
    with runner.connect() as connection:
        inspector = inspect(connection)
        assert _current_revision(connection) == "0002_hybrid_retrieval"
        assert "selection_decisions" not in inspector.get_table_names()
        assert "candidate_expires_at" not in {
            column["name"] for column in inspector.get_columns("memories")
        }

    runner.upgrade()
    with runner.connect() as connection:
        inspector = inspect(connection)
        assert _current_revision(connection) == EXPECTED_HEAD
        assert "selection_decisions" in inspector.get_table_names()
        assert "selection_decision_counter" in inspector.get_table_names()
        assert "candidate_expires_at" in {
            column["name"] for column in inspector.get_columns("memories")
        }
        receipt_columns = {
            column["name"]: bool(column["nullable"])
            for column in inspector.get_columns("command_receipts")
        }
        assert receipt_columns["event_id"] is True
        assert receipt_columns["selection_decision_id"] is True
        assert _schema_differences(connection) == []

    runner.downgrade("0002_hybrid_retrieval")
    with runner.connect() as connection:
        inspector = inspect(connection)
        assert _current_revision(connection) == "0002_hybrid_retrieval"
        assert "selection_decisions" not in inspector.get_table_names()
        assert "candidate_expires_at" not in {
            column["name"] for column in inspector.get_columns("memories")
        }
        receipt_columns = {
            column["name"]: bool(column["nullable"])
            for column in inspector.get_columns("command_receipts")
        }
        assert receipt_columns["event_id"] is False
        assert "selection_decision_id" not in receipt_columns


def test_existing_0003_database_upgrades_to_genesis_provenance(
    bootstrapped_alembic_runner: AlembicRunner,
) -> None:
    runner = bootstrapped_alembic_runner
    runner.upgrade("0003_selection_policy_lifecycle")
    with runner.connect() as connection:
        assert _current_revision(connection) == "0003_selection_policy_lifecycle"
        assert "genesis_import_runs" not in inspect(connection).get_table_names()

    runner.upgrade()
    with runner.connect() as connection:
        assert _current_revision(connection) == EXPECTED_HEAD
        assert {
            "genesis_import_runs",
            "genesis_import_sources",
            "genesis_import_records",
            "genesis_import_exclusions",
            "genesis_import_supersessions",
            "genesis_import_run_results",
        } <= set(inspect(connection).get_table_names())
        assert _schema_differences(connection) == []


def test_existing_0004_database_upgrades_through_ingress_and_sealed_content(
    bootstrapped_alembic_runner: AlembicRunner,
) -> None:
    runner = bootstrapped_alembic_runner
    runner.upgrade("0004_genesis_import_provenance")
    with runner.connect() as connection:
        ingress_columns = {
            column["name"]: bool(column["nullable"])
            for column in inspect(connection).get_columns("ingress_items")
        }
        memory_columns = {column["name"] for column in inspect(connection).get_columns("memories")}
        assert ingress_columns["declared_idempotency_key"] is False
        assert ingress_columns["payload_sha256"] is False
        assert "sealed_ciphertext" not in memory_columns

    runner.upgrade()
    with runner.connect() as connection:
        ingress_columns = {
            column["name"]: bool(column["nullable"])
            for column in inspect(connection).get_columns("ingress_items")
        }
        memory_columns = {column["name"] for column in inspect(connection).get_columns("memories")}
        assert _current_revision(connection) == EXPECTED_HEAD
        assert ingress_columns["declared_idempotency_key"] is True
        assert ingress_columns["payload_sha256"] is True
        assert {
            "sealed_envelope_version",
            "sealed_algorithm",
            "sealed_nonce",
            "sealed_ciphertext",
            "sealed_aad_sha256",
            "safe_summary",
        } <= memory_columns
        assert "ingress_provider_violations" in inspect(connection).get_table_names()
        assert _schema_differences(connection) == []


def test_existing_0006_database_upgrades_and_downgrades_persistence_hardening(
    bootstrapped_alembic_runner: AlembicRunner,
) -> None:
    runner = bootstrapped_alembic_runner
    runner.upgrade("0006_sealed_canonical_content")
    with runner.connect() as connection:
        assert _current_revision(connection) == "0006_sealed_canonical_content"
        assert "ingress_provider_violations" not in inspect(connection).get_table_names()

    runner.upgrade()
    with runner.connect() as connection:
        assert _current_revision(connection) == EXPECTED_HEAD
        assert "ingress_provider_violations" in inspect(connection).get_table_names()
        assert _schema_differences(connection) == []

    runner.downgrade("0006_sealed_canonical_content")
    with runner.connect() as connection:
        assert _current_revision(connection) == "0006_sealed_canonical_content"
        assert "ingress_provider_violations" not in inspect(connection).get_table_names()


def test_existing_0009_database_adds_and_removes_ingress_provider_heads(
    bootstrapped_alembic_runner: AlembicRunner,
) -> None:
    runner = bootstrapped_alembic_runner
    runner.upgrade("0009_secure_tunnel_binding")
    with runner.connect() as connection:
        assert _current_revision(connection) == "0009_secure_tunnel_binding"
        assert "ingress_provider_heads" not in inspect(connection).get_table_names()

    runner.upgrade()
    with runner.connect() as connection:
        assert _current_revision(connection) == EXPECTED_HEAD
        assert "ingress_provider_heads" in inspect(connection).get_table_names()
        assert _schema_differences(connection) == []

    runner.downgrade("0009_secure_tunnel_binding")
    with runner.connect() as connection:
        assert _current_revision(connection) == "0009_secure_tunnel_binding"
        assert "ingress_provider_heads" not in inspect(connection).get_table_names()

def test_genesis_downgrade_fails_closed_after_a_genesis_decision(
    bootstrapped_alembic_runner: AlembicRunner,
) -> None:
    runner = bootstrapped_alembic_runner
    runner.upgrade()
    with runner.engine.begin() as connection:
        connection.execute(text("SET LOCAL session_replication_role = 'replica'"))
        connection.execute(
            text(
                "INSERT INTO selection_decisions ("
                "selection_sequence, decision_id, tenant_id, lineage_id, branch_id, "
                "persona_id, actor_id, client_id, transport_binding_id, policy_id, "
                "policy_version, policy_sha256, policy_rule_code, input_sha256, source_kind, "
                "requested_operation, outcome, reason_codes, matched_rule_ids, selection_basis, "
                "scope, visibility, sensitivity, subject_id, subject_kind, memory_id, event_id) "
                "VALUES (1, '019c0000-0000-7000-8000-000000000001', "
                "'019c0000-0000-7000-8000-000000000002', "
                "'019c0000-0000-7000-8000-000000000003', "
                "'019c0000-0000-7000-8000-000000000004', "
                "'019c0000-0000-7000-8000-000000000005', "
                "'019c0000-0000-7000-8000-000000000006', "
                "'019c0000-0000-7000-8000-000000000007', "
                "'019c0000-0000-7000-8000-000000000008', "
                "'scalevault-memory-selection', 1, decode(repeat('a', 64), 'hex'), "
                "'genesis_import_test', decode(repeat('b', 64), 'hex'), "
                "'genesis_import', 'nominate', 'omit', '[\"test_reason\"]'::jsonb, "
                "'[]'::jsonb, 'imported_legacy', 'persona', 'private_root', 0, "
                "'019c0000-0000-7000-8000-000000000009', 'persona', NULL, NULL)"
            )
        )

    with pytest.raises(DBAPIError, match="cannot downgrade while Genesis"):
        runner.downgrade("0003_selection_policy_lifecycle")

    with runner.connect() as connection:
        assert _current_revision(connection) == EXPECTED_HEAD
        assert "genesis_import_runs" in inspect(connection).get_table_names()
