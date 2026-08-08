from __future__ import annotations

from uuid import UUID

from kivra_memory.domain.enums import MemoryCategory, MemoryScope, OntologicalStatus
from kivra_memory.domain.fingerprints import (
    FINGERPRINT_VERSION,
    ExactMemoryFingerprint,
    advisory_lock_input,
    exact_memory_fingerprint,
)
from kivra_memory.domain.identifiers import new_uuid7


def fingerprint(
    *,
    statement: str = "The project uses private, deterministic archives.",
    category: MemoryCategory = MemoryCategory.PROJECT_DECISION,
    ontological_status: OntologicalStatus = OntologicalStatus.LITERAL_TECHNICAL_FACT,
    scope: MemoryScope = MemoryScope.PROJECT,
    interpretation_limits: tuple[str, ...] = ("Do not infer a cloud backup.",),
) -> ExactMemoryFingerprint:
    return exact_memory_fingerprint(
        statement=statement,
        category=category,
        ontological_status=ontological_status,
        scope=scope,
        interpretation_limits=interpretation_limits,
    )


def uid(random_bits: int) -> UUID:
    return new_uuid7(timestamp_ms=1_786_000_000_000, random_bits=random_bits)


def test_v1_fingerprint_is_stable_and_its_lock_token_is_statement_free() -> None:
    first = fingerprint()
    second = fingerprint()

    assert FINGERPRINT_VERSION == 1
    assert first == second
    assert len(first.sha256_hex) == 64
    assert first.sha256_hex in first.canonical_lock_input.decode("ascii")
    assert "deterministic archives" not in first.canonical_lock_input.decode("ascii")


def test_semantic_dimensions_separate_otherwise_identical_statements() -> None:
    baseline = fingerprint()

    assert baseline.sha256_hex != fingerprint(category=MemoryCategory.PROJECT_STATE).sha256_hex
    assert (
        baseline.sha256_hex
        != fingerprint(ontological_status=OntologicalStatus.HYPOTHESIS).sha256_hex
    )
    assert baseline.sha256_hex != fingerprint(scope=MemoryScope.GLOBAL).sha256_hex
    assert (
        baseline.sha256_hex
        != fingerprint(interpretation_limits=("Do not infer a hosted backup.",)).sha256_hex
    )


def test_whitespace_only_variants_and_limit_order_share_identity_but_case_does_not() -> None:
    baseline = fingerprint(
        statement="The project\nuses private, deterministic archives.",
        interpretation_limits=("One limit.", "Second limit."),
    )
    presentation_variant = fingerprint(
        statement=" \tThe  project\r\nuses private,\tdeterministic archives. \n",
        interpretation_limits=(" Second  limit. ", "\tOne limit."),
    )
    case_variant = fingerprint(statement="The Project\nuses private, deterministic archives.")

    assert presentation_variant == baseline
    assert case_variant.sha256_hex != baseline.sha256_hex


def test_unicode_is_preserved_without_normalization() -> None:
    composed = fingerprint(statement="Caf\u00e9 policy")
    decomposed = fingerprint(statement="Cafe\u0301 policy")
    unicode_space = fingerprint(statement="Caf\u00e9\u00a0policy")

    assert composed.sha256_hex != decomposed.sha256_hex
    assert composed.sha256_hex != unicode_space.sha256_hex


def test_repr_and_advisory_lock_input_never_expose_statement_content() -> None:
    secret = "PRIVATE_FINGERPRINT_CANARY"
    result = fingerprint(statement=secret)
    lock_input = advisory_lock_input(
        tenant_id=uid(1),
        lineage_id=uid(2),
        branch_id=uid(3),
        subject_id=uid(4),
        fingerprint=result,
    )

    assert secret not in repr(result)
    assert secret not in lock_input.decode("ascii")
    assert result.sha256_hex in lock_input.decode("ascii")
