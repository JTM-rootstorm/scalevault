from kivra_memory.domain.enums import (
    EventOperation,
    MemoryCategory,
    OntologicalStatus,
    ProposalConfidenceBasis,
    TransportKind,
    enum_values,
)


def test_memory_category_wire_values_are_closed() -> None:
    assert enum_values(MemoryCategory) == (
        "stable_fact",
        "user_preference",
        "assistant_preference_like_pattern",
        "boundary_or_permission",
        "interaction_convention",
        "relationship_pattern",
        "emergent_tendency",
        "episodic_anchor",
        "project_decision",
        "project_state",
        "procedure",
        "open_question",
        "interpretation",
        "external_fact",
    )


def test_event_operations_include_all_replayable_projection_changes() -> None:
    assert {
        "evidence_attached",
        "evidence_redacted",
        "unlinked",
        "payload_purge_completed",
    } <= set(enum_values(EventOperation))


def test_transport_values_match_accepted_contract() -> None:
    assert enum_values(TransportKind) == (
        "direct_private",
        "secure_tunnel",
        "relay",
        "github_ingress",
        "internal_service",
        "archive_restore",
    )


def test_legacy_confidence_basis_is_not_ontological_or_numeric_confidence() -> None:
    assert ProposalConfidenceBasis.EXPLICIT.value == "explicit"
    assert "explicit" not in enum_values(OntologicalStatus)
