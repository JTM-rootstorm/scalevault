from dataclasses import replace

import pytest
from kivra_memory.domain.constraints import (
    CATEGORY_ONTOLOGY_COMPATIBILITY,
    MemoryConstraintContext,
    validate_category_ontology,
    validate_memory_constraints,
)
from kivra_memory.domain.enums import (
    MemoryCategory,
    MemoryScope,
    MemoryStatus,
    MemoryVisibility,
    OntologicalStatus,
    SubjectKind,
    TransportKind,
)
from kivra_memory.domain.errors import DomainConstraintError
from kivra_memory.domain.identifiers import new_uuid7


def valid_context() -> MemoryConstraintContext:
    return MemoryConstraintContext(
        category=MemoryCategory.PROJECT_STATE,
        ontological_status=OntologicalStatus.LITERAL_TECHNICAL_FACT,
        scope=MemoryScope.PROJECT,
        visibility=MemoryVisibility.RESTRICTED,
        status=MemoryStatus.ACTIVE,
        sensitivity=1,
        subject_kind=SubjectKind.PROJECT,
        origin_session_id=None,
        origin_session_matches=False,
        structural_anchor_matches=True,
        imported_provenance=False,
        publication_approved=False,
        branch_allows_visibility=True,
        transport_kind=TransportKind.DIRECT_PRIVATE,
    )


def test_category_ontology_matrix_accepts_every_declared_pair_and_rejects_the_rest() -> None:
    for category in MemoryCategory:
        allowed = CATEGORY_ONTOLOGY_COMPATIBILITY[category]
        for ontological_status in OntologicalStatus:
            if ontological_status in allowed:
                validate_category_ontology(category, ontological_status)
            else:
                with pytest.raises(DomainConstraintError) as caught:
                    validate_category_ontology(category, ontological_status)
                assert caught.value.code == "category_ontology_incompatible"


@pytest.mark.parametrize(
    ("scope", "subject_kind"),
    [
        (MemoryScope.PERSONA, SubjectKind.PROJECT),
        (MemoryScope.RELATIONSHIP, SubjectKind.PERSONA),
        (MemoryScope.PROJECT, SubjectKind.CONCEPT),
        (MemoryScope.EPISODIC, SubjectKind.SCENE),
    ],
)
def test_scoped_memory_requires_matching_subject(
    scope: MemoryScope, subject_kind: SubjectKind
) -> None:
    with pytest.raises(DomainConstraintError) as caught:
        validate_memory_constraints(
            replace(valid_context(), scope=scope, subject_kind=subject_kind)
        )
    assert caught.value.code == "scope_subject_mismatch"


def test_scene_local_requires_matching_session_and_private_visibility() -> None:
    scene = replace(
        valid_context(),
        category=MemoryCategory.EPISODIC_ANCHOR,
        ontological_status=OntologicalStatus.FICTIONAL_OR_ROLEPLAYED_SCENE,
        scope=MemoryScope.SCENE_LOCAL,
        subject_kind=SubjectKind.SCENE,
        structural_anchor_matches=True,
    )

    with pytest.raises(DomainConstraintError) as missing:
        validate_memory_constraints(scene)
    assert missing.value.code == "scene_origin_mismatch"

    with pytest.raises(DomainConstraintError) as public:
        validate_memory_constraints(
            replace(
                scene,
                origin_session_id=new_uuid7(),
                origin_session_matches=True,
                visibility=MemoryVisibility.SHAREABLE,
            )
        )
    assert public.value.code == "scene_visibility_forbidden"


@pytest.mark.parametrize(
    ("status", "sensitivity", "publication_approved", "code"),
    [
        (MemoryStatus.CANDIDATE, 0, True, "public_seed_not_active"),
        (MemoryStatus.ACTIVE, 1, True, "public_seed_sensitive"),
        (MemoryStatus.ACTIVE, 0, False, "public_seed_unapproved"),
    ],
)
def test_public_seed_requires_all_publication_invariants(
    status: MemoryStatus,
    sensitivity: int,
    publication_approved: bool,
    code: str,
) -> None:
    context = replace(
        valid_context(),
        visibility=MemoryVisibility.PUBLIC_SEED,
        status=status,
        sensitivity=sensitivity,
        publication_approved=publication_approved,
    )
    with pytest.raises(DomainConstraintError) as caught:
        validate_memory_constraints(context)
    assert caught.value.code == code


@pytest.mark.parametrize("scope", [MemoryScope.GLOBAL, MemoryScope.SCENE_LOCAL])
def test_github_ingress_rejects_forbidden_scopes(scope: MemoryScope) -> None:
    context = replace(
        valid_context(),
        scope=scope,
        transport_kind=TransportKind.GITHUB_INGRESS,
        subject_kind=SubjectKind.GLOBAL if scope is MemoryScope.GLOBAL else SubjectKind.SCENE,
        structural_anchor_matches=scope is MemoryScope.SCENE_LOCAL,
        origin_session_id=new_uuid7() if scope is MemoryScope.SCENE_LOCAL else None,
        origin_session_matches=scope is MemoryScope.SCENE_LOCAL,
    )
    with pytest.raises(DomainConstraintError) as caught:
        validate_memory_constraints(context)
    assert caught.value.code == "github_scope_forbidden"


def test_context_repr_contains_no_memory_payload_fields() -> None:
    rendered = repr(valid_context())
    assert "statement" not in rendered
    assert "reason_to_remember" not in rendered


def test_global_scope_requires_global_subject_and_rejects_roleplayed_scene() -> None:
    with pytest.raises(DomainConstraintError) as subject:
        validate_memory_constraints(
            replace(valid_context(), scope=MemoryScope.GLOBAL, subject_kind=SubjectKind.PROJECT)
        )
    assert subject.value.code == "scope_subject_mismatch"

    with pytest.raises(DomainConstraintError) as ontology:
        validate_memory_constraints(
            replace(
                valid_context(),
                category=MemoryCategory.EPISODIC_ANCHOR,
                ontological_status=OntologicalStatus.FICTIONAL_OR_ROLEPLAYED_SCENE,
                scope=MemoryScope.GLOBAL,
                subject_kind=SubjectKind.GLOBAL,
            )
        )
    assert ontology.value.code == "global_roleplay_forbidden"


def test_scene_local_requires_matching_structural_anchor() -> None:
    with pytest.raises(DomainConstraintError) as caught:
        validate_memory_constraints(
            replace(
                valid_context(),
                category=MemoryCategory.EPISODIC_ANCHOR,
                ontological_status=OntologicalStatus.FICTIONAL_OR_ROLEPLAYED_SCENE,
                scope=MemoryScope.SCENE_LOCAL,
                subject_kind=SubjectKind.SCENE,
                origin_session_id=new_uuid7(),
                origin_session_matches=True,
                structural_anchor_matches=False,
            )
        )
    assert caught.value.code == "scope_anchor_mismatch"


def test_shareable_visibility_rejects_sensitivity_above_one() -> None:
    with pytest.raises(DomainConstraintError) as caught:
        validate_memory_constraints(
            replace(
                valid_context(),
                visibility=MemoryVisibility.SHAREABLE,
                sensitivity=2,
            )
        )
    assert caught.value.code == "shareable_sensitive"


def test_relay_rejects_sensitivity_four_but_secure_tunnel_does_not() -> None:
    relay = replace(
        valid_context(),
        transport_kind=TransportKind.RELAY,
        sensitivity=4,
    )
    with pytest.raises(DomainConstraintError) as caught:
        validate_memory_constraints(relay)
    assert caught.value.code == "relay_sensitivity_forbidden"

    validate_memory_constraints(replace(relay, transport_kind=TransportKind.SECURE_TUNNEL))
