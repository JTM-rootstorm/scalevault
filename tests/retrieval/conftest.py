from __future__ import annotations

from datetime import UTC, datetime
from typing import Literal
from uuid import UUID

import pytest
from kivra_memory.domain.enums import (
    AuthorityClass,
    MemoryCategory,
    MemoryScope,
    MemoryVisibility,
    OntologicalStatus,
    SubjectKind,
)
from kivra_memory.domain.identifiers import new_uuid7
from kivra_memory.retrieval.contracts import (
    ChannelAvailability,
    ChannelState,
    MemoryHit,
    MemoryScore,
    RetrievalProfileInfo,
    ScoreModifiers,
)
from kivra_memory.retrieval.ranking import RRF_V1_PROFILE_SHA256

NOW = datetime(2026, 8, 8, 12, tzinfo=UTC)


def uid(value: int) -> UUID:
    return new_uuid7(timestamp_ms=1_786_000_000_000, random_bits=value)


@pytest.fixture
def retrieval_profile() -> RetrievalProfileInfo:
    available = ChannelState(availability="available")
    return RetrievalProfileInfo(
        sha256=RRF_V1_PROFILE_SHA256,
        active_embedding_model_id=uid(90),
        channels=ChannelAvailability(
            lexical=available,
            trigram=available,
            semantic=available,
        ),
    )


def make_hit(
    value: int,
    *,
    statement: str | None = None,
    category: MemoryCategory = MemoryCategory.STABLE_FACT,
    scope: MemoryScope = MemoryScope.PERSONA,
    status: Literal["candidate", "active", "disputed"] = "active",
    score: float = 0.5,
) -> MemoryHit:
    return MemoryHit(
        memory_id=uid(value),
        revision=1,
        last_event_id=uid(1000 + value),
        branch_id=uid(3),
        subject_id=uid(4),
        subject_kind={
            MemoryScope.GLOBAL: SubjectKind.GLOBAL,
            MemoryScope.PERSONA: SubjectKind.PERSONA,
            MemoryScope.RELATIONSHIP: SubjectKind.RELATIONSHIP,
            MemoryScope.PROJECT: SubjectKind.PROJECT,
            MemoryScope.EPISODIC: SubjectKind.EPISODE,
            MemoryScope.SCENE_LOCAL: SubjectKind.SCENE,
        }[scope],
        category=category,
        ontological_status=(
            OntologicalStatus.HYPOTHESIS
            if category is MemoryCategory.OPEN_QUESTION
            else OntologicalStatus.LITERAL_TECHNICAL_FACT
        ),
        scope=scope,
        visibility=MemoryVisibility.PRIVATE_ROOT,
        status=status,
        statement=statement or f"Synthetic retrieval statement {value}.",
        reason_to_remember="Synthetic retrieval fixture.",
        interpretation_limits=("Synthetic fixture only.",),
        authority_class=AuthorityClass.VERIFIED_PROJECT_SOURCE,
        observed_at=NOW,
        score=MemoryScore(
            sources=(),
            rrf_score=score,
            modifiers=ScoreModifiers(),
            modifier_contributions=(),
            final_score=score,
        ),
    )
