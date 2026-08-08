"""Deterministic checked-in weighted reciprocal-rank fusion profile."""

from __future__ import annotations

import json
from collections.abc import Mapping
from datetime import datetime
from decimal import Decimal
from hashlib import sha256
from pathlib import Path
from typing import Literal
from uuid import UUID

from pydantic import Field, field_validator, model_validator

from kivra_memory.domain.canonical_json import canonical_json_bytes
from kivra_memory.domain.enums import AuthorityClass, MemoryCategory
from kivra_memory.domain.identifiers import require_uuid7
from kivra_memory.retrieval.contracts import (
    MemoryScore,
    ModifierContribution,
    ReadModel,
    ScoreModifiers,
    SourceContribution,
)

RetrievalSource = Literal["lexical", "trigram", "semantic"]


class RetrievalProfile(ReadModel):
    profile_version: Literal["rrf-v1"]
    k: int = Field(ge=1, le=10_000)
    candidate_depths: dict[RetrievalSource, int]
    generator_weights: dict[RetrievalSource, float]
    authority_values: dict[AuthorityClass, float]
    category_recency_curve: dict[
        MemoryCategory, Literal["default", "project_state", "stable_identity"]
    ]
    modifier_weights: dict[str, float]
    recency_curves: dict[str, int]
    tie_break: tuple[Literal["final_score_desc", "memory_id_asc"], ...]

    @model_validator(mode="after")
    def validate_profile(self) -> RetrievalProfile:
        sources = {"lexical", "trigram", "semantic"}
        if set(self.candidate_depths) != sources or set(self.generator_weights) != sources:
            raise ValueError("retrieval profile must define every generator exactly once")
        if any(not 1 <= value <= 10_000 for value in self.candidate_depths.values()):
            raise ValueError("candidate depths are out of bounds")
        if any(not 0 <= value <= 100 for value in self.generator_weights.values()):
            raise ValueError("generator weights are out of bounds")
        if set(self.modifier_weights) != {
            "scope_match",
            "authority",
            "confidence",
            "salience",
            "recency",
        }:
            raise ValueError("retrieval profile modifiers do not match v1")
        if any(not 0 <= value <= 1 for value in self.modifier_weights.values()):
            raise ValueError("modifier weights are out of bounds")
        if set(self.authority_values) != set(AuthorityClass):
            raise ValueError("retrieval profile must define every authority class")
        if any(not 0 <= value <= 1 for value in self.authority_values.values()):
            raise ValueError("authority values are out of bounds")
        if set(self.category_recency_curve) != set(MemoryCategory):
            raise ValueError("retrieval profile must define every category recency curve")
        if self.tie_break != ("final_score_desc", "memory_id_asc"):
            raise ValueError("retrieval profile tie-break is not v1")
        return self


class SourceRanking(ReadModel):
    source: RetrievalSource
    memory_ids: AnnotatedMemoryIds

    @field_validator("memory_ids")
    @classmethod
    def validate_ids(cls, value: tuple[UUID, ...]) -> tuple[UUID, ...]:
        if len(value) != len(set(value)):
            raise ValueError("one source ranking cannot contain duplicate memories")
        for item in value:
            require_uuid7(item, field_name="memory_id")
        return value


AnnotatedMemoryIds = tuple[UUID, ...]


class RankedMemory(ReadModel):
    memory_id: UUID
    score: MemoryScore

    @field_validator("memory_id")
    @classmethod
    def validate_memory_id(cls, value: UUID) -> UUID:
        return require_uuid7(value, field_name="memory_id")


_PROFILE_PATH = Path(__file__).with_name("profiles") / "rrf-v1.json"
_PROFILE_DOCUMENT = json.loads(_PROFILE_PATH.read_text(encoding="utf-8"))
RRF_V1_PROFILE = RetrievalProfile.model_validate_json(_PROFILE_PATH.read_text(encoding="utf-8"))
RRF_V1_PROFILE_CANONICAL = canonical_json_bytes(RRF_V1_PROFILE.model_dump(mode="python"))
RRF_V1_PROFILE_SHA256 = sha256(RRF_V1_PROFILE_CANONICAL).hexdigest()


def _modifier_values(modifiers: ScoreModifiers) -> tuple[tuple[str, float], ...]:
    return (
        ("scope_match", modifiers.scope_match),
        ("authority", modifiers.authority),
        ("confidence", modifiers.confidence),
        ("salience", modifiers.salience),
        ("recency", modifiers.recency),
    )


def recency_modifier_v1(
    *, category: MemoryCategory, observed_at: datetime | None, evaluated_at: datetime
) -> float:
    """Return the checked-in category-sensitive half-life modifier."""

    if evaluated_at.tzinfo is None or (observed_at is not None and observed_at.tzinfo is None):
        raise ValueError("recency timestamps must be timezone-aware")
    if observed_at is None:
        return 0.0
    age_days = max(0.0, (evaluated_at - observed_at).total_seconds() / 86_400)
    curve = RRF_V1_PROFILE.category_recency_curve[category]
    half_life = RRF_V1_PROFILE.recency_curves[f"{curve}_half_life_days"]
    return float(0.5 ** (age_days / half_life))


def score_modifiers_v1(
    *,
    scope_match: float,
    authority_class: AuthorityClass,
    confidence: Decimal | float,
    salience: Decimal | float,
    category: MemoryCategory,
    observed_at: datetime | None,
    evaluated_at: datetime,
) -> ScoreModifiers:
    """Build bounded modifier inputs using the immutable v1 profile."""

    return ScoreModifiers(
        scope_match=scope_match,
        authority=RRF_V1_PROFILE.authority_values[authority_class],
        confidence=float(confidence),
        salience=float(salience),
        recency=recency_modifier_v1(
            category=category, observed_at=observed_at, evaluated_at=evaluated_at
        ),
    )


def weighted_rrf_v1(
    source_rankings: tuple[SourceRanking, ...],
    modifiers_by_memory: Mapping[UUID, ScoreModifiers] | None = None,
) -> tuple[RankedMemory, ...]:
    """Fuse available channels deterministically using immutable profile rrf-v1."""

    sources = [ranking.source for ranking in source_rankings]
    if len(sources) != len(set(sources)):
        raise ValueError("retrieval sources must be unique")
    rankings = {ranking.source: ranking for ranking in source_rankings}
    memory_ids = {memory_id for ranking in source_rankings for memory_id in ranking.memory_ids}
    modifiers_by_memory = modifiers_by_memory or {}
    maximum_rrf = sum(
        RRF_V1_PROFILE.generator_weights[source] / (RRF_V1_PROFILE.k + 1) for source in rankings
    )
    modifier_weight_total = sum(RRF_V1_PROFILE.modifier_weights.values())
    results: list[RankedMemory] = []
    for memory_id in memory_ids:
        sources_for_memory: list[SourceContribution] = []
        raw_rrf = 0.0
        ordered_sources: tuple[RetrievalSource, ...] = ("lexical", "trigram", "semantic")
        for source in ordered_sources:
            ranking = rankings.get(source)
            if ranking is None or memory_id not in ranking.memory_ids:
                continue
            rank = ranking.memory_ids.index(memory_id) + 1
            raw = RRF_V1_PROFILE.generator_weights[source] / (RRF_V1_PROFILE.k + rank)
            raw_rrf += raw
            sources_for_memory.append(
                SourceContribution(
                    source=source,
                    rank=rank,
                    contribution=raw / maximum_rrf if maximum_rrf else 0.0,
                )
            )
        rrf_score = raw_rrf / maximum_rrf if maximum_rrf else 0.0
        modifiers = modifiers_by_memory.get(memory_id, ScoreModifiers())
        modifier_contributions = tuple(
            ModifierContribution(
                modifier=name,  # type: ignore[arg-type]
                value=value,
                contribution=RRF_V1_PROFILE.modifier_weights[name] * value,
            )
            for name, value in _modifier_values(modifiers)
        )
        modifier_sum = sum(item.contribution for item in modifier_contributions)
        final_score = (rrf_score + modifier_sum) / (1.0 + modifier_weight_total)
        results.append(
            RankedMemory(
                memory_id=memory_id,
                score=MemoryScore(
                    sources=tuple(sources_for_memory),
                    rrf_score=rrf_score,
                    modifiers=modifiers,
                    modifier_contributions=modifier_contributions,
                    final_score=final_score,
                ),
            )
        )
    return tuple(sorted(results, key=lambda item: (-item.score.final_score, str(item.memory_id))))
