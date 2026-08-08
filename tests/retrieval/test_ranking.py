from __future__ import annotations

import math

from kivra_memory.retrieval.ranking import (
    RRF_V1_PROFILE_SHA256,
    SourceRanking,
    weighted_rrf_v1,
)

from tests.retrieval.conftest import uid


def test_checked_in_rrf_v1_profile_digest_is_stable() -> None:
    assert RRF_V1_PROFILE_SHA256 == (
        "8221f314b5f77a00e685c8c2e726273f81a37513b9bfd63817a0ced36ff16b4b"
    )


def test_rrf_is_independent_of_channel_argument_order() -> None:
    lexical = SourceRanking(source="lexical", memory_ids=(uid(1), uid(2)))
    semantic = SourceRanking(source="semantic", memory_ids=(uid(2), uid(1)))

    first = weighted_rrf_v1((lexical, semantic))
    second = weighted_rrf_v1((semantic, lexical))

    assert first == second


def test_rrf_scores_are_finite_bounded_and_uuid_tied() -> None:
    results = weighted_rrf_v1((SourceRanking(source="lexical", memory_ids=(uid(2), uid(1))),))

    assert [item.memory_id for item in results] == [uid(2), uid(1)]
    assert all(math.isfinite(item.score.final_score) for item in results)
    assert all(0 <= item.score.final_score <= 1 for item in results)
