from __future__ import annotations

from pathlib import Path

import pytest

TEST_ROOT = Path(__file__).resolve().parent
DATABASE_TEST_ROOT = TEST_ROOT / "integration" / "database"
POSTGRESQL_READINESS_TEST = TEST_ROOT / "integration" / "test_postgres_readiness.py"


def pytest_collection_modifyitems(items: list[pytest.Item]) -> None:
    """Mark tests that provision disposable PostgreSQL for focused developer runs."""

    for item in items:
        test_path = Path(str(item.path)).resolve()
        if test_path.is_relative_to(DATABASE_TEST_ROOT) or test_path == POSTGRESQL_READINESS_TEST:
            item.add_marker(pytest.mark.database)
