from __future__ import annotations

from pathlib import Path

import pytest

from postgres_test_utils import (
    UnsafeTestDatabaseUrlError,
    assert_safe_test_database_url,
    get_test_database_url,
)


def test_get_test_database_url_reads_dotenv_when_environment_is_unset(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.delenv("AGENTGUARD_TEST_DATABASE_URL", raising=False)
    dotenv = tmp_path / ".env"
    dotenv.write_text(
        "AGENTGUARD_TEST_DATABASE_URL=postgresql+psycopg://postgres:123456@127.0.0.1:5432/agent_guard_test\n",
        encoding="utf-8",
    )

    assert get_test_database_url(dotenv_path=dotenv).endswith("/agent_guard_test")


@pytest.mark.parametrize(
    "database_url",
    [
        "postgresql+psycopg://postgres:123456@127.0.0.1:5432/agent_guard",
        "postgresql+psycopg://postgres:123456@127.0.0.1:5432/postgres",
        "postgresql+psycopg://postgres:123456@127.0.0.1:5432/",
    ],
)
def test_assert_safe_test_database_url_rejects_non_test_databases(database_url: str) -> None:
    with pytest.raises(UnsafeTestDatabaseUrlError):
        assert_safe_test_database_url(database_url)


@pytest.mark.parametrize(
    "database_url",
    [
        "postgresql://postgres:123456@127.0.0.1:5432/agent_guard_test",
        "postgresql+psycopg://postgres:123456@127.0.0.1:5432/agent_guard_ci_test",
    ],
)
def test_assert_safe_test_database_url_accepts_test_databases(database_url: str) -> None:
    normalized = assert_safe_test_database_url(database_url)

    assert normalized.startswith("postgresql+psycopg://")
    assert normalized.rsplit("/", 1)[-1].endswith("_test")
