"""Shared safeguards for PostgreSQL integration tests."""

from __future__ import annotations

import os
from pathlib import Path
from urllib.parse import urlsplit

import pytest
from sqlalchemy import create_engine, text

from guard_api.storage.postgres import PostgresControlPlaneStore


ROOT = Path(__file__).resolve().parent
CONTROL_PLANE_TABLES = [
    "adapter_statuses",
    "evaluation_runs",
    "action_critic_reviews",
    "memory_guard_changes",
    "config_audit_findings",
    "provenance_edges",
    "provenance_nodes",
    "audit_integrity_heads",
    "policy_snapshot_history",
    "policy_snapshots",
    "approval_nonces",
    "browser_sessions",
    "launch_codes",
    "approval_requests",
    "approvals",
    "audit_events",
    "alembic_version",
]


class UnsafeTestDatabaseUrlError(ValueError):
    """Raised when a PostgreSQL reset is pointed at a non-test database."""


def get_test_database_url(*, dotenv_path: Path | None = None) -> str:
    value = os.getenv("AGENTGUARD_TEST_DATABASE_URL") or _dotenv_value(
        dotenv_path or ROOT / ".env",
        "AGENTGUARD_TEST_DATABASE_URL",
    )
    if not value:
        pytest.skip("AGENTGUARD_TEST_DATABASE_URL is not configured")
    return assert_safe_test_database_url(value)


def assert_safe_test_database_url(database_url: str) -> str:
    normalized = PostgresControlPlaneStore(database_url).database_url
    database_name = urlsplit(normalized).path.removeprefix("/")
    if database_name == "agent_guard_test" or database_name.endswith("_test"):
        return normalized
    raise UnsafeTestDatabaseUrlError(
        "AGENTGUARD_TEST_DATABASE_URL must point to agent_guard_test or a database ending in _test"
    )


def reset_control_plane_schema(database_url: str) -> None:
    safe_url = assert_safe_test_database_url(database_url)
    engine = create_engine(safe_url)
    with engine.begin() as conn:
        for table in CONTROL_PLANE_TABLES:
            conn.execute(text(f"DROP TABLE IF EXISTS {table} CASCADE"))


def _dotenv_value(dotenv_path: Path, name: str) -> str | None:
    if not dotenv_path.exists():
        return None
    prefix = f"{name}="
    for raw_line in dotenv_path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or not line.startswith(prefix):
            continue
        return _strip_env_value(line.removeprefix(prefix))
    return None


def _strip_env_value(value: str) -> str:
    parsed = value.strip()
    if len(parsed) >= 2 and parsed[0] == parsed[-1] and parsed[0] in {"'", '"'}:
        return parsed[1:-1]
    return parsed
