from __future__ import annotations

import os

import pytest

_TEST_TAXONOMY = frozenset(
    {"unit", "contract", "integration", "postgres", "e2e", "live"}
)
_CONTRACT_TOKENS = (
    "contract",
    "freeze",
    "schema",
    "release_artifact",
    "release_version",
    "roadmap",
    "audit_event_v04",
)
_E2E_TOKENS = (
    "browser_continuous_recording",
    "real_browser_runtime",
)
_INTEGRATION_TOKENS = (
    "adapter",
    "approval",
    "audit_checkpoint",
    "baseline",
    "browser_runtime",
    "competition_parallel",
    "competition_runtime",
    "context_manifest",
    "execution_lease_api",
    "guard_api",
    "integration",
    "parallel_wiring",
    "pipeline",
    "provenance_writer",
    "provider_retry_rate_limit",
    "runner",
    "runtime_conformance",
    "state_service",
    "store_",
    "trace_query",
)


_ENV_KEYS_TO_RESTORE = (
    "AGENTGUARD_ADAPTER_TOKEN",
    "AGENTGUARD_BROWSER_ACTION_TIMEOUT",
    "AGENTGUARD_BROWSER_MODE",
    "AGENTGUARD_CONTROL_TOKEN",
    "AGENTGUARD_DATABASE_URL",
    "AGENTGUARD_ENV",
    "AGENTGUARD_LANGGRAPH_RECURSION_LIMIT",
    "AGENTGUARD_LLM_BASE_URL",
    "AGENTGUARD_LLM_ENABLED",
    "AGENTGUARD_LLM_ENV_FILE",
    "AGENTGUARD_LLM_MAX_RETRIES",
    "AGENTGUARD_LLM_MAX_TOOL_ROUNDS",
    "AGENTGUARD_LLM_MODEL",
    "AGENTGUARD_LLM_PROVIDER",
    "AGENTGUARD_LLM_REQUEST_TIMEOUT",
    "AGENTGUARD_MAX_WALL_CLOCK_SECONDS",
    "AGENTGUARD_STORAGE_BACKEND",
    "DEEPSEEK_API_KEY",
    "DEEPSEEK_BASE_URL",
    "OPENAI_API_KEY",
    "OPENAI_BASE_URL",
)


@pytest.fixture(autouse=True)
def restore_agentguard_env() -> None:
    snapshot = {
        key: os.environ[key] for key in _ENV_KEYS_TO_RESTORE if key in os.environ
    }
    missing = set(_ENV_KEYS_TO_RESTORE) - set(snapshot)
    yield
    for key in missing:
        os.environ.pop(key, None)
    for key, value in snapshot.items():
        os.environ[key] = value


def pytest_collection_modifyitems(items: list[pytest.Item]) -> None:
    """Give legacy tests one mutually exclusive CI layer.

    New tests should declare their marker explicitly.  This compatibility
    classifier keeps the existing suite partitioned without touching product
    packages or relying on a developer's local environment.
    """

    for item in items:
        explicit = {mark.name for mark in item.iter_markers()} & _TEST_TAXONOMY
        if explicit:
            if len(explicit) > 1:
                pytest.fail(
                    f"{item.nodeid} has multiple test-layer markers: "
                    f"{', '.join(sorted(explicit))}",
                    pytrace=False,
                )
            explicit_layer = next(iter(explicit))
            postgres_reasons = _postgres_dependency_reasons(item)
            if postgres_reasons and explicit_layer != "postgres":
                pytest.fail(
                    f"{item.nodeid} is marked {explicit_layer} but has PostgreSQL "
                    f"dependencies: {', '.join(postgres_reasons)}",
                    pytrace=False,
                )
            if explicit_layer == "unit" and _module_uses_test_client(item):
                pytest.fail(
                    f"{item.nodeid} imports TestClient and cannot be marked unit",
                    pytrace=False,
                )
            continue
        item.add_marker(getattr(pytest.mark, _inferred_test_layer(item)))


def _module_uses_test_client(item: pytest.Item) -> bool:
    module = getattr(item, "module", None)
    return module is not None and "TestClient" in vars(module)


def _postgres_dependency_reasons(item: pytest.Item) -> list[str]:
    reasons: list[str] = []
    callspec = getattr(item, "callspec", None)
    parameters = getattr(callspec, "params", {})
    if any(
        isinstance(value, str) and value.lower() == "postgres"
        for value in parameters.values()
    ):
        reasons.append("postgres parameter")
    postgres_fixtures = sorted(
        name for name in item.fixturenames if "postgres" in name.lower()
    )
    reasons.extend(f"fixture {name}" for name in postgres_fixtures)
    return reasons


def _inferred_test_layer(item: pytest.Item) -> str:
    nodeid = item.nodeid.replace("\\", "/").lower()
    path = nodeid.split("::", 1)[0]

    if path.endswith("tests/test_rte05_openclaw_live.py"):
        return "live"

    if "postgres" in nodeid or _postgres_dependency_reasons(item):
        return "postgres"

    if (
        "_e2e" in nodeid
        or "e2e_" in nodeid
        or any(token in nodeid for token in _E2E_TOKENS)
    ):
        return "e2e"
    if (
        _module_uses_test_client(item)
        or "_api_" in nodeid
        or path.endswith("_api.py")
        or "test_guard_api" in path
        or "test_lgv2_api" in path
    ):
        return "integration"
    if any(token in nodeid for token in _CONTRACT_TOKENS):
        return "contract"
    if any(token in nodeid for token in _INTEGRATION_TOKENS):
        return "integration"
    return "unit"
