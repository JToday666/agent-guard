from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import pytest

import conftest as root_conftest

pytestmark = pytest.mark.contract


def _item(
    nodeid: str,
    *,
    parameters: dict[str, Any] | None = None,
    fixtures: tuple[str, ...] = (),
) -> SimpleNamespace:
    return SimpleNamespace(
        callspec=SimpleNamespace(params=parameters or {}),
        fixturenames=list(fixtures),
        module=None,
        nodeid=nodeid,
    )


def test_postgres_dependency_detection_uses_parameters_and_fixtures() -> None:
    parameterized = _item(
        "tests/test_store.py::test_backend[postgres]",
        parameters={"backend": "postgres"},
    )
    fixture_backed = _item(
        "tests/test_store.py::test_backend",
        fixtures=("postgres_store",),
    )

    assert root_conftest._postgres_dependency_reasons(parameterized) == [
        "postgres parameter"
    ]
    assert root_conftest._postgres_dependency_reasons(fixture_backed) == [
        "fixture postgres_store"
    ]


@pytest.mark.parametrize(
    ("item", "expected"),
    [
        (_item("tests/test_schema_contract.py::test_schema"), "contract"),
        (_item("tests/test_guard_api.py::test_health"), "integration"),
        (_item("tests/test_runtime_safety_e2e.py::test_flow"), "e2e"),
        (
            _item(
                "tests/test_context_manifest.py::test_store[postgres]",
                parameters={"backend": "postgres"},
            ),
            "pg",
        ),
        (_item("tests/test_core_engine.py::test_allow"), "unit"),
    ],
)
def test_legacy_classifier_keeps_representative_layers_stable(
    item: SimpleNamespace,
    expected: str,
) -> None:
    expected_layer = "postgres" if expected == "pg" else expected
    assert root_conftest._inferred_test_layer(item) == expected_layer
