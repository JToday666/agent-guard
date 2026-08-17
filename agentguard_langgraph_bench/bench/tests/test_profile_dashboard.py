"""Focused lifecycle checks for the live Dashboard profile probe."""

from __future__ import annotations

from contextlib import contextmanager
from pathlib import Path
from typing import Iterator, Sequence

import pytest

from agentguard_langgraph_bench.bench.profile_dashboard import (
    DashboardProbeError,
    _RouteSpec,
    run_dashboard_chromium_probe,
)


class FakeLauncher:
    def __init__(self) -> None:
        self.started = False
        self.stopped = False
        self.guard_api_base_url: str | None = None

    @contextmanager
    def launch(
        self, *, guard_api_base_url: str, timeout_seconds: float
    ) -> Iterator[str]:
        assert timeout_seconds == 2
        self.started = True
        self.guard_api_base_url = guard_api_base_url
        try:
            yield "http://127.0.0.1:43123"
        finally:
            self.stopped = True


class FakeBrowser:
    def __init__(self, *, fail: bool = False) -> None:
        self.fail = fail
        self.control_token: str | None = None
        self.routes: tuple[_RouteSpec, ...] = ()

    def capture(
        self,
        *,
        dashboard_base_url: str,
        guard_api_base_url: str,
        control_token: str,
        artifact_directory: Path,
        routes: Sequence[_RouteSpec],
        timeout_seconds: float,
    ) -> None:
        assert dashboard_base_url == "http://127.0.0.1:43123"
        assert guard_api_base_url == "http://127.0.0.1:8088"
        assert timeout_seconds == 2
        self.control_token = control_token
        self.routes = tuple(routes)
        if self.fail:
            raise DashboardProbeError("injected browser failure")
        for route in routes:
            screenshot = artifact_directory / route.screenshot
            screenshot.parent.mkdir(parents=True, exist_ok=True)
            screenshot.write_bytes(b"fake-png")


def test_probe_returns_display_safe_routes_and_cleans_up(tmp_path: Path) -> None:
    launcher = FakeLauncher()
    browser = FakeBrowser()

    result = run_dashboard_chromium_probe(
        "http://127.0.0.1:8088/",
        "control-secret-must-not-be-returned",
        "trace/live 001",
        tmp_path,
        launcher=launcher,
        browser=browser,
        timeout_seconds=2,
    )

    assert launcher.started is True
    assert launcher.stopped is True
    assert launcher.guard_api_base_url == "http://127.0.0.1:8088"
    assert browser.control_token == "control-secret-must-not-be-returned"
    assert result == {
        "schema_version": "dashboard-chromium-probe/1.0",
        "status": "passed",
        "routes": [
            {
                "route": "/evaluation",
                "status": "rendered",
                "screenshot": "dashboard/evaluation.png",
            },
            {
                "route": "/evidence/trace%2Flive%20001?view=execution",
                "status": "rendered",
                "screenshot": "dashboard/evidence-execution.png",
            },
        ],
    }
    assert "control-secret" not in repr(result)
    assert (tmp_path / "dashboard/evaluation.png").read_bytes() == b"fake-png"


def test_probe_always_stops_vite_when_browser_fails(tmp_path: Path) -> None:
    launcher = FakeLauncher()

    with pytest.raises(DashboardProbeError, match="injected browser failure"):
        run_dashboard_chromium_probe(
            "http://127.0.0.1:8088",
            "control-secret",
            "trace-001",
            tmp_path,
            launcher=launcher,
            browser=FakeBrowser(fail=True),
            timeout_seconds=2,
        )

    assert launcher.started is True
    assert launcher.stopped is True


@pytest.mark.parametrize(
    ("base_url", "token", "trace_id"),
    [
        ("file:///tmp/guard", "control", "trace"),
        ("http://127.0.0.1:8088", "", "trace"),
        ("http://127.0.0.1:8088", "control", ""),
    ],
)
def test_probe_rejects_invalid_inputs_before_launch(
    tmp_path: Path, base_url: str, token: str, trace_id: str
) -> None:
    launcher = FakeLauncher()

    with pytest.raises(DashboardProbeError):
        run_dashboard_chromium_probe(
            base_url,
            token,
            trace_id,
            tmp_path,
            launcher=launcher,
            browser=FakeBrowser(),
            timeout_seconds=2,
        )

    assert launcher.started is False
