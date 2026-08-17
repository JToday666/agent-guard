"""Live Dashboard Chromium probe for the LangGraph reference profile.

The probe starts the repository's existing Vite Dashboard, authenticates it
against the live Guard API, renders the Evaluation and Evidence Detail routes,
and writes only screenshots plus a small display-safe result.
"""

from __future__ import annotations

import os
import shutil
import socket
import subprocess
import time
from contextlib import AbstractContextManager, contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator, Protocol, Sequence
from urllib.error import URLError
from urllib.parse import quote, urljoin, urlparse
from urllib.request import urlopen


REPO_ROOT = Path(__file__).resolve().parents[2]
DASHBOARD_ROOT = REPO_ROOT / "apps" / "dashboard"
DASHBOARD_PROBE_SCHEMA_VERSION = "dashboard-chromium-probe/1.0"


class DashboardProbeError(RuntimeError):
    """The live Dashboard could not be started or rendered."""


@dataclass(frozen=True, slots=True)
class _RouteSpec:
    route: str
    ready_selector: str
    live_api_path: str
    screenshot: str


class DashboardLauncher(Protocol):
    """Injectable Vite lifecycle used by fast tests."""

    def launch(
        self, *, guard_api_base_url: str, timeout_seconds: float
    ) -> AbstractContextManager[str]: ...


class DashboardBrowser(Protocol):
    """Injectable browser capture used by fast tests."""

    def capture(
        self,
        *,
        dashboard_base_url: str,
        guard_api_base_url: str,
        control_token: str,
        artifact_directory: Path,
        routes: Sequence[_RouteSpec],
        timeout_seconds: float,
    ) -> None: ...


class ViteDashboardLauncher:
    """Start and stop the existing Dashboard on a dynamic loopback port."""

    @contextmanager
    def launch(
        self, *, guard_api_base_url: str, timeout_seconds: float
    ) -> Iterator[str]:
        if not DASHBOARD_ROOT.is_dir():
            raise DashboardProbeError("Dashboard source directory is unavailable")
        port = _free_loopback_port()
        base_url = f"http://127.0.0.1:{port}"
        command = [
            *_vite_command(),
            "--host",
            "127.0.0.1",
            "--port",
            str(port),
            "--strictPort",
        ]
        env = os.environ.copy()
        env.update(
            {
                "VITE_BACKEND_TARGET": guard_api_base_url,
                "VITE_RUNTIME_SUPERVISION_S1_ENABLED": "true",
            }
        )
        process = subprocess.Popen(
            command,
            cwd=DASHBOARD_ROOT,
            env=env,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        try:
            _wait_for_vite(process, base_url, timeout_seconds)
            yield base_url
        finally:
            _stop_process(process)


class PlaywrightChromiumBrowser:
    """Authenticate and capture the two live routes with Python Playwright."""

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
        try:
            from playwright.sync_api import sync_playwright
        except ImportError as exc:  # pragma: no cover - installation failure
            raise DashboardProbeError("Python Playwright is unavailable") from exc

        timeout_ms = max(1, int(timeout_seconds * 1000))
        try:
            with sync_playwright() as playwright:
                browser = playwright.chromium.launch(headless=True)
                try:
                    context = browser.new_context(
                        viewport={"width": 1440, "height": 1024}
                    )
                    launch = context.request.post(
                        urljoin(guard_api_base_url + "/", "v1/auth/browser/launch"),
                        headers={"Authorization": f"Bearer {control_token}"},
                        timeout=timeout_ms,
                    )
                    if not launch.ok:
                        raise DashboardProbeError(
                            "Guard API rejected Dashboard browser launch"
                        )
                    payload = launch.json()
                    launch_code = (
                        payload.get("launch_code")
                        if isinstance(payload, dict)
                        else None
                    )
                    if not isinstance(launch_code, str) or not launch_code:
                        raise DashboardProbeError(
                            "Guard API browser launch response is invalid"
                        )

                    page = context.new_page()
                    observed: list[tuple[str, int]] = []
                    page.on(
                        "response",
                        lambda response: observed.append(
                            (urlparse(response.url).path, response.status)
                        ),
                    )
                    login_url = (
                        dashboard_base_url
                        + "/?launch_code="
                        + quote(launch_code, safe="")
                    )
                    page.goto(
                        login_url, wait_until="domcontentloaded", timeout=timeout_ms
                    )
                    source_badge = page.locator('[data-source-mode="live_api"]')
                    source_badge.wait_for(state="visible", timeout=timeout_ms)
                    if "LIVE API" not in source_badge.inner_text(timeout=timeout_ms):
                        raise DashboardProbeError(
                            "Dashboard did not enter live API mode"
                        )
                    page.wait_for_url(
                        lambda url: "launch_code=" not in url,
                        timeout=timeout_ms,
                    )
                    _wait_for_api_response(
                        page,
                        observed,
                        "/api/v1/auth/browser/exchange",
                        timeout_seconds,
                    )

                    for route in routes:
                        page.goto(
                            dashboard_base_url + route.route,
                            wait_until="domcontentloaded",
                            timeout=timeout_ms,
                        )
                        page.locator(route.ready_selector).wait_for(
                            state="visible", timeout=timeout_ms
                        )
                        _wait_for_api_response(
                            page,
                            observed,
                            route.live_api_path,
                            timeout_seconds,
                        )
                        page.screenshot(
                            path=str(artifact_directory / route.screenshot),
                            full_page=True,
                        )
                finally:
                    browser.close()
        except DashboardProbeError:
            raise
        except Exception as exc:
            # Do not propagate Playwright messages that can contain the one-time
            # launch URL. The classified runner only needs a stable failure.
            raise DashboardProbeError("Dashboard Chromium probe failed") from exc


def run_dashboard_chromium_probe(
    guard_api_base_url: str,
    control_token: str,
    trace_id: str,
    artifact_directory: str | Path,
    *,
    launcher: DashboardLauncher | None = None,
    browser: DashboardBrowser | None = None,
    timeout_seconds: float = 30.0,
) -> dict[str, object]:
    """Render live Dashboard routes and return a display-safe JSON value."""

    base_url = _normalized_http_base_url(guard_api_base_url)
    if not isinstance(control_token, str) or not control_token:
        raise DashboardProbeError("control token is required")
    if not isinstance(trace_id, str) or not trace_id:
        raise DashboardProbeError("trace id is required")
    if timeout_seconds <= 0:
        raise DashboardProbeError("timeout must be positive")

    artifact_root = Path(artifact_directory).resolve()
    artifact_root.mkdir(parents=True, exist_ok=True)
    screenshot_root = artifact_root / "dashboard"
    screenshot_root.mkdir(parents=True, exist_ok=True)
    encoded_trace_id = quote(trace_id, safe="")
    routes = (
        _RouteSpec(
            route="/evaluation",
            ready_selector=".evaluation-page",
            live_api_path="/api/v1/evaluations/latest",
            screenshot="dashboard/evaluation.png",
        ),
        _RouteSpec(
            route=f"/evidence/{encoded_trace_id}?view=execution",
            ready_selector=".execution-trace",
            live_api_path=f"/api/v1/traces/{encoded_trace_id}",
            screenshot="dashboard/evidence-execution.png",
        ),
    )
    selected_launcher = launcher or ViteDashboardLauncher()
    selected_browser = browser or PlaywrightChromiumBrowser()
    with selected_launcher.launch(
        guard_api_base_url=base_url, timeout_seconds=timeout_seconds
    ) as dashboard_base_url:
        selected_browser.capture(
            dashboard_base_url=dashboard_base_url,
            guard_api_base_url=base_url,
            control_token=control_token,
            artifact_directory=artifact_root,
            routes=routes,
            timeout_seconds=timeout_seconds,
        )

    for route in routes:
        screenshot = artifact_root / route.screenshot
        if not screenshot.is_file() or screenshot.stat().st_size == 0:
            raise DashboardProbeError("Dashboard screenshot was not produced")

    return {
        "schema_version": DASHBOARD_PROBE_SCHEMA_VERSION,
        "status": "passed",
        "routes": [
            {
                "route": route.route,
                "status": "rendered",
                "screenshot": route.screenshot,
            }
            for route in routes
        ],
    }


def _normalized_http_base_url(value: str) -> str:
    if not isinstance(value, str) or not value:
        raise DashboardProbeError("Guard API base URL is required")
    parsed = urlparse(value)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise DashboardProbeError("Guard API base URL must be HTTP(S)")
    if parsed.query or parsed.fragment:
        raise DashboardProbeError("Guard API base URL cannot contain query or fragment")
    return value.rstrip("/")


def _vite_command() -> list[str]:
    candidates = (
        DASHBOARD_ROOT / "node_modules" / ".bin" / "vite",
        REPO_ROOT / "node_modules" / ".bin" / "vite",
    )
    for candidate in candidates:
        if candidate.is_file():
            return [str(candidate)]
    vite = shutil.which("vite")
    if vite:
        return [vite]
    pnpm = shutil.which("pnpm")
    if pnpm:
        return [pnpm, "exec", "vite"]
    raise DashboardProbeError("Vite launcher is unavailable")


def _free_loopback_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.bind(("127.0.0.1", 0))
        return int(listener.getsockname()[1])


def _wait_for_vite(
    process: subprocess.Popen[bytes], base_url: str, timeout_seconds: float
) -> None:
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise DashboardProbeError("Vite exited before becoming ready")
        try:
            with urlopen(base_url, timeout=0.5) as response:  # noqa: S310 - loopback only
                if 200 <= response.status < 500:
                    return
        except (OSError, URLError):
            pass
        time.sleep(0.05)
    raise DashboardProbeError("Vite did not become ready")


def _stop_process(process: subprocess.Popen[bytes]) -> None:
    if process.poll() is not None:
        return
    process.terminate()
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=5)


def _wait_for_api_response(
    page: object,
    observed: Sequence[tuple[str, int]],
    expected_path: str,
    timeout_seconds: float,
) -> None:
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        if any(
            path == expected_path and status in {200, 304} for path, status in observed
        ):
            return
        page.wait_for_timeout(50)  # type: ignore[attr-defined]
    raise DashboardProbeError(
        f"Dashboard live API response missing for {expected_path}"
    )
