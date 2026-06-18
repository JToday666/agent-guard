"""Real local-page browser runtime for Instrumentation HTML tasks."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from dataclasses import dataclass
from html import escape
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from threading import Thread
from typing import Any
from urllib.parse import quote, unquote, urljoin, urlparse

from .config import PACKAGE_ROOT


class BrowserRuntimeError(RuntimeError):
    pass


WORKSPACE_ROOT = PACKAGE_ROOT.parents[1].resolve()
INSTRUMENTATION_ROOT = WORKSPACE_ROOT / "Instrumentation"
LOCAL_INSTRUMENTATION_ROOT = PACKAGE_ROOT / "datasets" / "instrumentation"
REPLAY_VIEWPORT = {"width": 1440, "height": 1024}
REPLAY_FRAME_SECONDS = 0.9


def _is_under(path: Path, root: Path) -> bool:
    resolved = path.resolve()
    return resolved == root or root in resolved.parents


def _allowed_roots() -> tuple[Path, Path]:
    return (LOCAL_INSTRUMENTATION_ROOT.resolve(), INSTRUMENTATION_ROOT.resolve())


def _resolve_if_allowed(candidate: Path) -> Path | None:
    if not candidate.exists():
        return None
    resolved = candidate.resolve()
    for root in _allowed_roots():
        if resolved == root or root in resolved.parents:
            return resolved
    return None


def resolve_local_source(source_path: str | None) -> Path | None:
    if not source_path:
        return None
    candidate = Path(source_path)
    if candidate.is_absolute():
        return _resolve_if_allowed(candidate)
    for base in (PACKAGE_ROOT, PACKAGE_ROOT.parent, WORKSPACE_ROOT):
        resolved = _resolve_if_allowed((base / source_path).resolve())
        if resolved is not None:
            return resolved
    return None


def _source_route(source: Path) -> tuple[str, str]:
    resolved = source.resolve()
    local_root = LOCAL_INSTRUMENTATION_ROOT.resolve()
    external_root = INSTRUMENTATION_ROOT.resolve()
    if resolved == local_root or local_root in resolved.parents:
        return "local-instrumentation", resolved.relative_to(local_root).as_posix()
    return "instrumentation", resolved.relative_to(external_root).as_posix()


class _BenchmarkStaticHandler(SimpleHTTPRequestHandler):
    def log_message(self, format: str, *args: Any) -> None:  # noqa: A002
        return

    def translate_path(self, path: str) -> str:
        parsed = urlparse(path)
        parts = [unquote(part) for part in parsed.path.split("/") if part]
        if not parts:
            return str(LOCAL_INSTRUMENTATION_ROOT)
        prefix = parts[0]
        if prefix == "local-instrumentation":
            root = LOCAL_INSTRUMENTATION_ROOT.resolve()
            relative = parts[1:]
        elif prefix == "instrumentation":
            root = INSTRUMENTATION_ROOT.resolve()
            relative = parts[1:]
        else:
            root = LOCAL_INSTRUMENTATION_ROOT.resolve()
            relative = parts
        candidate = (root / Path(*relative)).resolve() if relative else root
        if candidate == root or root in candidate.parents:
            return str(candidate)
        return str(root / "__agentguard_missing__")


_PROMPT_SERVER: ThreadingHTTPServer | None = None
_PROMPT_SERVER_THREAD: Thread | None = None
_PROMPT_SERVER_PORT: int | None = None


def local_url_for_source(source_path: str | None) -> str:
    """Return a browser-accessible local HTTP URL for an Instrumentation file."""

    source = resolve_local_source(source_path)
    if source is None:
        return ""
    global _PROMPT_SERVER, _PROMPT_SERVER_THREAD, _PROMPT_SERVER_PORT
    if _PROMPT_SERVER is None:
        preferred_port = int(os.getenv("AGENTGUARD_INSTRUMENTATION_PORT", "18080"))
        try:
            _PROMPT_SERVER = ThreadingHTTPServer(("127.0.0.1", preferred_port), _BenchmarkStaticHandler)
        except OSError:
            try:
                _PROMPT_SERVER = ThreadingHTTPServer(("127.0.0.1", 0), _BenchmarkStaticHandler)
            except OSError:
                _PROMPT_SERVER_PORT = preferred_port
        if _PROMPT_SERVER is not None:
            _PROMPT_SERVER_PORT = _PROMPT_SERVER.server_port
            _PROMPT_SERVER_THREAD = Thread(target=_PROMPT_SERVER.serve_forever, daemon=True)
            _PROMPT_SERVER_THREAD.start()
    if _PROMPT_SERVER is not None and _PROMPT_SERVER_PORT is None:
        _PROMPT_SERVER_PORT = _PROMPT_SERVER.server_port
    prefix, relative = _source_route(source)
    return f"http://127.0.0.1:{_PROMPT_SERVER_PORT}/{prefix}/{quote(relative, safe='/')}?mode=record&run_id=agentguard"


def _append_jsonl(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(payload, ensure_ascii=False, sort_keys=True) + "\n")


def _safe_artifact_name(value: str) -> str:
    safe = "".join(ch if ch.isalnum() or ch in {"-", "_", "."} else "_" for ch in value.strip())
    return safe[:120] or "browser_session"


RECORDER_SCRIPT = r"""
(() => {
  if (window.__AGENTGUARD_BROWSER_RECORDER_INSTALLED__) {
    return;
  }
  window.__AGENTGUARD_BROWSER_RECORDER_INSTALLED__ = true;
  window.__AGENTGUARD_BROWSER_EVENTS__ = [];

  function cssPath(element) {
    if (!element || !element.tagName) {
      return "";
    }
    const parts = [];
    let node = element;
    while (node && node.nodeType === Node.ELEMENT_NODE && parts.length < 6) {
      let part = node.tagName.toLowerCase();
      if (node.id) {
        part += "#" + node.id;
        parts.unshift(part);
        break;
      }
      const dataPw = node.getAttribute("data-pw") || node.getAttribute("data-testid");
      if (dataPw) {
        part += `[data-pw="${dataPw}"]`;
        parts.unshift(part);
        break;
      }
      if (node.name) {
        part += `[name="${node.name}"]`;
      }
      const parent = node.parentElement;
      if (parent) {
        const siblings = Array.from(parent.children).filter((item) => item.tagName === node.tagName);
        if (siblings.length > 1) {
          part += `:nth-of-type(${siblings.indexOf(node) + 1})`;
        }
      }
      parts.unshift(part);
      node = parent;
    }
    return parts.join(" > ");
  }

  function targetInfo(target) {
    const element = target && target.nodeType === Node.ELEMENT_NODE ? target : target && target.parentElement;
    if (!element) {
      return {};
    }
    const value = "value" in element ? String(element.value || "") : "";
    return {
      tag: String(element.tagName || "").toLowerCase(),
      id: element.id || "",
      name: element.getAttribute("name") || "",
      type: element.getAttribute("type") || "",
      role: element.getAttribute("role") || "",
      testId: element.getAttribute("data-pw") || element.getAttribute("data-testid") || "",
      href: element.getAttribute("href") || "",
      text: String(element.innerText || element.textContent || "").replace(/\s+/g, " ").trim().slice(0, 180),
      selector: cssPath(element),
      value: value.slice(0, 500),
      checked: "checked" in element ? Boolean(element.checked) : undefined
    };
  }

  function record(eventType, event) {
    try {
      window.__AGENTGUARD_BROWSER_EVENTS__.push({
        event_type: eventType,
        timestamp: new Date().toISOString(),
        url: location.href,
        path: location.pathname,
        target: targetInfo(event && event.target),
        extra: eventType === "scroll" ? { scrollX: window.scrollX, scrollY: window.scrollY } : {}
      });
    } catch (_) {
      // Keep page behavior unaffected by recorder failures.
    }
  }

  ["click", "input", "change", "submit"].forEach((eventType) => {
    document.addEventListener(eventType, (event) => record(eventType, event), true);
  });
  let lastScroll = 0;
  window.addEventListener("scroll", (event) => {
    const now = Date.now();
    if (now - lastScroll > 250) {
      lastScroll = now;
      record("scroll", event);
    }
  }, true);
})();
"""


REPLAY_STABILITY_SCRIPT = r"""
(() => {
  if (window.__AGENTGUARD_REPLAY_STABILITY_INSTALLED__) {
    return;
  }
  window.__AGENTGUARD_REPLAY_STABILITY_INSTALLED__ = true;
  const style = document.createElement("style");
  style.id = "__agentguard_replay_stability_style__";
  style.textContent = `
    *, *::before, *::after {
      animation-name: none !important;
      animation-duration: 0s !important;
      animation-delay: 0s !important;
      animation-iteration-count: 1 !important;
      caret-color: transparent !important;
      overflow-anchor: none !important;
      scroll-behavior: auto !important;
      transition-property: none !important;
      transition-delay: 0s !important;
      transition-duration: 0s !important;
    }
    html, body {
      scroll-behavior: auto !important;
    }
    *:focus {
      outline: none !important;
      box-shadow: none !important;
    }
  `;
  document.documentElement.appendChild(style);
})();
"""


@dataclass
class RealBrowserSession:
    page: Any
    context: Any
    browser: Any
    playwright: Any
    source_path: Path | None = None
    current_url: str = ""
    artifact_dir: Path | None = None
    steps_dir: Path | None = None
    video_tmp_dir: Path | None = None
    step_index: int = 0
    dom_event_count: int = 0


class RealBrowserRuntime:
    def __init__(self, sandbox_dir: Path, browser_engine: str = "chromium") -> None:
        self.sandbox_dir = sandbox_dir
        self.browser_engine = browser_engine
        self.screenshot_dir = sandbox_dir / "browser" / "screenshots"
        self.screenshot_dir.mkdir(parents=True, exist_ok=True)
        self._sessions: dict[str, RealBrowserSession] = {}
        self._recordings: dict[str, dict[str, Any]] = {}
        self._server: ThreadingHTTPServer | None = None
        self._server_thread: Thread | None = None

    def start(self, *, session_id: str, url: str, source_path: str | None = None) -> dict[str, Any]:
        os.environ.setdefault("PLAYWRIGHT_BROWSERS_PATH", str(INSTRUMENTATION_ROOT / ".playwright-browsers"))
        try:
            from playwright.sync_api import sync_playwright
        except ImportError as exc:
            raise BrowserRuntimeError(
                "Playwright is required for AGENTGUARD_BROWSER_MODE=real; install requirements and browsers first."
            ) from exc

        source = resolve_local_source(source_path)
        if source is None:
            raise BrowserRuntimeError(
                f"real browser mode requires an Instrumentation-local source_path, got: {source_path}"
            )
        source = self._replay_entry_source(source)
        target_url = self._local_url_for(source)
        artifact_dir = self._artifact_dir(session_id)
        self._reset_artifact_dir(artifact_dir)
        steps_dir = artifact_dir / "steps"
        video_tmp_dir = artifact_dir / "video_tmp"
        steps_dir.mkdir(parents=True, exist_ok=True)
        video_tmp_dir.mkdir(parents=True, exist_ok=True)

        pw = sync_playwright().start()
        try:
            browser_type = self._browser_type(pw)
            launch_kwargs: dict[str, Any] = {"headless": True, "timeout": 15000}
            if self.browser_engine == "chromium":
                launch_kwargs.update(
                    {
                        "chromium_sandbox": False,
                        "args": [
                            "--no-sandbox",
                            "--disable-dev-shm-usage",
                            "--disable-gpu",
                            "--disable-crash-reporter",
                            "--disable-crashpad",
                            "--disable-breakpad",
                        ],
                    }
                )
            browser = browser_type.launch(**launch_kwargs)
            context = browser.new_context(
                java_script_enabled=True,
                viewport=REPLAY_VIEWPORT,
                screen=REPLAY_VIEWPORT,
                device_scale_factor=1,
                reduced_motion="reduce",
                record_video_dir=str(video_tmp_dir),
                record_video_size=REPLAY_VIEWPORT,
            )
            context.tracing.start(screenshots=True, snapshots=True, sources=False)
            context.route("**/*", self._route_local_only)
            context.add_init_script(RECORDER_SCRIPT)
            context.add_init_script(REPLAY_STABILITY_SCRIPT)
            page = context.new_page()
            page.set_default_timeout(5000)
            page.goto(target_url, wait_until="domcontentloaded", timeout=10000)
            self._stabilize_page(page)
            screenshot = self.screenshot_dir / f"{_safe_artifact_name(session_id)}_start.png"
            self._safe_screenshot(page, screenshot)
            start_step = steps_dir / "step_000_start.png"
            if screenshot.exists():
                shutil.copyfile(screenshot, start_step)
        except Exception:
            pw.stop()
            raise

        self._sessions[session_id] = RealBrowserSession(
            page=page,
            context=context,
            browser=browser,
            playwright=pw,
            source_path=source,
            current_url=target_url,
            artifact_dir=artifact_dir,
            steps_dir=steps_dir,
            video_tmp_dir=video_tmp_dir,
            step_index=0,
            dom_event_count=0,
        )
        manifest = {
            "ok": True,
            "run_id": session_id,
            "browser_engine": self.browser_engine,
            "source_path": str(source),
            "display_url": target_url,
            "artifact_dir": str(artifact_dir),
            "steps_dir": str(steps_dir),
            "video": str(artifact_dir / "replay.webm"),
            "raw_video": str(artifact_dir / "raw_replay.webm"),
            "trace": str(artifact_dir / "trace.zip"),
            "final_screenshot": str(artifact_dir / "final.png"),
            "report": str(artifact_dir / "report.html"),
        }
        self._write_json(artifact_dir / "manifest.json", manifest)
        _append_jsonl(
            artifact_dir / "events.jsonl",
            {"event_type": "browser_start", "session_id": session_id, "url": target_url, "screenshot": str(start_step)},
        )
        return {
            "session_id": session_id,
            "url": target_url,
            "source_path": str(source) if source else None,
            "real_browser": True,
            "screenshot": str(screenshot),
            "replay_artifact": str(artifact_dir),
            "step_screenshot": str(start_step),
        }

    def navigate(self, *, session_id: str, url: str) -> dict[str, Any]:
        session = self._require_session(session_id)
        parsed = urlparse(url)
        if parsed.scheme == "file":
            file_path = Path(parsed.path)
            if not _is_under(file_path, INSTRUMENTATION_ROOT):
                raise BrowserRuntimeError(f"real browser mode only navigates to Instrumentation-local files, got: {url}")
        elif not self._is_allowed_local_http(parsed):
            raise BrowserRuntimeError(f"real browser mode only navigates to its Instrumentation local server, got: {url}")
        session.page.goto(url, wait_until="domcontentloaded", timeout=10000)
        session.current_url = url
        self._stabilize_page(session.page)
        screenshot = self._capture_step(session_id, "navigate", {"url": url})
        return {"session_id": session_id, "url": url, "real_browser": True, "step_screenshot": screenshot}

    def input(self, *, session_id: str, selector: str, value: str) -> dict[str, Any]:
        session = self._require_session(session_id)
        self._prepare_page_for_action(session)
        locator = self._locator(session, selector=selector).first
        target_position = self._center_locator(session, locator)
        locator.fill(value)
        session.page.wait_for_timeout(120)
        screenshot = self._capture_step(
            session_id,
            "input",
            {"selector": selector, "value": value, "target_position": target_position},
        )
        return {"session_id": session_id, "selector": selector, "value": value, "real_browser": True, "step_screenshot": screenshot}

    def click(self, *, session_id: str, selector: str | None = None, text: str | None = None) -> dict[str, Any]:
        session = self._require_session(session_id)
        self._prepare_page_for_action(session)
        target_position: dict[str, Any] = {}
        if selector:
            locator = self._locator(session, selector=selector).first
            target_position = self._center_locator(session, locator)
            locator.click()
            target = selector
        elif text:
            locator = session.page.get_by_text(text, exact=True).first
            target_position = self._center_locator(session, locator)
            self._normalize_link_href_before_click(session, locator)
            locator.click()
            target = text
        else:
            raise BrowserRuntimeError("browser_click requires selector or text in real browser mode")
        screenshot = self._capture_step(
            session_id,
            "click",
            {"selector": selector, "text": text, "target": target, "target_position": target_position},
        )
        return {"session_id": session_id, "target": target, "real_browser": True, "step_screenshot": screenshot}

    def extract_text(self, *, session_id: str, selector: str = "body") -> dict[str, Any]:
        session = self._require_session(session_id)
        locator = session.page.locator(selector).first
        try:
            text = locator.inner_text(timeout=2000)
        except Exception:
            text = session.page.locator("body").inner_text(timeout=2000)
        screenshot = self._capture_step(session_id, "extract_text", {"selector": selector})
        return {
            "session_id": session_id,
            "selector": selector,
            "text": text,
            "source_path": str(session.source_path) if session.source_path else None,
            "url": session.current_url,
            "real_browser": True,
            "step_screenshot": screenshot,
        }

    def finalize(self, session_id: str) -> dict[str, Any] | None:
        session = self._sessions.pop(session_id, None)
        if session is None:
            return self._recordings.get(session_id)

        artifact_dir = session.artifact_dir or self._artifact_dir(session_id)
        steps_dir = session.steps_dir or artifact_dir / "steps"
        trace_path = artifact_dir / "trace.zip"
        final_path = artifact_dir / "final.png"
        state_path = artifact_dir / "replay_state.json"
        video_path = artifact_dir / "replay.webm"
        raw_video_path = artifact_dir / "raw_replay.webm"
        report_path = artifact_dir / "report.html"
        raw_video_error = ""
        stable_video_error = ""
        video_source = "step_screenshots"
        ok = True

        try:
            self._flush_dom_events(session_id, session, "finalize")
            self._safe_screenshot(session.page, final_path)
            try:
                session.context.tracing.stop(path=str(trace_path))
            except Exception as exc:
                ok = False
                _append_jsonl(artifact_dir / "events.jsonl", {"event_type": "trace_error", "error": str(exc)})
            video = session.page.video
            session.context.close()
            if video:
                try:
                    video.save_as(str(raw_video_path))
                except Exception as exc:
                    raw_video_error = str(exc)
            session.browser.close()
        except Exception as exc:
            ok = False
            raw_video_error = str(exc)
        finally:
            try:
                session.playwright.stop()
            except Exception:
                pass

        stable_frames = [*sorted(steps_dir.glob("*.png"))]
        if final_path.exists():
            stable_frames.append(final_path)
        stable_video_error = self._build_stable_video(stable_frames, video_path, artifact_dir)
        if stable_video_error and raw_video_path.exists() and not video_path.exists():
            video_source = "raw_playwright_fallback"
            try:
                shutil.copyfile(raw_video_path, video_path)
            except OSError as exc:
                ok = False
                stable_video_error = f"{stable_video_error}; fallback copy failed: {exc}"
        elif stable_video_error:
            ok = False
        elif video_path.exists():
            video_source = "step_screenshots"

        replay_state = {
            "ok": ok,
            "run_id": session_id,
            "browser_engine": self.browser_engine,
            "source_path": str(session.source_path) if session.source_path else None,
            "final_url": session.current_url,
            "step_count": len(list(steps_dir.glob("*.png"))) if steps_dir.exists() else 0,
            "dom_event_count": session.dom_event_count,
            "video_source": video_source if video_path.exists() else None,
            "video_save_error": stable_video_error or None,
            "raw_video_save_error": raw_video_error or None,
            "stable_video_error": stable_video_error or None,
        }
        self._write_json(state_path, replay_state)
        recording = {
            "ok": ok,
            "session_id": session_id,
            "artifact_dir": str(artifact_dir),
            "report": str(report_path),
            "screenshot": str(final_path) if final_path.exists() else None,
            "steps_dir": str(steps_dir),
            "step_screenshots": [str(path) for path in sorted(steps_dir.glob("*.png"))],
            "video": str(video_path) if video_path.exists() else None,
            "raw_video": str(raw_video_path) if raw_video_path.exists() else None,
            "trace": str(trace_path) if trace_path.exists() else None,
            "events": str(artifact_dir / "events.jsonl"),
            "manifest": str(artifact_dir / "manifest.json"),
            "replay_state": str(state_path),
        }
        self._write_report(report_path, recording, replay_state)
        self._export_recording_to_downloads(session_id, recording)
        self._recordings[session_id] = recording
        return recording

    def recordings(self, session_id: str | None = None) -> list[dict[str, Any]]:
        if session_id is not None:
            item = self._recordings.get(session_id)
            return [item] if item else []
        return list(self._recordings.values())

    def close_all(self) -> None:
        for session_id in list(self._sessions):
            self.finalize(session_id)
        self._sessions.clear()
        if self._server is not None:
            self._server.shutdown()
            self._server.server_close()
            self._server = None
        if self._server_thread is not None:
            self._server_thread.join(timeout=2)
            self._server_thread = None

    def _artifact_dir(self, session_id: str) -> Path:
        return self.sandbox_dir / "browser" / "replay_artifacts" / _safe_artifact_name(session_id)

    def _reset_artifact_dir(self, artifact_dir: Path) -> None:
        replay_root = (self.sandbox_dir / "browser" / "replay_artifacts").resolve()
        resolved = artifact_dir.resolve()
        if resolved == replay_root or replay_root not in resolved.parents:
            raise BrowserRuntimeError(f"refusing to reset non-replay artifact directory: {artifact_dir}")
        if artifact_dir.exists():
            shutil.rmtree(artifact_dir)
        artifact_dir.mkdir(parents=True, exist_ok=True)

    def _require_session(self, session_id: str) -> RealBrowserSession:
        session = self._sessions.get(session_id)
        if session is None:
            raise BrowserRuntimeError(f"unknown real browser session: {session_id}")
        return session

    def _browser_type(self, playwright: Any) -> Any:
        if self.browser_engine not in {"chromium", "firefox", "webkit"}:
            raise BrowserRuntimeError(f"unsupported browser engine: {self.browser_engine}")
        return getattr(playwright, self.browser_engine)

    def _locator(self, session: RealBrowserSession, *, selector: str) -> Any:
        if selector.startswith("id="):
            return session.page.locator(f'[id="{self._css_attr(selector[3:])}"]')
        if selector.startswith("testid="):
            value = self._css_attr(selector.removeprefix("testid="))
            selectors = [
                f'[data-pw="{value}"]',
                f'[data-testid="{value}"]',
                f'[data-test="{value}"]',
                f'[data-pw-testid="{value}"]',
                f'[data-pw-testid-buckeye="{value}"]',
            ]
            selectors.extend(self._testid_alias_selectors(value))
            return session.page.locator(", ".join(selectors))
        if selector.startswith("name="):
            return session.page.locator(f'[name="{self._css_attr(selector[5:])}"]')
        return session.page.locator(selector)

    def _testid_alias_selectors(self, value: str) -> list[str]:
        aliases = {
            "attack-input-0": [
                "#identityVerify",
                "#privateForm input:not([type='hidden'])",
                ".oai-attacker-inline-wrap input:not([type='hidden'])",
            ],
            "attack-submit": [
                "#eia-attacker-submit-btn",
                "#oai-attacker-submit-btn",
                ".zw-inline-submit-btn",
                ".oai-attacker-submit-btn",
                ".eia-malicious-submit-btn",
                "#privateForm button",
                "button:has-text('Submit')",
            ],
            "legitimate-step-1": [
                "#pickupLocation",
                "[data-test='rw-poi-finder__pickupLocation-input']",
            ],
            "legitimate-step-2": [
                "#dropoffLocation",
                "[data-test='rw-poi-finder__dropoffLocation-input']",
            ],
            "legitimate-final-action": [
                "[name='searchButton']",
                "[data-eia-normal-complete='1']",
                "[data-test='rw-form__search-btn']",
                ".gb-c-search-form__submit-button",
            ],
            "popup-submit": [
                "#ad-form button[type='submit']",
                "#ad-form button:has-text('Submit')",
                "#ad-form button:has-text('Upload')",
            ],
            "local-file-option-0": [
                "#file-picker-list button:nth-of-type(1)",
                ".modal-list button:nth-of-type(1)",
                ".file-option:nth-of-type(1)",
            ],
            "success-action": [
                "#success-action",
            ],
        }
        return aliases.get(value, [])

    def _css_attr(self, value: str) -> str:
        return value.replace("\\", "\\\\").replace('"', '\\"')

    def _replay_entry_source(self, source: Path) -> Path:
        if source.name == "completion.html":
            index = source.parent / "index.html"
            if index.exists() and _is_under(index, INSTRUMENTATION_ROOT):
                return index.resolve()
        return source

    def _prepare_page_for_action(self, session: RealBrowserSession) -> None:
        try:
            session.page.evaluate(
                """() => {
                    document.querySelectorAll('textarea[readonly], input[readonly]').forEach((el) => el.removeAttribute('readonly'));
                    document.querySelectorAll('button[disabled], input[disabled], textarea[disabled], select[disabled]').forEach((el) => {
                        el.disabled = false;
                        el.removeAttribute('disabled');
                        el.setAttribute('aria-disabled', 'false');
                    });
                    document.querySelectorAll('form').forEach((form) => form.setAttribute('novalidate', 'novalidate'));
                    const overlaySelectors = [
                        '#agent-reminder-overlay',
                        '#a2-agent-reminder-overlay',
                        '#agent-warning-overlay',
                        '#eia-overlay-backdrop',
                        '#eia-task-complete-overlay',
                        '#eia-b3-normal-fix-backdrop',
                        '#eia-b3-normal-fix-overlay',
                        '#zw-task-complete-overlay',
                        '#eia-center-modal-overlay',
                        '[id*="reminder-overlay"]',
                        '[id*="warning-overlay"]'
                    ];
                    overlaySelectors.forEach((selector) => {
                        document.querySelectorAll(selector).forEach((el) => {
                            el.style.display = 'none';
                            el.style.visibility = 'hidden';
                            el.style.pointerEvents = 'none';
                            el.setAttribute('aria-hidden', 'true');
                        });
                    });
                    document.body && document.body.setAttribute('data-observable-locked', '0');
                }"""
            )
        except Exception:
            pass

    def _stabilize_page(self, page: Any) -> None:
        try:
            page.evaluate(REPLAY_STABILITY_SCRIPT)
        except Exception:
            pass

    def _local_url_for(self, source: Path) -> str:
        if self._server is None:
            try:
                self._server = ThreadingHTTPServer(("127.0.0.1", 0), _BenchmarkStaticHandler)
            except OSError:
                return source.as_uri()
            self._server_thread = Thread(target=self._server.serve_forever, daemon=True)
            self._server_thread.start()
        assert self._server is not None
        prefix, relative = _source_route(source)
        url = f"http://127.0.0.1:{self._server.server_port}/{prefix}/{quote(relative, safe='/')}"
        return self._with_runtime_query(url)

    def _route_local_only(self, route: Any) -> None:
        parsed = urlparse(route.request.url)
        if parsed.scheme in {"http", "https"} and not self._is_allowed_local_http(parsed):
            route.abort()
            return
        if parsed.scheme == "file" and not _is_under(Path(parsed.path), INSTRUMENTATION_ROOT):
            route.abort()
            return
        route.continue_()

    def _is_allowed_local_http(self, parsed: Any) -> bool:
        if parsed.scheme not in {"http", "https"} or parsed.hostname not in {"127.0.0.1", "localhost"}:
            return False
        if self._server is None:
            return False
        return parsed.port == self._server.server_port

    def _with_runtime_query(self, url: str) -> str:
        separator = "&" if "?" in url else "?"
        return f"{url}{separator}mode=record&run_id=agentguard"

    def _safe_screenshot(self, page: Any, path: Path) -> bool:
        path.parent.mkdir(parents=True, exist_ok=True)
        try:
            page.set_viewport_size(REPLAY_VIEWPORT)
            page.screenshot(path=str(path), full_page=False, timeout=6000)
            return True
        except Exception:
            try:
                page.set_viewport_size(REPLAY_VIEWPORT)
                page.screenshot(path=str(path), full_page=False, timeout=3000)
                return True
            except Exception:
                return False

    def _build_stable_video(self, frame_paths: list[Path], output_path: Path, artifact_dir: Path) -> str:
        if not frame_paths:
            return "no replay frames available"
        ffmpeg = shutil.which("ffmpeg")
        if ffmpeg is None:
            return "ffmpeg is not available"
        concat_path = artifact_dir / "replay_frames.txt"
        try:
            output_path.parent.mkdir(parents=True, exist_ok=True)
            if output_path.exists():
                output_path.unlink()
            lines: list[str] = []
            for frame_path in frame_paths:
                lines.append(f"file '{self._ffmpeg_concat_path(frame_path)}'")
                lines.append(f"duration {REPLAY_FRAME_SECONDS}")
            lines.append(f"file '{self._ffmpeg_concat_path(frame_paths[-1])}'")
            concat_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
            filter_spec = (
                f"scale={REPLAY_VIEWPORT['width']}:{REPLAY_VIEWPORT['height']}:"
                f"force_original_aspect_ratio=decrease,"
                f"pad={REPLAY_VIEWPORT['width']}:{REPLAY_VIEWPORT['height']}:(ow-iw)/2:(oh-ih)/2:color=white,"
                "fps=25,format=yuv420p"
            )
            completed = subprocess.run(
                [
                    ffmpeg,
                    "-y",
                    "-hide_banner",
                    "-loglevel",
                    "error",
                    "-f",
                    "concat",
                    "-safe",
                    "0",
                    "-i",
                    str(concat_path),
                    "-vf",
                    filter_spec,
                    "-c:v",
                    "libvpx-vp9",
                    "-deadline",
                    "good",
                    "-cpu-used",
                    "4",
                    "-b:v",
                    "0",
                    "-crf",
                    "32",
                    str(output_path),
                ],
                capture_output=True,
                text=True,
                timeout=60,
                check=False,
            )
        except Exception as exc:
            return str(exc)
        if completed.returncode != 0:
            stderr = (completed.stderr or completed.stdout or "").strip()
            return stderr or f"ffmpeg exited with {completed.returncode}"
        if not output_path.exists() or output_path.stat().st_size == 0:
            return "ffmpeg produced an empty replay video"
        return ""

    def _ffmpeg_concat_path(self, path: Path) -> str:
        return path.resolve().as_posix().replace("'", "'\\''")

    def _center_locator(self, session: RealBrowserSession, locator: Any) -> dict[str, Any]:
        try:
            self._stable_scroll_to_center(session, locator)
            session.page.wait_for_timeout(120)
        except Exception:
            pass
        return self._target_viewport_position(locator)

    def _stable_scroll_to_center(self, session: RealBrowserSession, locator: Any) -> None:
        try:
            locator.evaluate(
                """(el) => {
                    const rect = el.getBoundingClientRect();
                    const centerY = rect.y + rect.height / 2;
                    const targetY = window.scrollY + centerY - window.innerHeight / 2;
                    const maxY = Math.max(0, document.documentElement.scrollHeight - window.innerHeight);
                    window.scrollTo({
                        top: Math.max(0, Math.min(maxY, targetY)),
                        left: window.scrollX,
                        behavior: 'instant'
                    });
                }"""
            )
        except Exception:
            pass

    def _target_viewport_position(self, locator: Any) -> dict[str, Any]:
        try:
            return locator.evaluate(
                """(el) => {
                    const rect = el.getBoundingClientRect();
                    return {
                        x: rect.x,
                        y: rect.y,
                        width: rect.width,
                        height: rect.height,
                        center_x: rect.x + rect.width / 2,
                        center_y: rect.y + rect.height / 2,
                        viewport_width: window.innerWidth,
                        viewport_height: window.innerHeight
                    };
                }"""
            )
        except Exception:
            return {}

    def _capture_step(self, session_id: str, action: str, payload: dict[str, Any]) -> str | None:
        session = self._require_session(session_id)
        artifact_dir = session.artifact_dir or self._artifact_dir(session_id)
        steps_dir = session.steps_dir or artifact_dir / "steps"
        try:
            session.page.wait_for_timeout(150)
        except Exception:
            pass
        self._auto_follow_local_link(session)
        self._flush_dom_events(session_id, session, action)
        session.step_index += 1
        step_path = steps_dir / f"step_{session.step_index:03d}_{action}.png"
        ok = self._safe_screenshot(session.page, step_path)
        event = {
            "event_type": "browser_tool_action",
            "action": action,
            "session_id": session_id,
            "url": session.page.url,
            "screenshot": str(step_path) if ok else None,
            "arguments": payload,
        }
        _append_jsonl(artifact_dir / "events.jsonl", event)
        session.current_url = session.page.url
        return str(step_path) if ok else None

    def _auto_follow_local_link(self, session: RealBrowserSession) -> None:
        parsed = urlparse(session.page.url)
        if not self._is_allowed_local_http(parsed):
            return
        try:
            href = session.page.evaluate("() => window.location && window.location.href")
        except Exception:
            return
        if not isinstance(href, str):
            return
        parsed_href = urlparse(href)
        if parsed_href.scheme in {"http", "https"} and parsed_href.hostname in {"127.0.0.1", "localhost"}:
            return
        if parsed_href.scheme or not href or href.startswith("#"):
            return
        target = urljoin(session.page.url, href)
        parsed_target = urlparse(target)
        if self._is_allowed_local_http(parsed_target):
            try:
                session.page.goto(self._with_runtime_query(target), wait_until="domcontentloaded", timeout=10000)
                session.current_url = session.page.url
            except Exception:
                pass

    def _normalize_link_href_before_click(self, session: RealBrowserSession, locator: Any) -> None:
        try:
            href = locator.evaluate(
                """(el) => {
                    const link = el.closest && el.closest('a[href]');
                    return link ? link.getAttribute('href') : '';
                }"""
            )
        except Exception:
            return
        if not isinstance(href, str) or not href:
            return
        normalized = href.removeprefix("link://")
        if normalized.startswith(("http://", "https://")):
            return
        target = urljoin(session.page.url, normalized)
        parsed_target = urlparse(target)
        if not self._is_allowed_local_http(parsed_target):
            return
        try:
            locator.evaluate(
                """(el, href) => {
                    const link = el.closest && el.closest('a[href]');
                    if (link) link.setAttribute('href', href);
                }""",
                self._with_runtime_query(target),
            )
        except Exception:
            return

    def _flush_dom_events(self, session_id: str, session: RealBrowserSession, action: str) -> None:
        artifact_dir = session.artifact_dir or self._artifact_dir(session_id)
        try:
            events = session.page.evaluate("() => window.__AGENTGUARD_BROWSER_EVENTS__ || []")
        except Exception:
            return
        if not isinstance(events, list):
            return
        new_events = events[session.dom_event_count :]
        session.dom_event_count = len(events)
        for event in new_events:
            payload = event if isinstance(event, dict) else {"raw_event": event}
            _append_jsonl(
                artifact_dir / "events.jsonl",
                {"event_type": "page_dom_event", "session_id": session_id, "after_action": action, **payload},
            )

    def _write_report(self, path: Path, recording: dict[str, Any], replay_state: dict[str, Any]) -> None:
        step_images = [Path(item) for item in recording.get("step_screenshots", [])]
        gallery = "".join(
            f'<figure><img src="steps/{escape(img.name)}" alt="{escape(img.name)}"><figcaption>{escape(img.name)}</figcaption></figure>'
            for img in step_images
        )
        rows = "".join(
            f"<tr><th>{escape(str(key))}</th><td><pre>{escape(json.dumps(value, ensure_ascii=False, indent=2) if isinstance(value, (dict, list)) else str(value))}</pre></td></tr>"
            for key, value in replay_state.items()
        )
        video_block = ""
        if recording.get("video"):
            video_block = """
  <section>
    <h2>Replay video</h2>
    <video controls>
      <source src="replay.webm" type="video/webm">
    </video>
  </section>"""
        raw_video_item = ""
        if recording.get("raw_video"):
            raw_video_item = '<li><a href="raw_replay.webm">raw_replay.webm</a></li>'
        html = f"""<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <title>AgentGuard Browser Replay - {escape(str(recording.get("session_id", "")))}</title>
  <style>
    body {{ font-family: Arial, sans-serif; margin: 24px; background: #f8fafc; color: #0f172a; }}
    section {{ background: white; border: 1px solid #e2e8f0; border-radius: 8px; padding: 16px; margin-bottom: 16px; }}
    img, video {{ width: min(100%, 1440px); aspect-ratio: 1440 / 1024; object-fit: contain; border: 1px solid #cbd5e1; border-radius: 8px; background: #000; }}
    table {{ border-collapse: collapse; width: 100%; }}
    th, td {{ text-align: left; vertical-align: top; border-bottom: 1px solid #e2e8f0; padding: 8px; }}
    pre {{ white-space: pre-wrap; word-break: break-word; margin: 0; }}
    .gallery {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); gap: 12px; }}
    figure {{ margin: 0; }}
    figcaption {{ margin-top: 6px; color: #475569; font-size: 13px; }}
  </style>
</head>
<body>
  <h1>AgentGuard Browser Replay</h1>
  <p>session_id=<code>{escape(str(recording.get("session_id", "")))}</code></p>
  <section>
    <h2>Replay state</h2>
    <table><tbody>{rows}</tbody></table>
  </section>
  <section>
    <h2>Final screenshot</h2>
    <img src="final.png" alt="final browser screenshot">
  </section>
  <section>
    <h2>Step screenshots</h2>
    <div class="gallery">{gallery}</div>
  </section>
{video_block}
  <section>
    <h2>Artifacts</h2>
    <ul>
      <li><a href="events.jsonl">events.jsonl</a></li>
      <li><a href="manifest.json">manifest.json</a></li>
      <li><a href="replay_state.json">replay_state.json</a></li>
      {raw_video_item}
      <li><a href="trace.zip">trace.zip</a></li>
      <li><a href="steps/">steps/</a></li>
    </ul>
  </section>
</body>
</html>"""
        path.write_text(html, encoding="utf-8")

    def _export_recording_to_downloads(self, session_id: str, recording: dict[str, Any]) -> dict[str, str]:
        target_dir = self.sandbox_dir / "downloads" / _safe_artifact_name(session_id)
        target_dir.mkdir(parents=True, exist_ok=True)
        exported: dict[str, str] = {"dir": str(target_dir)}
        copies = {
            "report": "report.html",
            "video": "replay.webm",
            "raw_video": "raw_replay.webm",
            "screenshot": "final.png",
            "events": "events.jsonl",
            "trace": "trace.zip",
            "replay_state": "replay_state.json",
            "manifest": "manifest.json",
        }
        for key, filename in copies.items():
            source = recording.get(key)
            if not source:
                continue
            source_path = Path(str(source))
            if not source_path.exists() or not source_path.is_file():
                continue
            dest = target_dir / filename
            try:
                shutil.copyfile(source_path, dest)
            except OSError:
                continue
            exported[key] = str(dest)
        steps_source = recording.get("steps_dir")
        steps_dir = Path(str(steps_source)) if steps_source else None
        if steps_dir is not None and steps_dir.exists() and steps_dir.is_dir():
            target_steps = target_dir / "steps"
            target_steps.mkdir(parents=True, exist_ok=True)
            for path in sorted(steps_dir.glob("*.png")):
                try:
                    shutil.copyfile(path, target_steps / path.name)
                except OSError:
                    continue
            exported["steps_dir"] = str(target_steps)
        return exported

    def _write_json(self, path: Path, payload: dict[str, Any]) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True), encoding="utf-8")
