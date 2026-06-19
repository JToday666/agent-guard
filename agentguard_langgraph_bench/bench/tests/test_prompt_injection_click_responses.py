from __future__ import annotations

import json
from http.server import ThreadingHTTPServer
from pathlib import Path
from threading import Thread

import pytest

from agentguard_langgraph_bench.bench.browser_runtime import _BenchmarkStaticHandler
from agentguard_langgraph_bench.bench.dataset_loader import load_attack_cases


COLLECT_CONTROLS_JS = """
() => {
  function visible(el) {
    const style = window.getComputedStyle(el);
    const rect = el.getBoundingClientRect();
    if (style.display === "none" || style.visibility === "hidden" || style.opacity === "0") return false;
    if (rect.width <= 0 || rect.height <= 0) return false;
    if (el.closest("[hidden], [aria-hidden='true'], .hidden")) return false;
    return true;
  }
  function actionable(el) {
    const tag = el.tagName.toLowerCase();
    if (tag === "a") {
      const href = el.getAttribute("href") || "";
      return href && !href.startsWith("link://");
    }
    if (tag === "label") {
      const target = document.getElementById(el.getAttribute("for") || "");
      if (!target) return false;
      const type = (target.getAttribute("type") || "").toLowerCase();
      return ["checkbox", "radio", "file", "button", "submit", "reset"].includes(type);
    }
    return true;
  }
  const selector = [
    "a[href]",
    "button",
    "[role='button']",
    "summary",
    "input[type='submit']",
    "input[type='button']",
    "input[type='reset']",
    "label[for]",
    "select"
  ].join(",");
  return Array.from(document.querySelectorAll(selector))
    .filter((el) => visible(el) && actionable(el) && !el.disabled && el.getAttribute("aria-disabled") !== "true")
    .map((el, index) => {
      const rect = el.getBoundingClientRect();
      return {
        index,
        tag: el.tagName.toLowerCase(),
        id: el.id || "",
        text: (el.innerText || el.textContent || el.value || el.getAttribute("aria-label") || "").replace(/\\s+/g, " ").trim(),
        href: el.getAttribute("href") || "",
        dataPw: el.getAttribute("data-pw") || el.getAttribute("data-testid") || "",
        x: rect.x,
        y: rect.y
      };
    });
}
"""


SNAPSHOT_JS = """
() => {
  const body = document.body;
  return {
    href: window.location.href,
    hash: window.location.hash,
    text: body ? body.innerText.replace(/\\s+/g, " ").trim() : "",
    lastClick: body ? body.getAttribute("data-ag-last-click") || "" : "",
    changeCount: body ? body.getAttribute("data-ag-change-count") || "" : "",
    modalCount: document.querySelectorAll(".ag-modal-backdrop, .modal-overlay:not(.hidden), [role='dialog']:not([aria-hidden='true'])").length,
    drawerCount: document.querySelectorAll(".ag-drawer").length,
    popoverCount: document.querySelectorAll(".ag-popover").length,
    toastCount: document.querySelectorAll(".ag-toast").length,
    status: (document.querySelector("#ag-local-status, [role='status']") || {}).textContent || "",
    expanded: Array.from(document.querySelectorAll("[aria-expanded]")).map((el) => el.getAttribute("aria-expanded")).join("|"),
    cartCount: (document.querySelector("#cart-count") || {}).textContent || "",
    galleryIndex: body ? body.getAttribute("data-ag-gallery-index") || "" : ""
  };
}
"""


CLICK_CONTROL_JS = """
(index) => {
  const selector = [
    "a[href]",
    "button",
    "[role='button']",
    "summary",
    "input[type='submit']",
    "input[type='button']",
    "input[type='reset']",
    "label[for]",
    "select"
  ].join(",");
  function visible(el) {
    const style = window.getComputedStyle(el);
    const rect = el.getBoundingClientRect();
    if (style.display === "none" || style.visibility === "hidden" || style.opacity === "0") return false;
    if (rect.width <= 0 || rect.height <= 0) return false;
    if (el.closest("[hidden], [aria-hidden='true'], .hidden")) return false;
    return true;
  }
  function actionable(el) {
    const tag = el.tagName.toLowerCase();
    if (tag === "a") {
      const href = el.getAttribute("href") || "";
      return href && !href.startsWith("link://");
    }
    if (tag === "label") {
      const target = document.getElementById(el.getAttribute("for") || "");
      if (!target) return false;
      const type = (target.getAttribute("type") || "").toLowerCase();
      return ["checkbox", "radio", "file", "button", "submit", "reset"].includes(type);
    }
    return true;
  }
  const controls = Array.from(document.querySelectorAll(selector))
    .filter((el) => visible(el) && actionable(el) && !el.disabled && el.getAttribute("aria-disabled") !== "true");
  const el = controls[index];
  if (!el) return false;
  el.scrollIntoView({ block: "center", inline: "center" });
  if (el.tagName.toLowerCase() === "select") {
    el.dispatchEvent(new MouseEvent("click", { bubbles: true, cancelable: true }));
    el.dispatchEvent(new Event("change", { bubbles: true, cancelable: true }));
    return true;
  }
  el.click();
  return true;
}
"""


@pytest.fixture(scope="module")
def local_server():
    server = ThreadingHTTPServer(("127.0.0.1", 0), _BenchmarkStaticHandler)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


@pytest.fixture(scope="module")
def prompt_cases():
    dataset = Path(__file__).resolve().parents[1] / "datasets" / "attack_cases" / "prompt_injection.jsonl"
    return load_attack_cases(dataset)


def _case_url(base_url: str, case) -> str:
    source = case.metadata["web_entry_source_path"]
    rel = source.removeprefix("agentguard_langgraph_bench/bench/datasets/instrumentation/")
    return f"{base_url}/local-instrumentation/{rel}?mode=record&run_id=agentguard"


def _changed(before: dict, after: dict) -> bool:
    keys = [
        "href",
        "hash",
        "text",
        "lastClick",
        "changeCount",
        "modalCount",
        "drawerCount",
        "popoverCount",
        "toastCount",
        "status",
        "expanded",
        "cartCount",
        "galleryIndex",
    ]
    return any(before.get(key) != after.get(key) for key in keys)


def _wait_for_local_ui(page) -> None:
    try:
        page.wait_for_function(
            "() => document.body",
            timeout=5000,
        )
    except Exception:
        pass
    try:
        page.wait_for_function(
            "() => window.AgentGuardLocalUI && window.AgentGuardLocalUI.__installed",
            timeout=3000,
        )
    except Exception:
        pass


@pytest.mark.parametrize("case_id", [f"PI-{index:03d}" for index in range(1, 11)])
def test_prompt_injection_entry_controls_have_visible_responses(local_server, prompt_cases, case_id):
    pytest.importorskip("playwright.sync_api")
    from playwright.sync_api import sync_playwright

    case = next(item for item in prompt_cases if item.case_id == case_id)
    url = _case_url(local_server, case)
    failures = []
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(headless=True, chromium_sandbox=False, args=["--no-sandbox"])
        try:
            page = browser.new_page(viewport={"width": 1440, "height": 1024})
            page.goto(url, wait_until="commit")
            _wait_for_local_ui(page)
            page.wait_for_timeout(800)
            controls = page.evaluate(COLLECT_CONTROLS_JS)
            page.close()

            for control in controls:
                page = browser.new_page(viewport={"width": 1440, "height": 1024})
                page.goto(url, wait_until="commit")
                _wait_for_local_ui(page)
                page.wait_for_timeout(800)
                before = page.evaluate(SNAPSHOT_JS)
                clicked = page.evaluate(CLICK_CONTROL_JS, control["index"])
                page.wait_for_timeout(450)
                after = page.evaluate(SNAPSHOT_JS)
                if not clicked or not _changed(before, after):
                    failures.append(control)
                page.close()
        finally:
            browser.close()

    assert not failures, json.dumps({"case_id": case_id, "failures": failures[:20]}, ensure_ascii=False, indent=2)
