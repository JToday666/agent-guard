"""Deep click-response audit for prompt_injection local Instrumentation pages."""

from __future__ import annotations

import argparse
import json
from http.server import ThreadingHTTPServer
from pathlib import Path
from threading import Thread
from typing import Any

from agentguard_langgraph_bench.bench.browser_runtime import _BenchmarkStaticHandler
from agentguard_langgraph_bench.bench.dataset_loader import load_attack_cases


COLLECT_JS = """
() => {
  function visible(el) {
    const style = window.getComputedStyle(el);
    const rect = el.getBoundingClientRect();
    if (style.display === "none" || style.visibility === "hidden" || style.opacity === "0") return false;
    if (rect.width <= 0 || rect.height <= 0) return false;
    if (el.closest("[hidden], [aria-hidden='true'], .hidden")) return false;
    return true;
  }
  const selector = "a[href],button,[role='button'],summary,input[type='submit'],input[type='button'],input[type='reset'],label[for],select";
  return Array.from(document.querySelectorAll(selector))
    .filter((el) => visible(el) && !el.disabled && el.getAttribute("aria-disabled") !== "true")
    .map((el, index) => ({
      index,
      tag: el.tagName.toLowerCase(),
      id: el.id || "",
      text: (el.innerText || el.textContent || el.value || el.getAttribute("aria-label") || "").replace(/\\s+/g, " ").trim(),
      dataPw: el.getAttribute("data-pw") || el.getAttribute("data-testid") || "",
      href: el.getAttribute("href") || ""
    }));
}
"""

SNAP_JS = """
() => ({
  href: location.href,
  hash: location.hash,
  text: document.body.innerText.replace(/\\s+/g, " ").trim(),
  lastClick: document.body.getAttribute("data-ag-last-click") || "",
  modalCount: document.querySelectorAll(".ag-modal-backdrop, .modal-overlay:not(.hidden), [role='dialog']:not([aria-hidden='true'])").length,
  drawerCount: document.querySelectorAll(".ag-drawer").length,
  popoverCount: document.querySelectorAll(".ag-popover").length,
  toastCount: document.querySelectorAll(".ag-toast").length,
  status: (document.querySelector("#ag-local-status, [role='status']") || {}).textContent || "",
  expanded: Array.from(document.querySelectorAll("[aria-expanded]")).map((el) => el.getAttribute("aria-expanded")).join("|"),
  cartCount: (document.querySelector("#cart-count") || {}).textContent || "",
  galleryIndex: document.body.getAttribute("data-ag-gallery-index") || ""
})
"""

CLICK_JS = """
(index) => {
  function visible(el) {
    const style = window.getComputedStyle(el);
    const rect = el.getBoundingClientRect();
    if (style.display === "none" || style.visibility === "hidden" || style.opacity === "0") return false;
    if (rect.width <= 0 || rect.height <= 0) return false;
    if (el.closest("[hidden], [aria-hidden='true'], .hidden")) return false;
    return true;
  }
  const selector = "a[href],button,[role='button'],summary,input[type='submit'],input[type='button'],input[type='reset'],label[for],select";
  const controls = Array.from(document.querySelectorAll(selector))
    .filter((el) => visible(el) && !el.disabled && el.getAttribute("aria-disabled") !== "true");
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


def _url_for_case(base_url: str, case: Any) -> str:
    source = case.metadata["web_entry_source_path"]
    rel = source.removeprefix("agentguard_langgraph_bench/bench/datasets/instrumentation/")
    return f"{base_url}/local-instrumentation/{rel}?mode=record&run_id=agentguard"


def _changed(before: dict[str, Any], after: dict[str, Any]) -> bool:
    return any(before.get(key) != after.get(key) for key in before)


def _wait_for_local_ui(page: Any) -> None:
    try:
        page.wait_for_function(
            "() => window.AgentGuardLocalUI && window.AgentGuardLocalUI.__installed",
            timeout=3000,
        )
    except Exception:
        pass


def run_audit(dataset: Path, output: Path, browser_name: str = "chromium") -> dict[str, Any]:
    from playwright.sync_api import sync_playwright

    cases = load_attack_cases(dataset)
    server = ThreadingHTTPServer(("127.0.0.1", 0), _BenchmarkStaticHandler)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base_url = f"http://127.0.0.1:{server.server_port}"
    report: dict[str, Any] = {"base_url": base_url, "cases": [], "clicked": 0, "findings": 0}
    try:
        with sync_playwright() as playwright:
            browser = getattr(playwright, browser_name).launch(headless=True, chromium_sandbox=False, args=["--no-sandbox"] if browser_name == "chromium" else [])
            try:
                for case in cases:
                    url = _url_for_case(base_url, case)
                    page = browser.new_page(viewport={"width": 1440, "height": 1024})
                    page.goto(url, wait_until="commit")
                    _wait_for_local_ui(page)
                    page.wait_for_timeout(800)
                    controls = page.evaluate(COLLECT_JS)
                    page.close()
                    case_entry = {"case_id": case.case_id, "url": url, "controls": len(controls), "findings": []}
                    for control in controls:
                        page = browser.new_page(viewport={"width": 1440, "height": 1024})
                        page.goto(url, wait_until="commit")
                        _wait_for_local_ui(page)
                        page.wait_for_timeout(800)
                        before = page.evaluate(SNAP_JS)
                        clicked = page.evaluate(CLICK_JS, control["index"])
                        page.wait_for_timeout(450)
                        after = page.evaluate(SNAP_JS)
                        page.close()
                        report["clicked"] += 1
                        if not clicked or not _changed(before, after):
                            report["findings"] += 1
                            case_entry["findings"].append(control)
                    report["cases"].append(case_entry)
            finally:
                browser.close()
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)

    output.parent.mkdir(parents=True, exist_ok=True)
    lines = [
        "# Prompt Injection Deep Click Audit After",
        "",
        f"- Local server: `{base_url}/local-instrumentation/`",
        f"- Controls clicked: {report['clicked']}",
        f"- Potential no-response findings: {report['findings']}",
        "",
    ]
    for case in report["cases"]:
        lines.append(f"## {case['case_id']}")
        lines.append(f"- URL: `{case['url']}`")
        lines.append(f"- Visible controls clicked: {case['controls']}")
        lines.append(f"- Findings: {len(case['findings'])}")
        for index, finding in enumerate(case["findings"], start=1):
            label = finding.get("text") or finding.get("id") or finding.get("dataPw") or "[no text]"
            lines.append(f"  {index}. `{label}` ({finding.get('tag')}) no_observed_change")
        lines.append("")
    output.write_text("\n".join(lines), encoding="utf-8")
    output.with_suffix(".json").write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    return report


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--dataset", type=Path, required=True)
    parser.add_argument("--browser", default="chromium")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    report = run_audit(args.dataset, args.output, args.browser)
    print(json.dumps({"clicked": report["clicked"], "findings": report["findings"]}, ensure_ascii=False))


if __name__ == "__main__":
    main()
