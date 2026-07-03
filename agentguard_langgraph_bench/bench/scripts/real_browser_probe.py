import argparse
import json
import os
from pathlib import Path
import sys

PROJECT_ROOT = Path(__file__).resolve().parents[2]
REPO_ROOT = PROJECT_ROOT.parent
WORKSPACE_ROOT = REPO_ROOT.parent
sys.path.insert(0, str(REPO_ROOT))
os.environ.setdefault("PLAYWRIGHT_BROWSERS_PATH", str(WORKSPACE_ROOT / "Instrumentation" / ".playwright-browsers"))

from agentguard_langgraph_bench.bench.config import ensure_sandbox
from agentguard_langgraph_bench.bench.dataset_loader import load_attack_cases
from agentguard_langgraph_bench.bench.tools import MockToolRegistry


DEFAULT_SOURCE = (
    "Instrumentation/A1_Identity_Information_Leakage/"
    "EIA_A1_18_medium/adv_modified_file_action_generation_form_type1_most_bot.html"
)


def _source_for_case(case_id: str, dataset: Path) -> str:
    for case in load_attack_cases(dataset):
        if case.case_id != case_id:
            continue
        source = case.metadata.get("web_entry_source_path") or ""
        if source:
            return source
        for step in case.tool_plan:
            candidate = step.arguments.get("source_path")
            if isinstance(candidate, str) and candidate:
                return candidate
        raise SystemExit(f"case {case_id} has no browser source_path")
    raise SystemExit(f"case {case_id} not found in {dataset}")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Verify real Playwright opening for an Instrumentation page")
    parser.add_argument("--case-id", default="", help="AttackCase id whose Instrumentation page should be opened")
    parser.add_argument(
        "--dataset",
        default="agentguard_langgraph_bench/bench/datasets/attack_cases",
        help="AttackCase JSONL file or directory used with --case-id",
    )
    parser.add_argument("--source-path", default="", help="Explicit Instrumentation source_path to open")
    parser.add_argument("--sandbox", default="/tmp/ag_real_browser_probe_ok", help="Sandbox output directory")
    parser.add_argument("--browser-engine", choices=["chromium", "firefox", "webkit"], default="chromium")
    return parser


def _probe_result(
    *,
    start: dict,
    text: dict,
    recording: dict,
    source: str,
    browser_engine: str,
) -> dict:
    screenshot = Path(start.get("screenshot", ""))
    trace_exists = bool(recording.get("trace")) and Path(str(recording["trace"])).exists()
    report_exists = bool(recording.get("report")) and Path(str(recording["report"])).exists()
    video_exists = bool(recording.get("video")) and Path(str(recording["video"])).exists()
    return {
        "ok": bool(start.get("real_browser"))
        and screenshot.exists()
        and bool(text.get("text"))
        and trace_exists
        and report_exists,
        "real_browser": start.get("real_browser"),
        "browser_engine": browser_engine,
        "source_path": source,
        "url": start.get("url", ""),
        "screenshot": str(screenshot),
        "screenshot_exists": screenshot.exists(),
        "recording": recording,
        "video_exists": video_exists,
        "trace_exists": trace_exists,
        "report_exists": report_exists,
        "step_count": len(recording.get("step_screenshots") or []),
        "text_len": len(text.get("text", "")),
        "text_preview": text.get("text", "")[:200].replace("\n", " "),
    }


def main() -> int:
    args = build_parser().parse_args()
    sandbox = Path(args.sandbox)
    ensure_sandbox(sandbox)
    tools = MockToolRegistry(sandbox, browser_mode="real", browser_engine=args.browser_engine)
    source = args.source_path or (_source_for_case(args.case_id, Path(args.dataset)) if args.case_id else DEFAULT_SOURCE)
    try:
        start = tools.browser_start("instrumentation://" + source, run_id="probe", source_path=source)
        text = tools.browser_extract_text(session_id="probe")
        recording = tools.finalize_browser_session("probe") or {}
        result = _probe_result(
            start=start,
            text=text,
            recording=recording,
            source=source,
            browser_engine=args.browser_engine,
        )
        print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
    finally:
        tools.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
