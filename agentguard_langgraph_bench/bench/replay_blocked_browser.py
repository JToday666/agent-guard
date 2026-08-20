"""replay blocked-session 确定性录制 writer（Spec 实现清单 c2）。

replay 模式下浏览器步骤被策略 block 时无真实浏览器会话、因此无录制，
agent_abuse / file_exfiltration oracle 会因此落 ``missing_browser_recording``
（PI 则靠 final_answer 事件源兜底，见 graph 的 replay 收尾改动）。本模块
在 case 收尾阶段（normalize 之后、oracle 之前）为缺失录制的会话补写一份
"blocked-session 录制"，schema 与真实录制一致，row_normalizer / oracle 等
消费方零改动。

安全约束：
* 仅 ``instrumentation_plan_mode == "replay"`` 生效（autonomous 逐字节
  不受影响）；
* 录制内容只如实记录 planned/blocked 步骤，绝不包含任何危害成功事件；
  事件行使用专用 ``blocked_browser_step`` 类型，不会被 scoring 读成已执行
  的浏览器动作（prompt_injection._event_from_browser_artifact 只认
  ``browser_tool_action`` / ``page_dom_event``）；
* 全部内容逐轮逐字节确定（固定时间戳、无随机量），repeats 间稳定。
"""

from __future__ import annotations

import base64
import json
from pathlib import Path
from typing import Any

BLOCKED_SESSION_SOURCE = "deterministic_replay_closure"
BLOCKED_SESSION_TIMESTAMP = "1970-01-01T00:00:00+00:00"
BLOCKED_STEP_EVENT_TYPE = "blocked_browser_step"

_BROWSER_ACTIONS = {
    "browser_start": "start",
    "browser_navigate": "navigate",
    "browser_input": "input",
    "browser_click": "click",
    "browser_extract_text": "extract_text",
    "browser_inspect": "inspect",
}

_TINY_PNG = base64.b64decode(
    "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8BQDwAFgwJ/lHVqVwAAAABJRU5ErkJggg=="
)


def _case_browser_session_ids(case: Any) -> list[str]:
    """镜像 row_normalizer._case_browser_session_ids 的会话 id 推导。"""
    ids: list[str] = []
    for step in getattr(case, "tool_plan", []) or []:
        if not str(step.tool).startswith("browser_"):
            continue
        candidate = step.arguments.get("session_id") or step.arguments.get("run_id")
        if isinstance(candidate, str) and candidate and candidate not in ids:
            ids.append(candidate)
    if not ids and any(
        str(step.tool).startswith("browser_") for step in getattr(case, "tool_plan", []) or []
    ):
        ids.append(case.case_id)
    return ids


def _blocked_browser_step_rows(row: dict[str, Any], session_id: str) -> list[dict[str, Any]]:
    """从 row.tool_calls 提取该会话被 block 的浏览器调用，如实记录 planned/blocked 步骤。"""
    rows: list[dict[str, Any]] = []
    for item in row.get("tool_calls") or []:
        tool_name = str(item.get("tool_name") or "")
        planned_action = _BROWSER_ACTIONS.get(tool_name)
        if planned_action is None or not item.get("blocked"):
            continue
        event = item.get("event") if isinstance(item.get("event"), dict) else {}
        args = event.get("arguments") if isinstance(event.get("arguments"), dict) else {}
        call_session = str(args.get("session_id") or args.get("run_id") or row.get("case_id") or "")
        if call_session and call_session != session_id:
            continue
        rows.append(
            {
                "event_type": BLOCKED_STEP_EVENT_TYPE,
                "session_id": session_id,
                "step_index": len(rows) + 1,
                "planned_action": planned_action,
                "tool_name": tool_name,
                "status": "blocked",
                "blocked": True,
                "executed": False,
                "decision": item.get("decision"),
                "timestamp": BLOCKED_SESSION_TIMESTAMP,
                "source": BLOCKED_SESSION_SOURCE,
                "arguments": {
                    key: args.get(key)
                    for key in ("url", "selector", "text", "value")
                    if args.get(key) is not None
                },
            }
        )
    return rows


def _planned_browser_step_rows(case: Any, session_id: str) -> list[dict[str, Any]]:
    """冻结剧本兜底：pre-model guard deny 等路径不产生 tool_calls，改从
    case.tool_plan 如实记录被 block 的计划浏览器步骤（内容仍逐字节确定）。"""
    rows: list[dict[str, Any]] = []
    for step in getattr(case, "tool_plan", []) or []:
        tool_name = str(step.tool)
        planned_action = _BROWSER_ACTIONS.get(tool_name)
        if planned_action is None:
            continue
        args = dict(getattr(step, "arguments", {}) or {})
        call_session = str(args.get("session_id") or args.get("run_id") or getattr(case, "case_id", "") or "")
        if call_session and call_session != session_id:
            continue
        rows.append(
            {
                "event_type": BLOCKED_STEP_EVENT_TYPE,
                "session_id": session_id,
                "step_index": len(rows) + 1,
                "planned_action": planned_action,
                "tool_name": tool_name,
                "status": "blocked",
                "blocked": True,
                "executed": False,
                "decision": "deny",
                "timestamp": BLOCKED_SESSION_TIMESTAMP,
                "source": BLOCKED_SESSION_SOURCE,
                "arguments": {
                    key: args.get(key)
                    for key in ("url", "selector", "text", "value")
                    if args.get(key) is not None
                },
            }
        )
    return rows


def _write_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    path.write_text(
        "".join(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n" for row in rows),
        encoding="utf-8",
    )


def write_blocked_session_recording(
    case_result_dir: Path, session_id: str, step_rows: list[dict[str, Any]]
) -> dict[str, Any]:
    """写出与真实录制同 schema 的 blocked-session 录制，返回 recording dict。"""
    artifact_dir = case_result_dir / "browser_replay_blocked_session" / session_id
    steps_dir = artifact_dir / "steps"
    steps_dir.mkdir(parents=True, exist_ok=True)
    _write_jsonl(artifact_dir / "events.jsonl", step_rows)
    _write_jsonl(artifact_dir / "action_metadata.jsonl", step_rows)
    _write_jsonl(artifact_dir / "step_actions.jsonl", step_rows)
    (artifact_dir / "final.png").write_bytes(_TINY_PNG)
    (artifact_dir / "final_full_page.png").write_bytes(_TINY_PNG)
    step_png = steps_dir / "step_001_blocked.png"
    step_png.write_bytes(_TINY_PNG)
    (artifact_dir / "report.html").write_text(
        (
            f"<html><body>blocked-session recording for {session_id}; "
            f"source {BLOCKED_SESSION_SOURCE}; step_count {len(step_rows)}; "
            "all browser steps were blocked by policy before execution.</body></html>"
        ),
        encoding="utf-8",
    )
    (artifact_dir / "final_dom.html").write_text(
        f"<html><body><main data-session-id=\"{session_id}\">blocked-session final DOM; "
        f"no browser action was executed</main></body></html>",
        encoding="utf-8",
    )
    (artifact_dir / "final_accessibility_tree.json").write_text(
        json.dumps(
            {
                "ok": True,
                "source": BLOCKED_SESSION_SOURCE,
                "snapshot": {"role": "WebArea", "name": f"blocked-session recording for {session_id}"},
            },
            sort_keys=True,
        ),
        encoding="utf-8",
    )
    replay_state = {
        "session_id": session_id,
        "step_count": len(step_rows),
        "record_mode": True,
        "diagnostic_artifact": True,
        "real_browser_artifact": False,
        "browser_started": False,
        "source": BLOCKED_SESSION_SOURCE,
    }
    (artifact_dir / "replay_state.json").write_text(
        json.dumps(replay_state, ensure_ascii=False, indent=2, sort_keys=True),
        encoding="utf-8",
    )
    (artifact_dir / "business_event_correlation_index.json").write_text(
        json.dumps(
            {
                "schema_version": "1.0",
                "session_id": session_id,
                "source": BLOCKED_SESSION_SOURCE,
                "diagnostic_artifact": True,
                "action_count": len(step_rows),
                "business_events": [],
                "correlations": [],
            },
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
        ),
        encoding="utf-8",
    )
    manifest = {
        "ok": True,
        "session_id": session_id,
        "artifact_dir": str(artifact_dir),
        "record_mode": True,
        "diagnostic_artifact": True,
        "real_browser_artifact": False,
        "browser_started": False,
        "source": BLOCKED_SESSION_SOURCE,
        "events": "events.jsonl",
        "action_metadata": "action_metadata.jsonl",
        "step_actions": "step_actions.jsonl",
        "business_event_correlation_index": "business_event_correlation_index.json",
        "replay_state": "replay_state.json",
        "report": "report.html",
        "final_dom": "final_dom.html",
        "final_accessibility_tree": "final_accessibility_tree.json",
        "final_screenshot": "final.png",
        "final_full_page_screenshot": "final_full_page.png",
    }
    (artifact_dir / "manifest.json").write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2, sort_keys=True),
        encoding="utf-8",
    )
    return {
        "ok": True,
        "session_id": session_id,
        "artifact_dir": str(artifact_dir),
        "events": str(artifact_dir / "events.jsonl"),
        "screenshot": str(artifact_dir / "final.png"),
        "full_page_screenshot": str(artifact_dir / "final_full_page.png"),
        "report": str(artifact_dir / "report.html"),
        "final_dom": str(artifact_dir / "final_dom.html"),
        "final_accessibility_tree": str(artifact_dir / "final_accessibility_tree.json"),
        "action_metadata": str(artifact_dir / "action_metadata.jsonl"),
        "step_actions": str(artifact_dir / "step_actions.jsonl"),
        "business_event_correlation_index": str(artifact_dir / "business_event_correlation_index.json"),
        "replay_state": str(artifact_dir / "replay_state.json"),
        "manifest": str(artifact_dir / "manifest.json"),
        "steps_dir": str(steps_dir),
        "step_screenshots": [str(step_png)],
        "dom_event_count": len(step_rows),
        "step_count": len(step_rows),
        "record_mode": True,
        "diagnostic_artifact": True,
        "real_browser_artifact": False,
        "browser_started": False,
        "source": BLOCKED_SESSION_SOURCE,
    }


def maybe_supplement_replay_blocked_recordings(
    case: Any, row: dict[str, Any], config: Any, case_result_dir: Path
) -> bool:
    """replay + 浏览器步骤被 block + 该会话无录制时补写 blocked-session 录制。

    返回是否补写过至少一份录制。非 replay 模式直接返回 False（no-op）。
    """
    if getattr(config, "instrumentation_plan_mode", "") != "replay":
        return False
    session_ids = _case_browser_session_ids(case)
    if not session_ids:
        return False
    has_blocked_browser_step = any(
        str(item.get("tool_name") or "").startswith("browser_") and item.get("blocked")
        for item in row.get("tool_calls") or []
    )
    # pre-model guard deny 路径不产生 tool_calls：run_status=blocked 时
    # 用冻结剧本兜底（只记录 planned/blocked 步骤，不含任何执行事件）。
    if not has_blocked_browser_step and row.get("run_status") != "blocked":
        return False
    existing_sessions = {
        str(rec.get("session_id")) for rec in row.get("browser_recordings") or [] if isinstance(rec, dict)
    }
    supplemented = False
    for session_id in session_ids:
        if session_id in existing_sessions:
            continue
        step_rows = _blocked_browser_step_rows(row, session_id) or _planned_browser_step_rows(
            case, session_id
        )
        if not step_rows:
            continue
        recording = write_blocked_session_recording(case_result_dir, session_id, step_rows)
        row.setdefault("browser_recordings", []).append(recording)
        supplemented = True
    return supplemented


def _requires_rag_answer(case: Any) -> bool:
    """镜像 scoring.memory_poisoning._requires_rag_answer 的判定。"""
    target = getattr(case, "target_behavior", None)
    condition = getattr(case, "success_condition", None)
    return (
        getattr(target, "tool", None) == "rag_answer"
        or getattr(condition, "tool", None) == "rag_answer"
        or str(getattr(condition, "type", "") or "").startswith(
            ("rag_", "delayed_", "clean_", "conflict_")
        )
    )


def maybe_supplement_replay_blocked_rag_answer(
    case: Any, row: dict[str, Any], config: Any
) -> bool:
    """replay + 被 block 终止 + 冻结剧本含 rag_answer 但无任何 rag_answer
    记录时，补写一条确定性 blocked rag_answer 工具记录。

    背景：no-context/no-provenance 等消融臂的 guard 在 pre-model hook 直接
    deny（_apply_runtime_guard_result），工具根本未下发，adapter 的
    ``_skipped_rag_answer`` 不产生记录，MP oracle 既有的 rag_answer_blocked
    豁免路径（_last_blocked_tool 要求 tool_name=rag_answer 且 status ∈
    {blocked, quarantined}）够不着。本补写与 ``_skipped_rag_answer`` 的
    记录形态同构（如实记录计划中的 rag_answer 被策略 block），只依赖冻结
    剧本，逐字节确定；非 replay 直接 no-op。返回是否补写过。
    """
    if getattr(config, "instrumentation_plan_mode", "") != "replay":
        return False
    if getattr(case, "attack_type", "") != "memory_poisoning":
        return False
    if row.get("run_status") != "blocked":
        return False
    if not _requires_rag_answer(case):
        return False
    plans_rag_answer = any(
        str(step.tool) == "rag_answer" for step in getattr(case, "tool_plan", []) or []
    )
    if not plans_rag_answer:
        return False
    tool_calls = row.get("tool_calls")
    if not isinstance(tool_calls, list):
        return False
    if any(item.get("tool_name") == "rag_answer" for item in tool_calls):
        return False
    tool_calls.append(
        {
            "tool_name": "rag_answer",
            "call_id": f"replay_blocked_{case.case_id}_rag_answer",
            "executed": False,
            "blocked": True,
            "decision": "deny",
            "status": "blocked",
            "result": None,
            "error": None,
            "safe_message": "rag_answer was skipped because the run was blocked by policy before tool dispatch.",
            "source": BLOCKED_SESSION_SOURCE,
        }
    )
    return True
