"""Artifact integrity checks for browser replay evidence."""

from __future__ import annotations

import hashlib
import json
import re
import shutil
import subprocess
import zipfile
from html.parser import HTMLParser
from pathlib import Path
from typing import Any
from urllib.parse import unquote, urlsplit

CONTINUOUS_VIDEO_MIN_BYTES = 8000
OPTIONAL_UNPRODUCED_GENERIC_ARTIFACTS = {
    "llm_prompts/round_1_redacted.json",
    "llm_responses/round_1_redacted.json",
}


def build_artifact_integrity_manifest(run_or_artifact_dir: Path, *, output_path: Path | None = None) -> dict[str, Any]:
    root = run_or_artifact_dir.expanduser().resolve()
    replay_dirs = _find_replay_dirs(root)
    if replay_dirs:
        cases = {_case_key_for_replay_dir(case_dir): check_case_artifacts(case_dir, root=root) for case_dir in replay_dirs}
    else:
        cases = {_case_key_for_generic_case_dir(case_dir): check_generic_case_artifacts(case_dir, root=root) for case_dir in _find_generic_case_dirs(root)}
    manifest = {
        "schema_version": "1.0",
        "root": str(root),
        "case_count": len(cases),
        "cases": cases,
        "ok": bool(cases) and all(item.get("ok") for item in cases.values()),
    }
    if not cases:
        manifest["error"] = "no cases indexed"
    if output_path is not None:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(json.dumps(manifest, ensure_ascii=False, indent=2, sort_keys=True), encoding="utf-8")
    return manifest


def check_generic_case_artifacts(case_dir: Path, *, root: Path | None = None) -> dict[str, Any]:
    case_dir = case_dir.expanduser().resolve()
    root = root.expanduser().resolve() if root is not None else case_dir
    required = [
        "case_result.json",
        "tool_results.jsonl",
        "tool_call_events.jsonl",
        "audit_events.jsonl",
        "policy_decisions.jsonl",
        "evidence_index.json",
        "sandbox_diff.json",
        "agent_visible_prompt_contamination.json",
        "llm_prompts/round_1_redacted.json",
        "llm_responses/round_1_redacted.json",
        "mcp/calls.jsonl",
        "mcp/descriptors.jsonl",
        "mcp/catalog_diff.jsonl",
        "mcp/service_requests.jsonl",
    ]
    optional = [
        "mcp/collections.jsonl",
        "mcp/finance_queries.jsonl",
        "mcp/finance_news_queries.jsonl",
        "mcp/github_audits.jsonl",
        "mcp/github_repository_events.jsonl",
        "mcp/github_file_reads.jsonl",
        "mcp/fetched_pages.jsonl",
        "mcp/maps_place_queries.jsonl",
        "mcp/playwright_navigation.jsonl",
        "mcp/search_queries.jsonl",
        "rag/answers.jsonl",
        "browser/events.jsonl",
        "browser/final_state.json",
    ]
    if _generic_case_is_memory_poisoning(case_dir):
        required.extend(
            [
                "memory_poisoning_evaluation_report.json",
                "side_effects/current_case/memory/store.jsonl",
                "side_effects/current_case/memory/reads.jsonl",
                "side_effects/current_case/memory/searches.jsonl",
                "side_effects/current_case/rag/queries.jsonl",
                "side_effects/current_case/rag/answers.jsonl",
                "side_effects/current_case/api/requests.jsonl",
                "side_effects/scenario_snapshot/memory/store.jsonl",
                "side_effects/scenario_snapshot/memory/reads.jsonl",
                "side_effects/scenario_snapshot/memory/searches.jsonl",
                "side_effects/scenario_snapshot/rag/queries.jsonl",
                "side_effects/scenario_snapshot/rag/answers.jsonl",
                "side_effects/scenario_snapshot/api/requests.jsonl",
            ]
        )
    artifacts: list[dict[str, Any]] = []
    for relative in required:
        artifacts.append(_check_case_relative(case_dir, relative, root=root))
    for relative in optional:
        path = case_dir / relative
        if path.exists():
            artifacts.append(_check_case_relative(case_dir, relative, root=root))
    case_id = _case_key_for_generic_case_dir(case_dir)
    case_scoped = _generic_case_mcp_logs_case_scoped(case_dir, case_id)
    optional_unproduced = _generic_case_optional_unproduced_artifacts(case_dir)
    required_missing = [
        item
        for item in artifacts
        if item["type"] in required and not item.get("exists") and item["type"] not in optional_unproduced
    ]
    parse_failures = [item for item in artifacts if item.get("exists") and item.get("parse_ok") is False]
    critical_errors = [f"missing:{item['type']}" for item in required_missing]
    critical_errors.extend(f"parse:{item['type']}:{item.get('error')}" for item in parse_failures)
    if not case_scoped:
        critical_errors.append("mcp_case_scope_violation")
    return {
        "case_id": case_id,
        "artifact_dir": _relative(case_dir, root),
        "diagnostic_artifact": False,
        "ok": not critical_errors,
        "critical_ok": not critical_errors,
        "artifacts": artifacts,
        "case_scoped_mcp_logs": case_scoped,
        "cross_checks": {"critical_errors": [] if case_scoped else ["mcp_case_scope_violation"], "warnings": [], "errors": []},
        "warnings": [],
        "errors": sorted({item.get("error") for item in artifacts if item.get("error")}),
        "critical_errors": sorted(set(critical_errors)),
    }


def check_case_artifacts(case_dir: Path, *, root: Path | None = None) -> dict[str, Any]:
    case_dir = case_dir.expanduser().resolve()
    root = root.expanduser().resolve() if root is not None else case_dir
    diagnostic_artifact = _is_diagnostic_artifact(case_dir)
    artifacts: list[dict[str, Any]] = []
    for name in (
        "events.jsonl",
        "final.png",
        "final_full_page.png",
        "final_dom.html",
        "final_accessibility_tree.json",
        "action_metadata.jsonl",
        "step_actions.jsonl",
        "business_event_correlation_index.json",
        "replay.webm",
        "trace.zip",
        "report.html",
        "replay_state.json",
        "video_timeline.json",
        "continuous_frames_manifest.json",
    ):
        path = case_dir / name
        kind = name.rsplit(".", 1)[-1]
        if name.endswith(".jsonl"):
            artifacts.append(_check_jsonl(path, root=root, artifact_type=name))
        elif name.endswith(".png"):
            artifacts.append(_check_png(path, root=root, artifact_type=name))
        elif name.endswith(".webm"):
            artifacts.append(
                _check_webm(
                    path,
                    root=root,
                    artifact_type=name,
                    allow_zero_warning=diagnostic_artifact,
                )
            )
        elif name.endswith(".zip"):
            artifacts.append(_check_zip(path, root=root, artifact_type=name, allow_empty_warning=diagnostic_artifact))
        elif name.endswith(".html"):
            artifacts.append(_check_html(path, root=root, artifact_type=name))
        elif name.endswith(".json"):
            artifacts.append(_check_json(path, root=root, artifact_type=name))
        else:
            artifacts.append(_check_text(path, root=root, artifact_type=kind))
    steps_dir = case_dir / "steps"
    step_artifacts = [_check_png(path, root=root, artifact_type="step_png") for path in sorted(steps_dir.glob("*.png"))]
    artifacts.extend(step_artifacts)
    cross_checks = _cross_check_case(case_dir, artifacts)
    errors = [item for item in artifacts if item.get("error")]
    if diagnostic_artifact:
        errors = [
            item
            for item in errors
            if item.get("type") not in {"video_timeline.json", "continuous_frames_manifest.json"}
        ]
    parse_failures = [item for item in artifacts if item.get("exists") and item.get("parse_ok") is False]
    if diagnostic_artifact:
        parse_failures = [
            item
            for item in parse_failures
            if item.get("type")
            not in {
                "final_dom.html",
                "report.html",
                "final.png",
                "final_full_page.png",
                "step_png",
                "replay.webm",
                "trace.zip",
                "video_timeline.json",
                "continuous_frames_manifest.json",
            }
        ]
    critical_errors = _critical_artifact_errors(errors, diagnostic_artifact=diagnostic_artifact) + cross_checks["critical_errors"]
    warning_messages = [warning for item in artifacts for warning in item.get("warnings", [])] + cross_checks["warnings"]
    error_messages = [item.get("error") for item in errors if item.get("error")] + cross_checks["errors"]
    return {
        "case_id": _case_key_for_replay_dir(case_dir),
        "artifact_dir": _relative(case_dir, root),
        "diagnostic_artifact": diagnostic_artifact,
        "ok": not critical_errors and not parse_failures,
        "critical_ok": not critical_errors and not parse_failures,
        "artifacts": artifacts,
        "cross_checks": cross_checks,
        "warnings": sorted(set(warning_messages)),
        "errors": sorted(set(error_messages)),
        "critical_errors": sorted(set(critical_errors)),
    }


def _case_key_for_replay_dir(case_dir: Path) -> str:
    if case_dir.name == "browser_replay" and case_dir.parent.name:
        return case_dir.parent.name
    return case_dir.name


def _find_replay_dirs(root: Path) -> list[Path]:
    case_replay_dirs = sorted(path for path in (root / "cases").glob("*/browser_replay") if path.is_dir())
    if case_replay_dirs or (root / "cases").is_dir():
        return case_replay_dirs
    candidates = [path for path in root.rglob("replay_artifacts") if path.is_dir()]
    candidates.extend(path for path in root.rglob("browser_replay") if path.is_dir())
    replay_dirs: list[Path] = []
    for parent in candidates:
        if parent.name == "browser_replay":
            replay_dirs.append(parent)
        else:
            replay_dirs.extend(path for path in sorted(parent.iterdir()) if path.is_dir())
    if not replay_dirs and (root / "events.jsonl").exists():
        replay_dirs.append(root)
    return replay_dirs


def _find_generic_case_dirs(root: Path) -> list[Path]:
    cases_root = root / "cases"
    if cases_root.is_dir():
        return sorted(path for path in cases_root.iterdir() if path.is_dir() and (path / "case_result.json").exists())
    if (root / "case_result.json").exists():
        return [root]
    return []


def _case_key_for_generic_case_dir(case_dir: Path) -> str:
    return case_dir.name


def _generic_case_is_memory_poisoning(case_dir: Path) -> bool:
    case_result = case_dir / "case_result.json"
    if not case_result.exists():
        return False
    try:
        payload = json.loads(case_result.read_text(encoding="utf-8"))
    except Exception:
        return False
    metadata = payload.get("metadata") if isinstance(payload, dict) and isinstance(payload.get("metadata"), dict) else {}
    return bool(
        isinstance(payload, dict)
        and (payload.get("attack_type") == "memory_poisoning" or metadata.get("source_dataset") == "PoisonedRAG")
    )


def _generic_case_optional_unproduced_artifacts(case_dir: Path) -> set[str]:
    evidence_index = case_dir / "evidence_index.json"
    if not evidence_index.exists():
        return set()
    try:
        payload = json.loads(evidence_index.read_text(encoding="utf-8"))
    except Exception:
        return set()
    if not isinstance(payload, dict) or not isinstance(payload.get("missing"), list):
        return set()
    optional: set[str] = set()
    for item in payload["missing"]:
        if not isinstance(item, dict):
            continue
        path = str(item.get("path") or "")
        reason = str(item.get("reason") or "")
        if path in OPTIONAL_UNPRODUCED_GENERIC_ARTIFACTS and reason == "not produced":
            optional.add(path)
    return optional


def _check_case_relative(case_dir: Path, relative: str, *, root: Path) -> dict[str, Any]:
    path = case_dir / relative
    if relative.endswith(".jsonl"):
        return _check_jsonl(path, root=root, artifact_type=relative)
    if relative.endswith(".json"):
        return _check_json(path, root=root, artifact_type=relative)
    return _check_text(path, root=root, artifact_type=relative)


def _generic_case_mcp_logs_case_scoped(case_dir: Path, case_id: str) -> bool:
    mcp_dir = case_dir / "mcp"
    if not mcp_dir.exists():
        return False
    for path in sorted(mcp_dir.glob("*.jsonl")):
        try:
            with path.open("r", encoding="utf-8") as handle:
                for line in handle:
                    if not line.strip():
                        continue
                    payload = json.loads(line)
                    if not isinstance(payload, dict):
                        return False
                    record_case_id = _nested_case_id(payload)
                    if record_case_id and record_case_id != case_id:
                        return False
        except Exception:
            return False
    return True


def _nested_case_id(value: Any) -> str:
    if isinstance(value, dict):
        for key in ("case_id", "caseId"):
            if value.get(key):
                return str(value[key])
        for item in value.values():
            found = _nested_case_id(item)
            if found:
                return found
    if isinstance(value, list):
        for item in value:
            found = _nested_case_id(item)
            if found:
                return found
    return ""


def _is_diagnostic_artifact(case_dir: Path) -> bool:
    manifest = case_dir / "manifest.json"
    if not manifest.exists():
        return False
    try:
        payload = json.loads(manifest.read_text(encoding="utf-8"))
    except Exception:
        return False
    return bool(isinstance(payload, dict) and payload.get("diagnostic_artifact") is True)


def _base_artifact(path: Path, root: Path, artifact_type: str) -> dict[str, Any]:
    exists = path.exists()
    payload = {
        "type": artifact_type,
        "run_relative_path": _relative(path, root),
        "repo_path": _relative(path, Path.cwd()) if _is_under(path, Path.cwd()) else _relative(path, root),
        "debug_local_path": str(path),
        "exists": exists,
        "size_bytes": path.stat().st_size if exists else 0,
        "sha256": _sha256(path) if exists and path.is_file() else None,
        "parse_ok": False if exists else None,
        "warnings": [],
        "error": None if exists else "missing",
    }
    return payload


def _check_jsonl(path: Path, *, root: Path, artifact_type: str) -> dict[str, Any]:
    item = _base_artifact(path, root, artifact_type)
    if not item["exists"]:
        return item
    count = 0
    try:
        with path.open("r", encoding="utf-8") as handle:
            for line in handle:
                if line.strip():
                    json.loads(line)
                    count += 1
        item.update({"parse_ok": True, "record_count": count, "error": None})
    except Exception as exc:
        item["error"] = f"jsonl_parse_error:{exc}"
    return item


def _check_json(path: Path, *, root: Path, artifact_type: str) -> dict[str, Any]:
    item = _base_artifact(path, root, artifact_type)
    if not item["exists"]:
        return item
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        item.update({"parse_ok": True, "error": None})
        if isinstance(data, dict):
            item["keys"] = sorted(data)[:20]
    except Exception as exc:
        item["error"] = f"json_parse_error:{exc}"
    return item


def _check_text(path: Path, *, root: Path, artifact_type: str) -> dict[str, Any]:
    item = _base_artifact(path, root, artifact_type)
    if not item["exists"]:
        return item
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
        item.update({"parse_ok": True, "line_count": len(text.splitlines()), "error": None})
    except Exception as exc:
        item["error"] = f"text_parse_error:{exc}"
    return item


def _check_png(path: Path, *, root: Path, artifact_type: str) -> dict[str, Any]:
    item = _base_artifact(path, root, artifact_type)
    if not item["exists"]:
        return item
    try:
        from PIL import Image
    except Exception as exc:
        return _check_png_header_fallback(path, item, f"pillow_unavailable:{exc}")
    try:
        with Image.open(path) as image:
            image.verify()
            item.update({"parse_ok": True, "width": image.width, "height": image.height, "mode": image.mode, "error": None})
            if image.width <= 1 or image.height <= 1:
                item["error"] = f"png_placeholder_size:{image.width}x{image.height}"
    except Exception as exc:
        fallback = _check_png_header_fallback(path, item, f"pillow_parse_error:{exc}")
        if fallback.get("error") == "png_header_parse_error":
            fallback["error"] = f"png_parse_error:{exc}"
        return fallback
    return item


def _critical_artifact_errors(error_items: list[dict[str, Any]], *, diagnostic_artifact: bool) -> list[str]:
    critical: list[str] = []
    for item in error_items:
        error = str(item.get("error") or "")
        artifact_type = str(item.get("type") or "")
        if not error:
            continue
        if artifact_type in {"events.jsonl", "action_metadata.jsonl"}:
            critical.append(error)
        elif artifact_type in {"final.png", "final_full_page.png", "step_png"} and (
            error.startswith("png_placeholder_size")
            or error.startswith("png_parse_error")
            or error == "missing"
        ):
            if not diagnostic_artifact:
                critical.append(error)
        elif artifact_type == "replay.webm" and (
            error.startswith("webm_too_small:0")
            or error == "webm_too_small:0"
            or error.startswith("webm_parse_error")
        ):
            critical.append(error)
    return critical


def _check_png_header_fallback(path: Path, item: dict[str, Any], warning: str) -> dict[str, Any]:
    try:
        data = path.read_bytes()
    except Exception as exc:
        item["error"] = f"png_read_error:{exc}"
        return item
    if not data.startswith(b"\x89PNG\r\n\x1a\n"):
        item["error"] = "png_header_parse_error"
        return item
    width, height = _png_dimensions(data)
    item.update({"parse_ok": True, "width": width, "height": height, "error": None})
    if width is not None and height is not None and (width <= 1 or height <= 1):
        item["error"] = f"png_placeholder_size:{width}x{height}"
    item["warnings"].append(warning)
    item["warnings"].append("png_header_only_validation")
    return item


def _png_dimensions(data: bytes) -> tuple[int | None, int | None]:
    if len(data) < 24 or data[12:16] != b"IHDR":
        return None, None
    try:
        import struct

        return struct.unpack(">II", data[16:24])
    except Exception:
        return None, None


def _check_webm(path: Path, *, root: Path, artifact_type: str, allow_zero_warning: bool = False) -> dict[str, Any]:
    item = _base_artifact(path, root, artifact_type)
    if not item["exists"]:
        return item
    if item["size_bytes"] == 0 and allow_zero_warning:
        item.update({"parse_ok": None, "error": None})
        item["warnings"].append("empty_diagnostic_video")
        return item
    if item["size_bytes"] < CONTINUOUS_VIDEO_MIN_BYTES:
        item["error"] = f"webm_too_small:{item['size_bytes']}"
        return item
    ffprobe = shutil.which("ffprobe")
    if not ffprobe:
        item["error"] = "ffprobe_unavailable"
        return item
    try:
        completed = subprocess.run(
            [
                ffprobe,
                "-v",
                "error",
                "-show_entries",
                "stream=codec_name,width,height,duration",
                "-show_entries",
                "format=duration",
                "-of",
                "json",
                str(path),
            ],
            check=True,
            capture_output=True,
            text=True,
            timeout=10,
        )
        data = json.loads(completed.stdout or "{}")
        streams = data.get("streams") or []
        video_stream = next((stream for stream in streams if stream.get("codec_name")), {})
        fmt = data.get("format") if isinstance(data.get("format"), dict) else {}
        item.update(
            {
                "parse_ok": True,
                "codec": video_stream.get("codec_name"),
                "width": video_stream.get("width"),
                "height": video_stream.get("height"),
                "duration": video_stream.get("duration") or fmt.get("duration"),
                "error": None,
            }
        )
    except Exception as exc:
        item["error"] = f"webm_parse_error:{exc}"
    return item


def _check_zip(path: Path, *, root: Path, artifact_type: str, allow_empty_warning: bool = False) -> dict[str, Any]:
    item = _base_artifact(path, root, artifact_type)
    if not item["exists"]:
        return item
    if item["size_bytes"] == 0 and allow_empty_warning:
        item.update({"parse_ok": None, "error": None})
        item["warnings"].append("empty_diagnostic_trace")
        return item
    try:
        with zipfile.ZipFile(path) as archive:
            members = archive.namelist()
            bad = archive.testzip()
        item.update({"parse_ok": bad is None, "member_count": len(members), "members_preview": members[:20], "error": None if bad is None else f"zip_bad_member:{bad}"})
    except Exception as exc:
        item["error"] = f"zip_parse_error:{exc}"
    return item


def _check_html(path: Path, *, root: Path, artifact_type: str) -> dict[str, Any]:
    item = _check_text(path, root=root, artifact_type=artifact_type)
    if not item["exists"] or item.get("parse_ok") is not True:
        return item
    parser = _LinkParser()
    parser.feed(path.read_text(encoding="utf-8", errors="replace"))
    missing: list[str] = []
    for ref in parser.refs:
        if _is_external_or_non_file_ref(ref):
            continue
        if not _html_ref_exists(path, root, ref):
            missing.append(ref)
    item["referenced_files"] = parser.refs
    item["missing_references"] = sorted(set(missing))
    if missing:
        item["parse_ok"] = False
        item["error"] = "html_missing_references"
    return item


def _cross_check_case(case_dir: Path, artifacts: list[dict[str, Any]]) -> dict[str, list[str]]:
    warnings: list[str] = []
    errors: list[str] = []
    critical_errors: list[str] = []
    state_path = case_dir / "replay_state.json"
    manifest_path = case_dir / "manifest.json"
    report_path = case_dir / "report.html"
    frames_path = case_dir / "replay_frames.txt"
    raw_video_path = case_dir / "raw_replay.webm"
    timeline_path = case_dir / "video_timeline.json"
    continuous_manifest_path = case_dir / "continuous_frames_manifest.json"
    continuous_frames_dir = case_dir / "continuous_frames"
    if raw_video_path.exists():
        critical_errors.append("raw_replay_must_not_exist")
    manifest = _read_json(manifest_path)
    if isinstance(manifest, dict):
        if manifest.get("diagnostic_artifact") is True and manifest.get("real_browser_artifact") is True:
            critical_errors.append("artifact_manifest_conflicting_diagnostic_and_real_browser")
        if manifest.get("real_browser_artifact") is True and manifest.get("browser_started") is not True:
            critical_errors.append("real_browser_artifact_without_browser_started")
    state: dict[str, Any] | None = None
    if state_path.exists():
        try:
            loaded_state = json.loads(state_path.read_text(encoding="utf-8"))
            state = loaded_state if isinstance(loaded_state, dict) else {}
        except Exception as exc:
            critical_errors.append(f"replay_state_parse_error:{exc}")
    if state is not None:
        if state.get("diagnostic_artifact") is True and state.get("real_browser_artifact") is True:
            critical_errors.append("replay_state_conflicting_diagnostic_and_real_browser")
        if state.get("video_source") != "continuous_frame_sampler" and not _is_diagnostic_artifact(case_dir):
            critical_errors.append("replay_state_video_source_not_continuous_frame_sampler")
        if state.get("video_source") == "step_screenshots":
            critical_errors.append("legacy_step_screenshot_video_source")
        if state.get("step_screenshot_video_used") is True:
            critical_errors.append("step_screenshot_video_used")
        if state.get("raw_replay_absent") is not True and not _is_diagnostic_artifact(case_dir):
            critical_errors.append("replay_state_raw_replay_absent_false")
        if int(state.get("continuous_frame_count") or 0) < 2 and not _is_diagnostic_artifact(case_dir):
            warnings.append("replay_state_continuous_frame_count_lt_2")
    if state is not None and report_path.exists():
        try:
            html = report_path.read_text(encoding="utf-8", errors="replace")
            for key in ("step_count", "dom_event_count", "video_source"):
                if key in state and str(state[key]) not in html:
                    warnings.append(f"report_state_mismatch:{key}")
        except Exception as exc:
            warnings.append(f"replay_state_report_cross_check_error:{exc}")
    if frames_path.exists():
        warnings.append("legacy_step_replay_manifest_present")
    replay_item = next((item for item in artifacts if item.get("type") == "replay.webm"), {})
    duration = _float_or_none(replay_item.get("duration"))
    if replay_item.get("exists") and replay_item.get("parse_ok") is True:
        if duration is None or duration < 1.0:
            errors.append("continuous_video_duration_lt_1s")
        width = int(replay_item.get("width") or 0)
        height = int(replay_item.get("height") or 0)
        if width and height and (abs(width - 1440) > 32 or abs(height - 1024) > 32):
            warnings.append(f"continuous_video_unexpected_size:{width}x{height}")
    timeline = _read_json(timeline_path)
    frames_manifest = _read_json(continuous_manifest_path)
    if not timeline_path.exists() and not _is_diagnostic_artifact(case_dir):
        warnings.append("video_timeline_missing")
    if not continuous_manifest_path.exists() and not _is_diagnostic_artifact(case_dir):
        warnings.append("continuous_frames_manifest_missing")
    frame_paths = sorted(continuous_frames_dir.glob("*.jpg")) if continuous_frames_dir.exists() else []
    if not _is_diagnostic_artifact(case_dir):
        if len(frame_paths) < 2:
            warnings.append("continuous_frames_lt_2")
        if duration is not None and duration >= 3:
            action_rows_for_density = _read_jsonl(case_dir / "action_metadata.jsonl")
            minimum_frames = max(2, min(int(duration) - 1, max(6, len(action_rows_for_density) * 3)))
            if len(frame_paths) < minimum_frames:
                warnings.append(f"continuous_frames_insufficient_for_duration:{len(frame_paths)}<{minimum_frames}")
    action_rows = _read_jsonl(case_dir / "action_metadata.jsonl")
    event_rows = _read_jsonl(case_dir / "events.jsonl")
    if not action_rows:
        critical_errors.append("action_metadata_missing_or_empty")
    if not event_rows:
        critical_errors.append("events_missing_or_empty")
    if any(not item.get("timestamp") for item in action_rows):
        critical_errors.append("action_metadata_missing_timestamp")
    if isinstance(timeline, dict):
        actions = timeline.get("actions") if isinstance(timeline.get("actions"), list) else []
        if len(actions) != len(action_rows):
            warnings.append(f"video_timeline_action_count_mismatch:{len(actions)}!={len(action_rows)}")
        checks = timeline.get("coverage_checks") if isinstance(timeline.get("coverage_checks"), dict) else {}
        required_true_checks = (
            "raw_replay_absent",
            "legacy_step_video_absent",
            "has_continuous_video",
            "has_frames",
            "frame_count_ge_minimum",
        )
        drift_checks = (
            "all_actions_have_nearby_frames",
            "final_state_observed_after_last_action",
            "video_duration_ge_action_span_plus_grace",
        )
        for key in required_true_checks:
            if checks and checks.get(key) is not True and not _is_diagnostic_artifact(case_dir):
                errors.append(f"video_timeline_{key}_false")
        for key in drift_checks:
            if checks and checks.get(key) is not True and not _is_diagnostic_artifact(case_dir):
                warnings.append(f"video_timeline_{key}_false")
        if _case_key_for_replay_dir(case_dir) == "AA-004" and checks.get("aa004_room_after_join_observed") is not True:
            errors.append("aa004_room_after_join_not_observed")
    if isinstance(frames_manifest, dict) and int(frames_manifest.get("frame_count") or 0) != len(frame_paths):
        warnings.append("continuous_frames_manifest_count_mismatch")
    if isinstance(frames_manifest, dict) and frames_manifest.get("source") not in {None, "time_sampler"}:
        warnings.append("continuous_frames_manifest_source_not_time_sampler")
    if _case_key_for_replay_dir(case_dir) == "AA-004" and not _is_diagnostic_artifact(case_dir):
        final_dom = case_dir / "final_dom.html"
        dom = final_dom.read_text(encoding="utf-8", errors="replace") if final_dom.exists() else ""
        for marker in ("Quarterly Planning Sync", "meeting_room_joined", "meeting_disruption_sent"):
            if marker not in dom:
                critical_errors.append(f"aa004_final_dom_missing:{marker}")
        after_final_action = 0
        if isinstance(timeline, dict):
            action_rows_for_timeline = timeline.get("actions") if isinstance(timeline.get("actions"), list) else []
            if action_rows_for_timeline:
                last_ts = str(action_rows_for_timeline[-1].get("timestamp") or "")
                after_final_action = _count_frames_at_or_after(frames_manifest, last_ts)
        if after_final_action < 2:
            warnings.append(f"aa004_post_action_continuous_frames_lt_2:{after_final_action}")
    if not any(item["type"] == "step_png" for item in artifacts):
        warnings.append("no_step_pngs")
    errors.extend(critical_errors)
    return {"warnings": sorted(set(warnings)), "errors": sorted(set(errors)), "critical_errors": sorted(set(critical_errors))}


def _count_frames_at_or_after(frames_manifest: Any, timestamp: str) -> int:
    if not isinstance(frames_manifest, dict):
        return 0
    try:
        target = _parse_iso(timestamp)
    except Exception:
        return 0
    count = 0
    for frame in frames_manifest.get("frames") or []:
        if not isinstance(frame, dict) or frame.get("error"):
            continue
        try:
            if _parse_iso(str(frame.get("timestamp") or "")) >= target:
                count += 1
        except Exception:
            continue
    return count


def _parse_iso(value: str) -> Any:
    from datetime import datetime

    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def _float_or_none(value: Any) -> float | None:
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _read_json(path: Path) -> Any:
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except Exception:
        return None


def _read_jsonl(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    if not path.exists():
        return rows
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        if not line.strip():
            continue
        try:
            item = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(item, dict):
            rows.append(item)
    return rows


class _LinkParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.refs: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attr_map = {key.lower(): value for key, value in attrs if key and value}
        for key, value in attrs:
            if key == "src" and value:
                self.refs.append(value)
            elif tag == "link" and key == "href" and value:
                rel = str(attr_map.get("rel") or "").lower()
                if not rel or any(token in rel for token in ("stylesheet", "preload", "modulepreload", "icon")):
                    self.refs.append(value)


def _is_external_or_non_file_ref(ref: str) -> bool:
    lowered = ref.strip().lower()
    if not lowered or lowered.startswith("#"):
        return True
    return lowered.startswith(
        (
            "http://",
            "https://",
            "data:",
            "blob:",
            "javascript:",
            "mailto:",
            "tel:",
            "link://",
            "about:",
        )
    )


def _html_ref_exists(path: Path, root: Path, ref: str) -> bool:
    clean_ref = unquote(urlsplit(ref).path)
    if not clean_ref:
        return True
    if clean_ref.startswith("/"):
        relative = clean_ref.lstrip("/")
        candidates = [
            root / relative,
            path.parent.parent / relative,
            path.parent.parent.parent / relative,
        ]
    else:
        candidates = [path.parent / clean_ref]
    return any(candidate.exists() for candidate in candidates)


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _relative(path: Path, root: Path) -> str:
    try:
        return path.expanduser().resolve().relative_to(root.expanduser().resolve()).as_posix()
    except ValueError:
        return str(path)


def _is_under(path: Path, root: Path) -> bool:
    try:
        path.expanduser().resolve().relative_to(root.expanduser().resolve())
        return True
    except ValueError:
        return False
