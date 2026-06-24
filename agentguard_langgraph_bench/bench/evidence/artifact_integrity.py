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

CONTINUOUS_VIDEO_MIN_BYTES = 8000


def build_artifact_integrity_manifest(run_or_artifact_dir: Path, *, output_path: Path | None = None) -> dict[str, Any]:
    root = run_or_artifact_dir.expanduser().resolve()
    replay_dirs = _find_replay_dirs(root)
    cases = {_case_key_for_replay_dir(case_dir): check_case_artifacts(case_dir, root=root) for case_dir in replay_dirs}
    manifest = {
        "schema_version": "1.0",
        "root": str(root),
        "case_count": len(cases),
        "cases": cases,
        "ok": all(item.get("ok") for item in cases.values()),
    }
    if output_path is not None:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(json.dumps(manifest, ensure_ascii=False, indent=2, sort_keys=True), encoding="utf-8")
    return manifest


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
            if item.get("type") not in {"replay.webm", "trace.zip", "video_timeline.json", "continuous_frames_manifest.json"}
        ]
    return {
        "case_id": _case_key_for_replay_dir(case_dir),
        "artifact_dir": _relative(case_dir, root),
        "diagnostic_artifact": diagnostic_artifact,
        "ok": not errors and not parse_failures and not cross_checks["errors"],
        "artifacts": artifacts,
        "cross_checks": cross_checks,
        "warnings": [warning for item in artifacts for warning in item.get("warnings", [])] + cross_checks["warnings"],
        "errors": [item.get("error") for item in errors if item.get("error")] + cross_checks["errors"],
    }


def _case_key_for_replay_dir(case_dir: Path) -> str:
    if case_dir.name == "browser_replay" and case_dir.parent.name:
        return case_dir.parent.name
    return case_dir.name


def _find_replay_dirs(root: Path) -> list[Path]:
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
    except Exception as exc:
        item["error"] = f"png_parse_error:{exc}"
    return item


def _check_png_header_fallback(path: Path, item: dict[str, Any], warning: str) -> dict[str, Any]:
    try:
        data = path.read_bytes()
    except Exception as exc:
        item["error"] = f"png_read_error:{exc}"
        return item
    if not data.startswith(b"\x89PNG\r\n\x1a\n"):
        item["error"] = "png_header_parse_error"
        return item
    item.update({"parse_ok": True, "error": None})
    item["warnings"].append(warning)
    item["warnings"].append("png_header_only_validation")
    return item


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
        if ref.startswith(("http://", "https://", "data:", "#")):
            continue
        if not (path.parent / ref).exists():
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
    state_path = case_dir / "replay_state.json"
    report_path = case_dir / "report.html"
    frames_path = case_dir / "replay_frames.txt"
    raw_video_path = case_dir / "raw_replay.webm"
    timeline_path = case_dir / "video_timeline.json"
    continuous_manifest_path = case_dir / "continuous_frames_manifest.json"
    continuous_frames_dir = case_dir / "continuous_frames"
    if raw_video_path.exists():
        errors.append("raw_replay_must_not_exist")
    if state_path.exists() and report_path.exists():
        try:
            state = json.loads(state_path.read_text(encoding="utf-8"))
            html = report_path.read_text(encoding="utf-8", errors="replace")
            for key in ("step_count", "dom_event_count", "video_source"):
                if key in state and str(state[key]) not in html:
                    warnings.append(f"report_state_mismatch:{key}")
            if state.get("video_source") != "continuous_playwright" and not _is_diagnostic_artifact(case_dir):
                errors.append("replay_state_video_source_not_continuous_playwright")
            if state.get("video_source") == "step_screenshots":
                errors.append("legacy_step_screenshot_video_source")
        except Exception as exc:
            errors.append(f"replay_state_report_cross_check_error:{exc}")
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
        errors.append("video_timeline_missing")
    if not continuous_manifest_path.exists() and not _is_diagnostic_artifact(case_dir):
        errors.append("continuous_frames_manifest_missing")
    frame_paths = sorted(continuous_frames_dir.glob("*.jpg")) if continuous_frames_dir.exists() else []
    if not _is_diagnostic_artifact(case_dir):
        if len(frame_paths) < 2:
            errors.append("continuous_frames_lt_2")
        if duration is not None and duration >= 3 and len(frame_paths) < max(2, int(duration) - 1):
            errors.append(f"continuous_frames_insufficient_for_duration:{len(frame_paths)}<{max(2, int(duration) - 1)}")
    action_rows = _read_jsonl(case_dir / "action_metadata.jsonl")
    if any(not item.get("timestamp") for item in action_rows):
        errors.append("action_metadata_missing_timestamp")
    if isinstance(timeline, dict):
        actions = timeline.get("actions") if isinstance(timeline.get("actions"), list) else []
        if len(actions) != len(action_rows):
            errors.append(f"video_timeline_action_count_mismatch:{len(actions)}!={len(action_rows)}")
        checks = timeline.get("coverage_checks") if isinstance(timeline.get("coverage_checks"), dict) else {}
        if checks and checks.get("raw_replay_absent") is not True:
            errors.append("video_timeline_raw_replay_absent_false")
        if checks and checks.get("video_duration_ge_action_span_plus_grace") is not True and not _is_diagnostic_artifact(case_dir):
            errors.append("video_duration_does_not_cover_action_span_plus_grace")
    if isinstance(frames_manifest, dict) and int(frames_manifest.get("frame_count") or 0) != len(frame_paths):
        errors.append("continuous_frames_manifest_count_mismatch")
    if not any(item["type"] == "step_png" for item in artifacts):
        warnings.append("no_step_pngs")
    return {"warnings": sorted(set(warnings)), "errors": sorted(set(errors))}


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
        for key, value in attrs:
            if key in {"href", "src"} and value:
                self.refs.append(value)


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
