import json
import shutil
import subprocess
from pathlib import Path

import pytest

from agentguard_langgraph_bench.bench.evidence.artifact_integrity import check_case_artifacts
from agentguard_langgraph_bench.bench.tools import MockToolRegistry


def _ffprobe_ok(path: Path) -> bool:
    ffprobe = shutil.which("ffprobe")
    if not ffprobe:
        pytest.skip("ffprobe unavailable")
    completed = subprocess.run(
        [
            ffprobe,
            "-v",
            "error",
            "-show_entries",
            "format=duration",
            "-of",
            "json",
            str(path),
        ],
        capture_output=True,
        text=True,
        check=False,
        timeout=10,
    )
    if completed.returncode != 0:
        return False
    data = json.loads(completed.stdout or "{}")
    return float((data.get("format") or {}).get("duration") or 0) >= 1.0


def test_real_browser_continuous_recording_artifacts(tmp_path):
    pytest.importorskip("playwright.sync_api")
    tools = MockToolRegistry(tmp_path / "sandbox", browser_mode="real")
    try:
        tools.browser_start(
            "",
            run_id="AA-004",
            source_path="agentguard_langgraph_bench/bench/datasets/instrumentation/Browser-art_D4_23/zoom/index.html",
        )
        tools.browser_click("testid=join-and-send-disruption", session_id="AA-004")
        recording = tools._real_browser_runtime().finalize("AA-004")
    except Exception as exc:
        pytest.skip(f"real browser unavailable: {exc}")

    artifact_dir = Path(recording["artifact_dir"])
    replay = artifact_dir / "replay.webm"
    frames = sorted((artifact_dir / "continuous_frames").glob("*.jpg"))
    timeline = json.loads((artifact_dir / "video_timeline.json").read_text(encoding="utf-8"))
    replay_state = json.loads((artifact_dir / "replay_state.json").read_text(encoding="utf-8"))

    assert not (artifact_dir / "raw_replay.webm").exists()
    assert not (artifact_dir / "replay_frames.txt").exists()
    assert replay.stat().st_size > 8000
    assert _ffprobe_ok(replay)
    assert len(frames) >= 2
    assert replay_state["video_source"] == "continuous_frame_sampler"
    assert replay_state["step_screenshot_video_used"] is False
    assert timeline["coverage_checks"]["has_continuous_video"] is True
    assert timeline["coverage_checks"]["all_actions_have_nearby_frames"] is True
    assert timeline["coverage_checks"]["aa004_room_after_join_observed"] is True
    integrity = check_case_artifacts(artifact_dir, root=tmp_path)
    assert integrity["ok"] is True, integrity["errors"]
