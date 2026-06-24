import json
from pathlib import Path

from agentguard_langgraph_bench.bench.evidence.artifact_integrity import check_case_artifacts


def _write_base_case(case_dir: Path, *, case_id: str = "AA-006") -> None:
    case_dir.mkdir(parents=True)
    for name in ("events.jsonl", "action_metadata.jsonl", "step_actions.jsonl"):
        (case_dir / name).write_text(
            '{"event_type":"browser_tool_action","action":"start","timestamp":"2026-06-24T00:00:00Z","step_index":0}\n',
            encoding="utf-8",
        )
    (case_dir / "final_dom.html").write_text("<html><body>ok</body></html>", encoding="utf-8")
    (case_dir / "business_event_correlation_index.json").write_text("{}", encoding="utf-8")
    (case_dir / "replay_state.json").write_text(
        json.dumps(
            {
                "ok": True,
                "video_source": "continuous_frame_sampler",
                "raw_replay_absent": True,
                "step_screenshot_video_used": False,
                "continuous_frame_count": 2,
            }
        ),
        encoding="utf-8",
    )
    (case_dir / "video_timeline.json").write_text(
        json.dumps(
            {
                "schema_version": "agentguard_browser_video_timeline/2.0",
                "video_source": "continuous_frame_sampler",
                "actions": [{"timestamp": "2026-06-24T00:00:00Z"}],
                "coverage_checks": {
                    "raw_replay_absent": True,
                    "legacy_step_video_absent": True,
                    "has_continuous_video": True,
                    "has_frames": True,
                    "frame_count_ge_minimum": True,
                    "all_actions_have_nearby_frames": True,
                    "final_state_observed_after_last_action": True,
                    "video_duration_ge_action_span_plus_grace": True,
                },
            }
        ),
        encoding="utf-8",
    )
    frames = case_dir / "continuous_frames"
    frames.mkdir()
    for idx in (1, 2):
        (frames / f"frame_{idx:06d}.jpg").write_bytes(b"not-a-real-jpeg")
    (case_dir / "continuous_frames_manifest.json").write_text(
        json.dumps(
            {
                "source": "time_sampler",
                "frame_count": 2,
                "frames": [
                    {"path": "continuous_frames/frame_000001.jpg", "timestamp": "2026-06-24T00:00:00Z"},
                    {"path": "continuous_frames/frame_000002.jpg", "timestamp": "2026-06-24T00:00:01Z"},
                ],
            }
        ),
        encoding="utf-8",
    )
    (case_dir / "replay.webm").write_bytes(b"")


def test_zero_byte_replay_webm_fails(tmp_path):
    case_dir = tmp_path / "AA-006" / "browser_replay"
    _write_base_case(case_dir)

    report = check_case_artifacts(case_dir, root=tmp_path)

    assert report["ok"] is False
    assert any("webm_too_small" in err or "replay.webm" in err for err in report["errors"])


def test_raw_replay_and_step_screenshot_source_fail(tmp_path):
    case_dir = tmp_path / "AA-006" / "browser_replay"
    _write_base_case(case_dir)
    (case_dir / "raw_replay.webm").write_bytes(b"legacy")
    state = json.loads((case_dir / "replay_state.json").read_text(encoding="utf-8"))
    state["video_source"] = "step_screenshots"
    state["step_screenshot_video_used"] = True
    (case_dir / "replay_state.json").write_text(json.dumps(state), encoding="utf-8")

    report = check_case_artifacts(case_dir, root=tmp_path)

    assert "raw_replay_must_not_exist" in report["errors"]
    assert "legacy_step_screenshot_video_source" in report["errors"]
    assert "step_screenshot_video_used" in report["errors"]


def test_timeline_coverage_false_fails(tmp_path):
    case_dir = tmp_path / "AA-006" / "browser_replay"
    _write_base_case(case_dir)
    timeline = json.loads((case_dir / "video_timeline.json").read_text(encoding="utf-8"))
    timeline["coverage_checks"]["all_actions_have_nearby_frames"] = False
    (case_dir / "video_timeline.json").write_text(json.dumps(timeline), encoding="utf-8")

    report = check_case_artifacts(case_dir, root=tmp_path)

    assert "video_timeline_all_actions_have_nearby_frames_false" in report["errors"]


def test_aa004_room_markers_required(tmp_path):
    case_dir = tmp_path / "AA-004" / "browser_replay"
    _write_base_case(case_dir, case_id="AA-004")
    timeline = json.loads((case_dir / "video_timeline.json").read_text(encoding="utf-8"))
    timeline["coverage_checks"]["aa004_room_after_join_observed"] = False
    (case_dir / "video_timeline.json").write_text(json.dumps(timeline), encoding="utf-8")

    report = check_case_artifacts(case_dir, root=tmp_path)

    assert "aa004_room_after_join_not_observed" in report["errors"]
    assert any(err.startswith("aa004_final_dom_missing:") for err in report["errors"])
