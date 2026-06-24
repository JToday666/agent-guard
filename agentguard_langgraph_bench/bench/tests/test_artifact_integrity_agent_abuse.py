import json
import builtins
import subprocess
import zipfile

from agentguard_langgraph_bench.bench.evidence.artifact_integrity import check_case_artifacts
from agentguard_langgraph_bench.bench.runner import _write_case_artifacts


PNG_1X1 = bytes.fromhex(
    "89504e470d0a1a0a0000000d4948445200000001000000010802000000907753de"
    "0000000c49444154789c6360000000020001e221bc330000000049454e44ae426082"
)
JPG_1X1 = bytes.fromhex(
    "ffd8ffe000104a46494600010101006000600000ffdb004300030202030202030303"
    "0304030304050805050404050a070706080c0a0c0c0b0a0b0b0d0e12100d0e110e0b"
    "0b1016101113141515150c0f171816141812141514ffdb004301030404050405090505"
    "09140d0b0d1414141414141414141414141414141414141414141414141414141414"
    "141414141414141414141414141414141414141414141414ffc0001108000100010301"
    "2200021101031101ffc4001400010000000000000000000000000000000000000008"
    "ffc4001410010000000000000000000000000000000000000000ffda000c03010002"
    "110311003f00b2c001ffd9"
)


def _write_replay_artifacts(root):
    root.mkdir(parents=True, exist_ok=True)
    (root / "events.jsonl").write_text(json.dumps({"event_type": "click"}) + "\n", encoding="utf-8")
    (root / "final.png").write_bytes(PNG_1X1)
    (root / "final_full_page.png").write_bytes(PNG_1X1)
    (root / "replay.webm").write_bytes(b"webm" * 2500)
    with zipfile.ZipFile(root / "trace.zip", "w") as archive:
        archive.writestr("trace.trace", "{}")
    (root / "report.html").write_text("<html><body>step_count 1 dom_event_count 1 continuous_frame_sampler</body></html>", encoding="utf-8")
    (root / "replay_state.json").write_text(
        json.dumps(
            {
                "step_count": 1,
                "dom_event_count": 1,
                "video_source": "continuous_frame_sampler",
                "raw_replay_absent": True,
                "step_screenshot_video_used": False,
                "continuous_frame_count": 4,
                "final_observation_wait_ms": 3000,
                "video_duration_seconds": 5.0,
            }
        ),
        encoding="utf-8",
    )
    (root / "final_dom.html").write_text("<html><body>done</body></html>", encoding="utf-8")
    (root / "final_accessibility_tree.json").write_text(json.dumps({"ok": True, "snapshot": {"role": "WebArea"}}), encoding="utf-8")
    action = {"action": "click", "step_index": 1, "timestamp": "2026-06-23T00:00:00.000000Z"}
    (root / "action_metadata.jsonl").write_text(json.dumps(action) + "\n", encoding="utf-8")
    (root / "step_actions.jsonl").write_text(json.dumps(action) + "\n", encoding="utf-8")
    (root / "business_event_correlation_index.json").write_text(json.dumps({"schema_version": "1.0", "action_count": 1}), encoding="utf-8")
    frame_rows = [
        {
            "path": f"continuous_frames/frame_{index:06d}.jpg",
            "timestamp": f"2026-06-23T00:00:0{index}.000000Z",
            "elapsed_ms": index * 1000,
            "reason": "time_sample",
        }
        for index in range(4)
    ]
    (root / "video_timeline.json").write_text(
        json.dumps(
            {
                "schema_version": "agentguard_browser_video_timeline/2.0",
                "video": "replay.webm",
                "video_source": "continuous_frame_sampler",
                "action_count": 1,
                "actions": [
                    {
                        **action,
                        "nearest_frame_before": "continuous_frames/frame_000000.jpg",
                        "nearest_frame_after": "continuous_frames/frame_000000.jpg",
                        "max_frame_gap_ms": 0,
                        "covered_by_video": True,
                    }
                ],
                "video_duration_seconds": 5.0,
                "action_span_seconds": 0.0,
                "final_observation_wait_ms": 3000,
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
    frames = root / "continuous_frames"
    frames.mkdir()
    for index in range(4):
        (frames / f"frame_{index:06d}.jpg").write_bytes(JPG_1X1)
    (root / "continuous_frames_manifest.json").write_text(
        json.dumps(
            {
                "source": "time_sampler",
                "fps": 1,
                "frame_count": 4,
                "frames": frame_rows,
            }
        ),
        encoding="utf-8",
    )
    steps = root / "steps"
    steps.mkdir()
    (steps / "step_001.png").write_bytes(PNG_1X1)


def _mock_ffprobe(monkeypatch):
    monkeypatch.setattr("agentguard_langgraph_bench.bench.evidence.artifact_integrity.shutil.which", lambda name: "/usr/bin/ffprobe" if name == "ffprobe" else None)

    def fake_run(*args, **kwargs):
        return subprocess.CompletedProcess(
            args=args[0],
            returncode=0,
            stdout=json.dumps({"streams": [{"codec_name": "vp8", "width": 1440, "height": 1024}], "format": {"duration": "5.0"}}),
            stderr="",
        )

    monkeypatch.setattr("agentguard_langgraph_bench.bench.evidence.artifact_integrity.subprocess.run", fake_run)


def test_case_artifact_integrity_accepts_continuous_replay_contract(tmp_path, monkeypatch):
    case_dir = tmp_path / "cases" / "AA-005" / "browser_replay"
    _write_replay_artifacts(case_dir)
    _mock_ffprobe(monkeypatch)

    manifest = check_case_artifacts(case_dir, root=tmp_path)

    assert manifest["ok"] is True
    assert not (case_dir / "raw_replay.webm").exists()
    assert not (case_dir / "replay_frames.txt").exists()
    assert all(not artifact["run_relative_path"].startswith("/") for artifact in manifest["artifacts"])


def test_case_result_references_immutable_browser_replay_copy(tmp_path):
    source = tmp_path / "sandbox" / "browser" / "replay_artifacts" / "AA-005"
    _write_replay_artifacts(source)
    case_dir = tmp_path / "run_1" / "cases" / "AA-005"
    row = {
        "case_id": "AA-005",
        "browser_recordings": [
            {
                "artifact_dir": str(source),
                "events": str(source / "events.jsonl"),
                "screenshot": str(source / "final.png"),
                "full_page_screenshot": str(source / "final_full_page.png"),
                "video": str(source / "replay.webm"),
                "video_timeline": str(source / "video_timeline.json"),
                "continuous_frames_manifest": str(source / "continuous_frames_manifest.json"),
                "continuous_frames_dir": str(source / "continuous_frames"),
                "trace": str(source / "trace.zip"),
                "report": str(source / "report.html"),
                "final_dom": str(source / "final_dom.html"),
                "final_accessibility_tree": str(source / "final_accessibility_tree.json"),
                "action_metadata": str(source / "action_metadata.jsonl"),
                "step_actions": str(source / "step_actions.jsonl"),
                "business_event_correlation_index": str(source / "business_event_correlation_index.json"),
                "steps_dir": str(source / "steps"),
            }
        ],
    }

    _write_case_artifacts(case_dir, row, None)

    replay_dir = case_dir / "browser_replay"
    assert (replay_dir / "events.jsonl").exists()
    assert (replay_dir / "final.png").exists()
    evidence_index = json.loads((case_dir / "evidence_index.json").read_text(encoding="utf-8"))
    assert evidence_index["artifact_parse_status"]["checked"] is True
    assert all(not stream.get("run_relative_path", "").startswith("/") for stream in evidence_index["streams"])


def test_png_header_fallback_when_pillow_unavailable(tmp_path, monkeypatch):
    case_dir = tmp_path / "cases" / "AA-005" / "browser_replay"
    _write_replay_artifacts(case_dir)
    real_import = builtins.__import__

    def fake_import(name, *args, **kwargs):
        if name == "PIL":
            raise ImportError("no pillow in unit test")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", fake_import)

    manifest = check_case_artifacts(case_dir, root=tmp_path)

    png_artifacts = [item for item in manifest["artifacts"] if item["type"] in {"final.png", "final_full_page.png", "step_png"}]
    assert png_artifacts
    assert all(item["parse_ok"] is True for item in png_artifacts)
    assert any("png_header_only_validation" in warning for item in png_artifacts for warning in item["warnings"])


def test_replay_frames_missing_reference_fails_integrity(tmp_path):
    case_dir = tmp_path / "cases" / "AA-005" / "browser_replay"
    _write_replay_artifacts(case_dir)
    (case_dir / "raw_replay.webm").write_bytes(b"")

    manifest = check_case_artifacts(case_dir, root=tmp_path)

    assert manifest["ok"] is False
    assert "raw_replay_must_not_exist" in manifest["errors"]


def test_case_result_missing_artifact_reference_is_indexed_as_missing(tmp_path):
    case_dir = tmp_path / "run_1" / "cases" / "AA-005"
    missing = tmp_path / "sandbox" / "browser" / "replay_artifacts" / "AA-005" / "events.jsonl"
    row = {"case_id": "AA-005", "browser_recordings": [{"events": str(missing), "artifact_dir": str(missing.parent)}]}

    _write_case_artifacts(case_dir, row, None)

    evidence_index = json.loads((case_dir / "evidence_index.json").read_text(encoding="utf-8"))
    assert any(stream["error"] == "missing" for stream in evidence_index["streams"])


def test_high_confidence_browser_artifacts_are_required(tmp_path):
    case_dir = tmp_path / "cases" / "AA-005" / "browser_replay"
    _write_replay_artifacts(case_dir)
    (case_dir / "final_dom.html").unlink()

    manifest = check_case_artifacts(case_dir, root=tmp_path)

    assert manifest["ok"] is False
    assert "missing" in manifest["errors"]
    assert any(item["type"] == "final_dom.html" and item["error"] == "missing" for item in manifest["artifacts"])
