import json
import builtins
import zipfile

from agentguard_langgraph_bench.bench.evidence.artifact_integrity import check_case_artifacts
from agentguard_langgraph_bench.bench.runner import _write_case_artifacts


PNG_1X1 = bytes.fromhex(
    "89504e470d0a1a0a0000000d4948445200000001000000010802000000907753de"
    "0000000c49444154789c6360000000020001e221bc330000000049454e44ae426082"
)


def _write_replay_artifacts(root):
    root.mkdir(parents=True, exist_ok=True)
    (root / "events.jsonl").write_text(json.dumps({"event_type": "click"}) + "\n", encoding="utf-8")
    (root / "final.png").write_bytes(PNG_1X1)
    (root / "final_full_page.png").write_bytes(PNG_1X1)
    (root / "replay.webm").write_bytes(b"webm")
    (root / "raw_replay.webm").write_bytes(b"")
    with zipfile.ZipFile(root / "trace.zip", "w") as archive:
        archive.writestr("trace.trace", "{}")
    (root / "report.html").write_text("<html><body>step_count 1 dom_event_count 1</body></html>", encoding="utf-8")
    (root / "replay_state.json").write_text(json.dumps({"step_count": 1, "dom_event_count": 1}), encoding="utf-8")
    (root / "final_dom.html").write_text("<html><body>done</body></html>", encoding="utf-8")
    (root / "final_accessibility_tree.json").write_text(json.dumps({"ok": True, "snapshot": {"role": "WebArea"}}), encoding="utf-8")
    (root / "action_metadata.jsonl").write_text(json.dumps({"action": "click", "step_index": 1}) + "\n", encoding="utf-8")
    (root / "step_actions.jsonl").write_text(json.dumps({"action": "click", "step_index": 1}) + "\n", encoding="utf-8")
    (root / "business_event_correlation_index.json").write_text(json.dumps({"schema_version": "1.0", "action_count": 1}), encoding="utf-8")
    (root / "replay_frames.txt").write_text("steps/step_001.png\nfinal.png\n", encoding="utf-8")
    steps = root / "steps"
    steps.mkdir()
    (steps / "step_001.png").write_bytes(PNG_1X1)


def test_case_artifact_integrity_accepts_replay_files_and_raw_video_warning(tmp_path, monkeypatch):
    case_dir = tmp_path / "cases" / "AA-005" / "browser_replay"
    _write_replay_artifacts(case_dir)
    monkeypatch.setattr("agentguard_langgraph_bench.bench.evidence.artifact_integrity.shutil.which", lambda name: None)

    manifest = check_case_artifacts(case_dir, root=tmp_path)

    assert any(error == "ffprobe_unavailable" for error in manifest["errors"])
    assert any("raw video unavailable" in warning for warning in manifest["warnings"])
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
                "raw_video": str(source / "raw_replay.webm"),
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
    (case_dir / "replay_frames.txt").write_text("steps/missing.png\n", encoding="utf-8")

    manifest = check_case_artifacts(case_dir, root=tmp_path)

    assert manifest["ok"] is False
    assert "missing_replay_frame:steps/missing.png" in manifest["errors"]


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
