import pytest

from agentguard_langgraph_bench.bench.browser_runtime import RealBrowserRuntime, local_url_for_source
from agentguard_langgraph_bench.bench.config import ensure_sandbox


SOURCE_PATH = "agentguard_langgraph_bench/bench/datasets/instrumentation/Browser-art_E1_33/email/index.html"


def test_real_browser_start_inspect_and_duplicate_start(tmp_path):
    ensure_sandbox(tmp_path)
    runtime = RealBrowserRuntime(tmp_path, browser_engine="chromium")
    url = local_url_for_source(SOURCE_PATH)
    if not url:
        pytest.skip("Instrumentation fixture is unavailable")

    try:
        started = runtime.start(session_id="RB-001", url=url, source_path=SOURCE_PATH)
        inspected = runtime.inspect(session_id="RB-001", limit=20)
        repeated = runtime.start(session_id="RB-001", url=url, source_path=SOURCE_PATH)
        recording = runtime.finalize("RB-001")
    except Exception as exc:
        pytest.skip(f"real browser runtime unavailable: {exc}")
    finally:
        runtime.close_all()

    assert started["session_id"] == "RB-001"
    assert inspected["session_id"] == "RB-001"
    assert inspected["interactive_elements"]
    assert repeated["reused_session"] is True
    artifact_dir = tmp_path / "browser" / "replay_artifacts" / "RB-001"
    assert (artifact_dir / "manifest.json").exists()
    assert (artifact_dir / "steps" / "step_000_start.png").exists()
    assert recording is not None
    assert recording["ok"] is True
