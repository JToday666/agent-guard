import json
from pathlib import Path
from urllib.error import URLError
from urllib.request import urlopen

import pytest

from agentguard_langgraph_bench.bench.config import BenchConfig, ensure_sandbox
from agentguard_langgraph_bench.bench.dataset_loader import load_attack_cases
from agentguard_langgraph_bench.bench.runner import run_cases
from agentguard_langgraph_bench.bench.tools import MockToolRegistry


def _prompt_cases():
    dataset = Path(__file__).resolve().parents[1] / "datasets" / "attack_cases" / "prompt_injection.jsonl"
    return load_attack_cases(dataset)


def test_prompt_injection_cases_use_local_real_resources(tmp_path):
    ensure_sandbox(tmp_path)
    cases = _prompt_cases()

    assert len(cases) == 10
    for case in cases:
        serialized = json.dumps(case.model_dump(), ensure_ascii=False)
        assert "mock identity payload" not in serialized
        assert "mock contact payload" not in serialized
        assert "https://attacker.example" not in serialized
        assert "https://control.example" not in serialized
        assert "https://api.example.local" not in serialized
        assert "sed -i" not in serialized

        for step in case.tool_plan:
            args = step.arguments
            if step.tool == "read_file":
                assert (tmp_path / "files" / args["path"].lstrip("/")).exists(), (case.case_id, args["path"])
            if step.tool == "call_api":
                assert args["url"].startswith(("http://127.0.0.1:18087/", "http://127.0.0.1:18086/"))


def test_prompt_injection_browser_pages_are_served_locally(tmp_path):
    ensure_sandbox(tmp_path)
    tools = MockToolRegistry(tmp_path)

    for case in _prompt_cases():
        start = next(step for step in case.tool_plan if step.tool == "browser_start")
        result = tools.browser_start(**start.arguments)

        assert result["source_exists"] is True, case.case_id
        assert "/local-instrumentation/" in result["url"], case.case_id
        try:
            with urlopen(result["url"], timeout=2.0) as response:  # noqa: S310 - localhost-only benchmark fixture
                assert response.status == 200, case.case_id
        except (OSError, URLError) as exc:
            pytest.skip(f"localhost sockets are unavailable in this sandbox: {exc}")


def test_prompt_injection_local_services_write_evidence(tmp_path):
    ensure_sandbox(tmp_path)
    tools = MockToolRegistry(tmp_path)
    cases = {case.case_id: case for case in _prompt_cases()}

    pi003_read = next(step for step in cases["PI-003"].tool_plan if step.tool == "read_file")
    pi009_page = next(step for step in cases["PI-009"].tool_plan if step.tool == "browser_extract_text")

    lead_schema = tools.read_file(**pi003_read.arguments)
    page = tools.browser_start(**next(step for step in cases["PI-009"].tool_plan if step.tool == "browser_start").arguments)

    assert isinstance(lead_schema, str)
    assert lead_schema.strip()
    assert "neuralforge_lead_schema" in pi003_read.arguments["path"]
    assert page["source_exists"] is True
    assert pi009_page.arguments["selector"] == "body"

    pi010_harm = cases["PI-010"].metadata["harm_oracle"]

    assert pi010_harm[0]["target"]["id"] == "identityVerify"
    assert pi010_harm[0]["value_equals"] == "COMP-INTEL-2025-04-MARKET"
    assert pi010_harm[1]["target"]["testId"] == "market-segment-submit"
    assert cases["PI-010"].success_condition.type == "prompt_injection_harm_oracle"

    pi010_row = cases["PI-010"]
    assert "market segment routing note" in pi010_row.input.payload
    assert "COMP-INTEL-2025-04-MARKET" not in pi010_row.input.payload
    assert "demo" not in pi010_row.input.payload.lower()


def test_prompt_injection_code_exec_changes_sandbox_config(tmp_path):
    ensure_sandbox(tmp_path)
    tools = MockToolRegistry(tmp_path)
    case = next(case for case in _prompt_cases() if case.case_id == "PI-008")

    assert any(step.tool in {"read_file", "browser_start", "browser_extract_text"} for step in case.tool_plan)
    assert all(step.tool != "code_exec" for step in case.tool_plan)
    start = next(step for step in case.tool_plan if step.tool == "browser_start")
    result = tools.browser_start(**start.arguments)

    assert result["source_exists"] is True
    assert "/local-instrumentation/" in result["url"]


def test_prompt_injection_fake_deny_blocks_before_side_effects(tmp_path):
    rows = run_cases(
        _prompt_cases(),
        config=BenchConfig(defense_enabled=True, sandbox_dir=tmp_path / "sandbox", results_dir=tmp_path / "results"),
        fake_core=True,
        fake_core_decision="deny",
    )

    assert len(rows) == 10
    assert all(row["blocked"] for row in rows)
    assert not any(row["side_effects"] for row in rows)
    assert not (tmp_path / "sandbox" / "outbox" / "emails.jsonl").exists()
    assert not (tmp_path / "sandbox" / "api" / "neuralforge_leads.jsonl").exists()
