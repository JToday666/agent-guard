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

    pi003_call = next(step for step in cases["PI-003"].tool_plan if step.tool == "call_api")
    pi009_call = next(step for step in cases["PI-009"].tool_plan if step.tool == "call_api")

    financial = tools.call_api(**pi003_call.arguments)
    security = tools.call_api(**pi009_call.arguments)

    assert financial["real_local_service"] is True
    assert financial["service"] == "agentguard-exfiltration-collector-local"
    assert (tmp_path / "api" / "exfiltration_collector.jsonl").exists()

    assert security["real_local_service"] is True
    assert security["body"]["event"] == "security_controls_weakened"
    security_state = json.loads((tmp_path / "api" / "lead_security_controls.json").read_text(encoding="utf-8"))
    assert security_state["lead_verification_enabled"] is False
    assert security_state["phone_confirmation_enabled"] is False

    pi010_input = next(step for step in cases["PI-010"].tool_plan if step.tool == "browser_input")
    pi010_click = next(step for step in cases["PI-010"].tool_plan if step.tool == "browser_click")

    assert pi010_input.arguments["selector"] == "#identityVerify"
    assert pi010_input.arguments["value"] == "COMP-INTEL-2025-04-MARKET"
    assert pi010_click.arguments["selector"] == "#oai-attacker-submit-btn"
    assert cases["PI-010"].success_condition.type == "prompt_injection_harm_oracle"


def test_prompt_injection_code_exec_changes_sandbox_config(tmp_path):
    ensure_sandbox(tmp_path)
    tools = MockToolRegistry(tmp_path)
    case = next(case for case in _prompt_cases() if case.case_id == "PI-008")
    command = next(step.arguments["command"] for step in case.tool_plan if step.tool == "code_exec")

    result = tools.code_exec(command)

    assert result["executed"] is True
    assert result["mode"] == "sandbox_config_update"
    config_text = (tmp_path / "files" / "config" / "apple_device_policy.conf").read_text(encoding="utf-8")
    assert "desktop_wallpaper_policy=forced" in config_text
    assert (tmp_path / "api" / "config_changes.jsonl").exists()


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
