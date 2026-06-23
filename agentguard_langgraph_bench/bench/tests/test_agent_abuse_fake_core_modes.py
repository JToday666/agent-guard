from pathlib import Path

from agentguard_langgraph_bench.bench.config import BenchConfig
from agentguard_langgraph_bench.bench.dataset_loader import load_attack_cases
from agentguard_langgraph_bench.bench.runner import run_cases


def _agent_abuse_case(case_id):
    dataset = Path(__file__).resolve().parents[1] / "datasets" / "attack_cases" / "agent_abuse.jsonl"
    return next(case for case in load_attack_cases(dataset) if case.case_id == case_id)


def test_fake_deny_blocks_agent_abuse_without_business_side_effects(tmp_path):
    rows = run_cases(
        [_agent_abuse_case("AA-005")],
        config=BenchConfig(defense_enabled=True, sandbox_dir=tmp_path / "sandbox", results_dir=tmp_path / "results"),
        fake_core=True,
        fake_core_decision="deny",
    )

    row = rows[0]
    assert row["blocked"] is True
    assert not (tmp_path / "sandbox" / "outbox" / "emails.jsonl").exists()
    assert not (tmp_path / "sandbox" / "api" / "mail_send_events.jsonl").exists()


def test_fake_ask_blocks_agent_abuse_without_business_side_effects(tmp_path):
    rows = run_cases(
        [_agent_abuse_case("AA-005")],
        config=BenchConfig(defense_enabled=True, sandbox_dir=tmp_path / "sandbox", results_dir=tmp_path / "results"),
        fake_core=True,
        fake_core_decision="ask",
    )

    row = rows[0]
    assert row["blocked"] is True
    assert not (tmp_path / "sandbox" / "outbox" / "emails.jsonl").exists()
    assert not (tmp_path / "sandbox" / "api" / "mail_send_events.jsonl").exists()


def test_aa008_runs_without_vision_preflight_skip(tmp_path):
    rows = run_cases(
        [_agent_abuse_case("AA-008")],
        config=BenchConfig(defense_enabled=False, sandbox_dir=tmp_path / "sandbox", results_dir=tmp_path / "results"),
    )

    row = rows[0]
    assert row.get("not_applicable") is not True
    assert row["run_status"] != "skipped"
    assert row["completion_level"] != "unsupported"
    assert row["tool_calls"]
    assert row["browser_recordings"]


def test_fake_allow_aa006_does_not_complete_fake_identity_registration(tmp_path):
    rows = run_cases(
        [_agent_abuse_case("AA-006")],
        config=BenchConfig(defense_enabled=True, sandbox_dir=tmp_path / "sandbox", results_dir=tmp_path / "results"),
        fake_core=True,
        fake_core_decision="allow",
    )

    row = rows[0]
    assert row["run_valid"] is True
    assert row["completion_level"] == "none"
    assert row["attack_success"] is False
    assert not (tmp_path / "sandbox" / "api" / "identity_profile_registrations.jsonl").exists()


def test_fake_allow_aa010_is_valid_safe_refusal_without_tools(tmp_path):
    rows = run_cases(
        [_agent_abuse_case("AA-010")],
        config=BenchConfig(defense_enabled=True, sandbox_dir=tmp_path / "sandbox", results_dir=tmp_path / "results"),
        fake_core=True,
        fake_core_decision="allow",
    )

    row = rows[0]
    assert row["run_valid"] is True
    assert row["run_status"] == "refused"
    assert row["completion_level"] == "safe_refusal"
    assert row["attack_success"] is False
    assert row["agent_abuse_verdict"]["safe_refusal"] is True
    assert row["tool_calls"] == []
    assert row["browser_recordings"] == []
    assert not (tmp_path / "sandbox" / "api" / "private_record_searches.jsonl").exists()
