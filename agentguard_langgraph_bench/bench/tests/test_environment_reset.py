import json
from pathlib import Path

from agentguard_langgraph_bench.bench.config import BenchConfig, ensure_sandbox
from agentguard_langgraph_bench.bench.dataset_loader import load_attack_cases
from agentguard_langgraph_bench.bench.environment import archive_sandbox_effects, restore_initial_sandbox
from agentguard_langgraph_bench.bench.runner import main, run_cases


def dataset_dir() -> Path:
    return Path(__file__).resolve().parents[1] / "datasets" / "attack_cases"


def test_restore_initial_sandbox_removes_runtime_effects_and_restores_fixtures(tmp_path):
    sandbox = tmp_path / "sandbox"
    ensure_sandbox(sandbox)

    (sandbox / "api" / "requests.jsonl").write_text('{"url": "unsafe"}\n', encoding="utf-8")
    (sandbox / "api" / "lead_security_controls.json").write_text(
        json.dumps({"lead_verification_enabled": False}),
        encoding="utf-8",
    )
    (sandbox / "api" / "neuralforge_rate_limits.json").write_text(
        json.dumps({"bulk_submission_threshold": 25}),
        encoding="utf-8",
    )
    (sandbox / "browser" / "replay_artifacts" / "FE-001").mkdir(parents=True)
    (sandbox / "browser" / "replay_artifacts" / "FE-001" / "report.html").write_text("artifact", encoding="utf-8")
    (sandbox / "mcp" / "github" / "repositories" / "demo").mkdir(parents=True)
    (sandbox / "mcp" / "github" / "repositories" / "demo" / "repository.json").write_text("{}", encoding="utf-8")
    (sandbox / "files" / "reports" / "leak.txt").write_text("secret", encoding="utf-8")
    (sandbox / "files" / "config" / "apple_device_policy.conf").write_text(
        "desktop_wallpaper_policy=forced\nrisk_confirmation_required=false\n",
        encoding="utf-8",
    )

    report = restore_initial_sandbox(sandbox)

    assert report.removed_files >= 5
    assert not (sandbox / "api" / "requests.jsonl").exists()
    assert not (sandbox / "api" / "lead_security_controls.json").exists()
    assert not (sandbox / "api" / "neuralforge_rate_limits.json").exists()
    assert not (sandbox / "browser" / "replay_artifacts" / "FE-001" / "report.html").exists()
    assert not (sandbox / "mcp" / "github" / "repositories" / "demo" / "repository.json").exists()
    assert not (sandbox / "files" / "reports" / "leak.txt").exists()

    policy = (sandbox / "files" / "config" / "apple_device_policy.conf").read_text(encoding="utf-8")
    assert "desktop_wallpaper_policy=user_choice" in policy
    assert "risk_confirmation_required=true" in policy
    assert (sandbox / "files" / "docs" / "public.txt").exists()
    assert (sandbox / "files" / "contacts" / "ops_team.json").exists()
    assert (sandbox / "files" / "payloads" / "license_txt.exe").exists()


def test_archive_sandbox_effects_copies_changes_before_reset(tmp_path):
    sandbox = tmp_path / "sandbox"
    results = tmp_path / "results"
    ensure_sandbox(sandbox)
    (sandbox / "api" / "requests.jsonl").write_text('{"url": "unsafe"}\n', encoding="utf-8")
    (sandbox / "files" / "config" / "apple_device_policy.conf").write_text(
        "desktop_wallpaper_policy=forced\nrisk_confirmation_required=false\n",
        encoding="utf-8",
    )

    archive = archive_sandbox_effects(sandbox, results, run_id="unit-test")
    reset = restore_initial_sandbox(sandbox)

    artifact_dir = Path(archive.artifact_dir)
    assert archive.added_files == 1
    assert archive.modified_files == 1
    assert archive.copied_files == 2
    assert (artifact_dir / "sandbox" / "api" / "requests.jsonl").exists()
    assert (artifact_dir / "sandbox" / "files" / "config" / "apple_device_policy.conf").exists()
    manifest = json.loads(Path(archive.manifest_path).read_text(encoding="utf-8"))
    copied_paths = {item["path"] for item in manifest["copied_files"]}
    assert copied_paths == {"api/requests.jsonl", "files/config/apple_device_policy.conf"}
    assert reset.removed_files >= 1
    assert not (sandbox / "api" / "requests.jsonl").exists()


def test_runner_resets_sandbox_after_default_run(tmp_path):
    sandbox = tmp_path / "sandbox"
    case = next(case for case in load_attack_cases(dataset_dir() / "agent_abuse.jsonl") if case.case_id == "AA-003")

    rows = run_cases(
        [case],
        config=BenchConfig(defense_enabled=False, sandbox_dir=sandbox, results_dir=tmp_path),
    )

    assert rows[0]["attack_success"] is None
    assert rows[0]["agent_abuse_evaluation_report"]["reason"] != "legacy_condition_only"
    assert any(effect["path"].endswith("api/backdoor_plans.jsonl") for effect in rows[0]["side_effects"])
    archive = rows[0]["sandbox_archive"]
    artifact_dir = Path(archive["artifact_dir"])
    assert archive["copied_files"] >= 3
    assert (artifact_dir / "sandbox" / "api" / "backdoor_plans.jsonl").exists()
    assert (artifact_dir / "sandbox" / "api" / "code_exec.jsonl").exists()
    assert (artifact_dir / "sandbox" / "browser" / "events.jsonl").exists()
    assert not (sandbox / "api" / "backdoor_plans.jsonl").exists()
    assert not (sandbox / "api" / "code_exec.jsonl").exists()
    assert not (sandbox / "browser" / "events.jsonl").exists()


def test_runner_can_keep_sandbox_effects_for_debugging(tmp_path):
    sandbox = tmp_path / "sandbox"
    case = next(case for case in load_attack_cases(dataset_dir() / "agent_abuse.jsonl") if case.case_id == "AA-003")

    rows = run_cases(
        [case],
        config=BenchConfig(defense_enabled=False, sandbox_dir=sandbox, results_dir=tmp_path),
        reset_environment=False,
    )

    assert rows[0]["attack_success"] is None
    assert rows[0]["completion_level"] == "unknown"
    assert (sandbox / "api" / "backdoor_plans.jsonl").exists()
    assert (sandbox / "api" / "code_exec.jsonl").exists()
    assert (sandbox / "browser" / "events.jsonl").exists()


def test_runner_cli_reset_env_only(tmp_path, capsys):
    sandbox = tmp_path / "sandbox"
    ensure_sandbox(sandbox)
    (sandbox / "memory" / "store.jsonl").write_text('{"key": "stale"}\n', encoding="utf-8")

    code = main(
        [
            "--dataset",
            str(dataset_dir()),
            "--results-dir",
            str(tmp_path),
            "--sandbox-dir",
            str(sandbox),
            "--reset-env-only",
        ]
    )

    assert code == 0
    output = json.loads(capsys.readouterr().out)
    assert output["environment_reset"]["sandbox_dir"] == str(sandbox.resolve())
    assert not (sandbox / "memory" / "store.jsonl").exists()
