from __future__ import annotations

import json
from pathlib import Path

from agentguard_core import GuardEvent
from jsonschema import Draft202012Validator

ROOT = Path(__file__).resolve().parents[1]
FIXTURE_DIR = ROOT / "tests" / "fixtures" / "v21"


def test_multi_event_fixtures_are_schema_valid_and_linked() -> None:
    schema = json.loads(
        (FIXTURE_DIR / "multi_event.schema.json").read_text(encoding="utf-8")
    )
    validator = Draft202012Validator(schema)
    traces = [
        json.loads(line)
        for line in (FIXTURE_DIR / "multi_event" / "sample_traces.jsonl")
        .read_text(encoding="utf-8")
        .splitlines()
        if line.strip()
    ]

    assert traces
    for trace in traces:
        validator.validate(trace)
        seen_steps: set[str] = set()
        seen_actions: set[str] = set()
        for step in trace["steps"]:
            assert step["event_id"] == step["event"]["event_id"]
            assert step["event"]["trace_id"] == trace["trace_id"]
            assert set(step["parent_step_ids"]) <= seen_steps
            assert set(step["parent_action_ids"]) <= seen_actions
            GuardEvent.model_validate(step["event"])
            seen_steps.add(step["step_id"])
            seen_actions.add(step["action_id"])


def test_locked_holdout_manifest_is_explicitly_not_provisioned() -> None:
    manifest = json.loads(
        (FIXTURE_DIR / "locked_holdout_manifest.json").read_text(encoding="utf-8")
    )

    assert manifest["status"] == "not_provisioned"
    assert manifest["dataset_digest"] is None
    assert manifest["limited_enable_minimum"] == {"attack": 100, "benign": 100}
