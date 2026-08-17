"""Negative scope matrix for the competition model-output observation policy."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Literal

from fastapi.testclient import TestClient

from agentguard_core import (
    GuardEvent,
    ModelCallPayload,
    PolicyBundle,
    RuleHit,
    SecurityContext,
)
from agentguard_core.actions import ActionEffect
from agentguard_core.actions.canonical_json import canonical_sha256
from agentguard_core.decisions import DetectionResult
from agentguard_core.decisions.shadow import shadow_assess_with_coverage
from agentguard_core.security_context import AssessmentTransientFacts
from guard_api.main import create_app
from guard_api.services import PolicyService
from guard_api.storage.memory import MemoryControlPlaneStore
from tests.support.auth import add_adapter_credential
from tests.test_lgv2_api_official import _activation, _settings
from tests.test_gate_a_core_overlay import SCOPE, _flow, _source
from tests.test_v21_08_shadow_assessment import _snapshot
from tests.test_v21_09_pipeline import _TASK_ID, _commit_task_fact

_ADAPTER_HEADERS = {"Authorization": "Bearer adapter-secret"}
_HIGH_IMPACT_DOMAINS = {
    "task",
    "source",
    "capability",
    "behavior",
    "dataflow",
    "memory",
}


def _client_and_store(
    tmp_path: Path,
    *,
    mode: Literal["shadow", "active"],
) -> tuple[TestClient, MemoryControlPlaneStore]:
    store = MemoryControlPlaneStore()
    add_adapter_credential(store, principal_id="principal_a")
    _commit_task_fact(store)
    policy = PolicyService(store=store)
    activation = _activation(
        canonical_sha256(policy.current_snapshot().model_dump(mode="json"))
    )
    activation_path = tmp_path / f"competition-{mode}-activation.json"
    activation_path.write_text(
        json.dumps(activation.manifest.model_dump(mode="json"), sort_keys=True),
        encoding="utf-8",
    )
    activation_path.chmod(0o444)
    settings = _settings(
        v21_mode=mode,
        v21_competition_activation_path=str(activation_path),
    )
    return TestClient(create_app(store=store, settings=settings)), store


def _model_event(
    *,
    event_id: str,
    phase: Literal["input", "output"],
    visible_source_refs: tuple[str, ...] = (),
) -> GuardEvent:
    return GuardEvent(
        event_id=event_id,
        event_type=(
            "model_input_prepared" if phase == "input" else "model_output_produced"
        ),
        runtime="langgraph",
        trace_id=f"trace_{event_id}",
        timestamp="2026-08-18T00:00:00+00:00",
        pre_execution=phase == "input",
        security_context=SecurityContext(
            agent_id="main",
            user_task="Summarize the provided material.",
            visible_source_refs=visible_source_refs,
        ),
        payload=ModelCallPayload(
            phase=phase,
            content_preview="A benign model exchange.",
            provider="fixture",
            model="fixture-model",
        ),
        metadata={"task_id": _TASK_ID},
    )


def _decision_v21(
    client: TestClient,
    store: MemoryControlPlaneStore,
    event: GuardEvent,
) -> dict[str, object]:
    response = client.post(
        "/v1/guard/evaluate",
        headers=_ADAPTER_HEADERS,
        json=event.model_dump(mode="json"),
    )
    assert response.status_code == 200, response.text
    audit = store.get_policy_evaluation_by_event_id(event.event_id)
    assert audit is not None
    assert audit.evidence is not None
    return audit.evidence["decision_v21"]["payload"]


def test_active_output_waives_only_observation_provenance_domains(
    tmp_path: Path,
) -> None:
    client, store = _client_and_store(tmp_path, mode="active")
    payload = _decision_v21(
        client,
        store,
        _model_event(event_id="evt_active_output_scope", phase="output"),
    )

    assert set(payload["required_domains"]) == {
        "task",
        "capability",
        "behavior",
    }
    coverage = payload["coverage"]
    assert {
        domain: coverage[domain]["status"]
        for domain in ("source", "dataflow", "memory")
    } == {
        "source": "not_applicable",
        "dataflow": "not_applicable",
        "memory": "not_applicable",
    }


def test_active_input_keeps_source_and_dataflow_required(
    tmp_path: Path,
) -> None:
    client, store = _client_and_store(tmp_path, mode="active")
    payload = _decision_v21(
        client,
        store,
        _model_event(event_id="evt_active_input_scope", phase="input"),
    )

    assert set(payload["required_domains"]) == _HIGH_IMPACT_DOMAINS - {"memory"}
    coverage = payload["coverage"]
    assert coverage["source"]["status"] != "not_applicable"
    assert coverage["dataflow"]["status"] != "not_applicable"
    assert coverage["memory"]["status"] == "not_applicable"


def test_shadow_output_keeps_all_high_impact_domains_required(
    tmp_path: Path,
) -> None:
    client, store = _client_and_store(tmp_path, mode="shadow")
    payload = _decision_v21(
        client,
        store,
        _model_event(event_id="evt_shadow_output_scope", phase="output"),
    )

    assert set(payload["required_domains"]) == _HIGH_IMPACT_DOMAINS
    coverage = payload["coverage"]
    assert all(
        coverage[domain]["status"] != "not_applicable"
        for domain in ("source", "dataflow", "memory")
    )


def test_active_output_memory_lineage_keeps_memory_required(
    tmp_path: Path,
) -> None:
    client, store = _client_and_store(tmp_path, mode="active")
    payload = _decision_v21(
        client,
        store,
        _model_event(
            event_id="evt_active_output_memory_lineage",
            phase="output",
            visible_source_refs=("source:memory:task-context:0",),
        ),
    )

    assert set(payload["required_domains"]) == {
        "task",
        "capability",
        "behavior",
        "memory",
    }
    coverage = payload["coverage"]
    assert coverage["source"]["status"] == "not_applicable"
    assert coverage["dataflow"]["status"] == "not_applicable"
    assert coverage["memory"]["status"] != "not_applicable"


def test_scoped_output_is_low_impact_without_dropping_signal_or_taint_inputs() -> None:
    source = _source()
    event = _model_event(
        event_id="evt_active_output_possible_influence",
        phase="output",
        visible_source_refs=(source.source_id,),
    )
    transient = AssessmentTransientFacts.from_primitives(
        event_id=event.event_id,
        scope_digest=SCOPE,
        source_facts=[source],
        flow_facts=[
            _flow(
                "flow-output-possible-influence",
                source_ref=source.source_id,
                target_ref=f"model_output:{event.event_id}",
                relation="influenced_by",
                taints=["UNTRUSTED"],
            )
        ],
    )
    detection = DetectionResult(
        decision="ask",
        risk_score=72,
        category="prompt_injection",
        rule_hit=RuleHit(
            rule_id="P101_prompt_injection",
            severity="high",
            evidence=["high_confidence=true"],
        ),
        reason="prompt injection detector fixture",
        severity="high",
    )
    snapshot = _snapshot().model_copy(update={"sources": [source]})

    ordinary = shadow_assess_with_coverage(
        event,
        PolicyBundle(),
        snapshot,
        server_secret=b"lgv2-output-observation-core-test",
        detection_results=[detection],
        transient_facts=transient,
    )
    observation = shadow_assess_with_coverage(
        event,
        PolicyBundle(),
        snapshot,
        server_secret=b"lgv2-output-observation-core-test",
        detection_results=[detection],
        transient_facts=transient,
        memory_not_required_actions=frozenset({"model_call"}),
        source_dataflow_not_required_actions=frozenset({"model_call"}),
    )

    assert ordinary.action_ir is not None
    assert ordinary.action_ir.impact == "high"
    assert (
        "v21-08:influence_rule:INFLUENCE-POSSIBLE-HIGH"
        in ordinary.assessment.reason_codes
    )
    assert observation.action_ir is not None
    assert observation.action_ir.effects == ActionEffect()
    assert observation.action_ir.impact == "low"
    assert observation.assessment.impact == "low"
    assert set(observation.assessment.required_check_plan.required_domains) == {
        "task",
        "capability",
        "behavior",
    }
    assert (
        "v21-08:influence_rule:INFLUENCE-POSSIBLE-HIGH"
        not in observation.assessment.reason_codes
    )
    assert observation.assessment.signals == ordinary.assessment.signals
    assert observation.action_ir.data_refs == ordinary.action_ir.data_refs
    assert observation.consumed_overlay_digest == transient.overlay_digest
    assert transient.flow_facts[0].taints == ["UNTRUSTED"]
