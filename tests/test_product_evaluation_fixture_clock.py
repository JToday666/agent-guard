"""Explicit synthetic clocks do not change real authority freshness checks."""

from datetime import datetime, timedelta, timezone

import pytest

from guard_api.services.v21_pipeline import V21OfficialEvaluationUnavailableError
from scripts.product_runtime.evidence import EvidenceStore
from scripts.product_runtime.policy_evidence import verify_policy_evidence
from tests.support import product_evaluation
from tests.test_product_activation_ack_receipt import _rig
from tests import test_product_runtime_policy_evidence as policy_fixture

pytestmark = pytest.mark.unit


@pytest.mark.parametrize("runtime", ["langgraph", "openclaw"])
def test_explicit_fixture_clock_keeps_issuance_events_and_authority_consistent(
    tmp_path, runtime
):
    time = [datetime.now(timezone.utc)]

    def clock():
        return time[0]

    harness = product_evaluation.create_product_evaluation_harness(
        tmp_path, runtime=runtime, clock=clock
    )
    assert harness.clock is clock
    assert harness.pipeline._runtime_binding_resolver.clock is clock
    authority = harness.evaluation.product_activation_authority
    assert authority is not None and authority.clock is clock
    records = tuple(harness.store.product_activation_acks_v1.values())
    assert len(records) == 2
    assert {record.unsigned_ack().issued_at for record in records} == {
        time[0].isoformat()
    }
    assert harness.event().timestamp == time[0].isoformat()
    _, parent, _, _ = _rig(tmp_path, runtime=runtime, harness=harness)
    assert parent.decision == "allow"
    assert parent.decision_authority is not None
    assert parent.decision_authority["source"] == "v21"
    assert parent.decision_authority["mode"] == "active"
    before = len(harness.store.audit_events)
    # Exactly expires_at must still reject through the unchanged production API.
    time[0] = max(
        datetime.fromisoformat(record.unsigned_ack().expires_at) for record in records
    )
    with pytest.raises(V21OfficialEvaluationUnavailableError) as raised:
        harness.evaluate(harness.event(event_id="expired", call_id="expired-call"))
    assert raised.value.code == "V21_PRODUCT_RUNTIME_OBSERVATION_MISMATCH"
    assert len(harness.store.audit_events) == before


@pytest.mark.parametrize("runtime", ["langgraph", "openclaw"])
def test_offline_policy_fixture_is_independent_of_live_clock_rollback(
    tmp_path, monkeypatch, runtime
):
    instant = datetime.now(timezone.utc)
    live_reads = []

    class FixtureDatetime(datetime):
        @classmethod
        def now(cls, tz=None):
            return instant.astimezone(tz)

    def rolled_back_live_clock():
        live_reads.append(True)
        return instant - timedelta(microseconds=107_115)

    monkeypatch.setattr(policy_fixture, "datetime", FixtureDatetime)
    monkeypatch.setattr(product_evaluation, "_utc_now", rolled_back_live_clock)
    fixture = policy_fixture.make_policy_replay(
        tmp_path, runtime=runtime, group="ask", category="file"
    )
    assert live_reads == []
    assert fixture.event.timestamp == instant.isoformat()
    assert fixture.snapshot.evaluation_clock.evaluated_at == instant.isoformat()
    authority = verify_policy_evidence(
        fixture.row,
        runtime=runtime,
        scope_id=fixture.scope_id,
        policy=fixture.policy,
        store=EvidenceStore(tmp_path),
        candidate_manifest_digest=policy_fixture.DIGEST,
        adapter_artifact_digest=policy_fixture.ARTIFACT,
    )
    assert authority == fixture.authority
    assert authority.selected_decision.decision == "ask"


def test_harness_default_retains_live_clock_and_rejects_a_real_reference_rollback(
    tmp_path, monkeypatch
):
    wall = [datetime.now(timezone.utc)]
    monkeypatch.setattr(product_evaluation, "_utc_now", lambda: wall[0])
    harness = product_evaluation.create_product_evaluation_harness(tmp_path)
    issued = wall[0]
    wall[0] += timedelta(seconds=1)
    assert harness.event().timestamp == wall[0].isoformat()
    _rig(tmp_path, harness=harness)
    wall[0] = issued - timedelta(microseconds=107_115)
    with pytest.raises(V21OfficialEvaluationUnavailableError) as raised:
        harness.evaluate(harness.event(event_id="rollback", call_id="rollback-call"))
    assert raised.value.code == "V21_PRODUCT_RUNTIME_OBSERVATION_MISMATCH"
