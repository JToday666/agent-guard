"""Context source identity contracts with synthetic parents, no Host claim."""

from copy import deepcopy

import pytest
from agentguard_core import AuditEvent
from guard_api.services.product_model_content import verify_product_model_content
from tests.test_product_model_content import _ct, _fixture
from tests.test_v21_05_provenance import make_flow

pytestmark = pytest.mark.integration


@pytest.mark.parametrize(
    "binding", ["valid", "missing_record", "foreign_target", "missing_source"]
)
def test_context_artifact_requires_its_original_complete_source_and_observed_flow(
    tmp_path, binding
):
    rig = _fixture(tmp_path)
    context_ref = "context:original-context"
    flow = make_flow(
        "context-assembly",
        rig.user.source_id,
        context_ref if binding != "foreign_target" else "context:invented",
        relation="assembled_into",
        taints=[],
    ).model_copy(update={"scope_digest": rig.snapshot.scope.scope_digest})
    if binding != "missing_record":
        raw = deepcopy(rig.input.model_dump(mode="json"))
        raw.pop("integrity", None)
        raw.update(audit_id="audit:original-context", event_type="context_assembled")
        raw["links"].update(event_id="original-context")
        raw["evidence"]["decision_authority"]["payload"].update(
            event_id="original-context", event_type="context_assembled"
        )
        raw["evidence"]["ct_transient_facts"] = _ct(
            "original-context",
            rig.snapshot.scope.scope_digest,
            [] if binding == "missing_source" else [rig.user],
            [flow],
        )
        assert rig.harness.store.add_audit_event(AuditEvent.model_validate(raw))
    snapshot = rig.snapshot.model_copy(update={"flows": (*rig.snapshot.flows, flow)})
    proof = verify_product_model_content(
        rig.harness.store, rig.event, snapshot, rig.tool
    )
    assert (context_ref in proof.artifact_refs) is (binding == "valid")
    assert proof.covers_flow_endpoints(flow) is (binding == "valid")
    assert "context:invented" not in proof.artifact_refs
    assert proof.source_refs == tuple(sorted((rig.user.source_id, rig.model.source_id)))
    assert "UNTRUSTED" in proof.taints and rig.model.trust == "unknown"
