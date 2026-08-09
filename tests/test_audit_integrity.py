from __future__ import annotations

import pytest

from agentguard_core import AuditEvent
from guard_api.storage.base import AuditCanonicalizationError
from guard_api.storage.integrity import (
    CANONICALIZATION,
    canonical_json_bytes,
    canonical_sha256,
    verify_audit_chain,
)
from guard_api.storage.memory import MemoryControlPlaneStore


def test_canonical_json_matches_rfc8785_reference_vector() -> None:
    payload = {
        "numbers": [333333333.33333329, 1e30, 4.50, 2e-3, 1e-27],
        "string": '€$\x0f\nA\'B"\\\\"/',
        "literals": [None, True, False],
    }
    expected = r"""{"literals":[null,true,false],"numbers":[333333333.3333333,1e+30,4.5,0.002,1e-27],"string":"€$\u000f\nA'B\"\\\\\"/"}""".encode()

    assert canonical_json_bytes(payload) == expected
    assert CANONICALIZATION == "jcs:rfc8785"


def test_canonical_json_rejects_values_outside_ijson_number_domain() -> None:
    with pytest.raises(AuditCanonicalizationError):
        canonical_sha256({"unsafe_integer": 2**60})


def test_integrity_verification_reports_invalid_metadata_without_raising() -> None:
    store = MemoryControlPlaneStore()
    event = AuditEvent(
        audit_id="audit_jcs_metadata",
        trace_id="trace_jcs_metadata",
        summary="JCS metadata contract",
        decision="allow",
        risk_score=0,
        severity="low",
        blocked=False,
        reason="ok",
    )
    store.add_audit_event(event)
    stored = store.audit_events[0]
    assert stored.model_extra is not None
    metadata = stored.model_extra["integrity"]
    metadata_payload = metadata.model_dump(mode="json")
    metadata_payload["canonicalization"] = "json:v1"
    stored.model_extra["integrity"] = metadata_payload

    status = verify_audit_chain(store.audit_events)

    assert status.valid is False
    assert status.first_broken_audit_id == event.audit_id
