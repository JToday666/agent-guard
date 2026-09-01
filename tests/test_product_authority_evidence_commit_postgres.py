"""PostgreSQL parity for Product V2 critical authority evidence."""

from __future__ import annotations

import pytest

from agentguard_core import PolicyBundle, product_decision_authority_envelope
from agentguard_core.decisions.evidence import decision_v21_envelope

from guard_api.services.audit import AuditService
from guard_api.services.competition import parse_decision_authority_evidence_payload
from guard_api.storage.postgres import PostgresControlPlaneStore
from tests.support.postgres import get_test_database_url, reset_control_plane_schema
from tests.test_product_authority_evidence_commit import (
    _event,
    _product_authority_fixture,
)

pytestmark = pytest.mark.postgres


def test_postgres_roundtrips_product_v2_authority_without_loss() -> None:
    database_url = get_test_database_url()
    reset_control_plane_schema(database_url)
    store = PostgresControlPlaneStore(database_url)
    store.initialize()
    authority_evidence, decision_evidence = _product_authority_fixture()
    envelope = product_decision_authority_envelope(authority_evidence)
    v21_envelope = decision_v21_envelope(decision_evidence.model_dump(mode="json"))

    persisted = AuditService(store=store).record_evaluation(
        _event(),
        authority_evidence.selected_decision,
        policy_bundle=PolicyBundle(),
        policy_revision=None,
        extra_metadata={"policy_digest": authority_evidence.policy_digest},
        v21_evidence=v21_envelope,
        decision_authority_evidence=envelope,
        decision_authority=authority_evidence.decision_authority,
    )
    reopened = PostgresControlPlaneStore(database_url).get_audit_event(
        persisted.audit_id
    )

    assert reopened is not None
    assert reopened == persisted
    assert reopened.evidence is not None
    assert reopened.evidence["decision_authority"] == envelope["decision_authority"]
    assert parse_decision_authority_evidence_payload(envelope) == authority_evidence
