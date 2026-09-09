"""Exercise every non-policy evidence validator with explicit unit inputs."""

import pytest

from scripts.product_runtime.conformance import (
    Facts,
    _event,
    _invocations,
    _native,
    _protocol,
)
from scripts.product_runtime.evidence import EvidenceStore
from scripts.product_runtime.models import CaseResult, Observation, read_model
from scripts.product_runtime.models import AdmissionError
from scripts.product_runtime.requirements import requirements_for
from tests.product_runtime_case_fixture import build_case_fixture
from tests.test_product_runtime_admission import observation
from tests.support.product_activation import (
    build_test_product_activation,
    product_activation_ack_for_status,
    product_runtime_status_for_activation,
)

pytestmark = pytest.mark.unit


@pytest.mark.parametrize(
    "runtime,requirement",
    [
        (runtime, case)
        for runtime in ("langgraph", "openclaw")
        for case in requirements_for(runtime)
        if case.policy_group is None
    ],
    ids=lambda item: item if isinstance(item, str) else item.id,
)
def test_non_policy_case_input_is_complete_and_accepted(tmp_path, runtime, requirement):
    fixture = build_test_product_activation()
    ack = product_activation_ack_for_status(
        fixture, product_runtime_status_for_activation(fixture, runtime)
    ).model_dump(mode="json")
    raw = observation([("consumer", "unit_fixture", {})]).model_dump(mode="json")
    raw.update(runtime=runtime, case_id=requirement.id)
    baseline = requirement.id.startswith("baseline.")
    raw["authority_kind"] = "none" if baseline else "synthetic_contract_fixture"
    case = read_model(
        CaseResult,
        build_case_fixture(
            tmp_path,
            requirement,
            raw,
            baseline_material={},
            ack=ack,
            capability=fixture.capability(runtime).model_dump(mode="json"),
        ),
    )
    store = EvidenceStore(tmp_path)
    obs = read_model(Observation, store.read_json(case.hashed_evidence[0]).data)
    facts = Facts(obs, store)
    _invocations(facts, case)
    if requirement.validator == "native_invocation":
        _native(facts, case, requirement.subject)
    elif requirement.validator == "event_consumer":
        _event(facts, requirement.subject)
    elif requirement.validator == "protocol":
        _protocol(facts, case, requirement.subject)


def test_sqlite_evidence_rejects_executable_view():
    import sqlite3
    from scripts.product_runtime.conformance import _sqlite_rows

    connection = sqlite3.connect(":memory:")
    try:
        connection.execute("CREATE TABLE seed(value TEXT)")
        connection.execute(
            "CREATE VIEW memory AS WITH RECURSIVE sequence(x) AS (SELECT 1 UNION ALL SELECT x+1 FROM sequence) SELECT x AS key,x AS value FROM sequence"
        )
        content = connection.serialize()
    finally:
        connection.close()
    with pytest.raises(AdmissionError, match="conformance_sqlite_schema_invalid"):
        _sqlite_rows(content, "SELECT key,value FROM memory ORDER BY key")


@pytest.mark.parametrize(
    "subject,mutation",
    [
        ("ack.historical_receipt", "wrong_issuance"),
        ("ack.historical_receipt", "wrong_delivery"),
        ("ack.single_flight", "fake_ack"),
        ("ack.consume_retry_fixed", "changed_wire"),
        ("ack.consume_retry_fixed", "duplicate_header"),
    ],
)
def test_ack_protocol_rejects_unbound_observations(tmp_path, subject, mutation):
    fixture = build_test_product_activation()
    ack = product_activation_ack_for_status(
        fixture, product_runtime_status_for_activation(fixture, "langgraph")
    ).model_dump(mode="json")
    requirement = next(
        item for item in requirements_for("langgraph") if item.subject == subject
    )
    raw = observation([("consumer", "unit_fixture", {})]).model_dump(mode="json")
    raw.update(case_id=requirement.id, authority_kind="synthetic_contract_fixture")
    case = read_model(
        CaseResult,
        build_case_fixture(
            tmp_path,
            requirement,
            raw,
            baseline_material={},
            ack=ack,
            capability=fixture.capability("langgraph").model_dump(mode="json"),
        ),
    )
    store = EvidenceStore(tmp_path)
    obs = read_model(Observation, store.read_json(case.hashed_evidence[0]).data)
    if mutation.startswith("wrong_"):
        frame = next(item for item in obs.frames if item.event == "historical_window")
        frame.data["issued_at" if mutation == "wrong_issuance" else "delivery_at"] = (
            "2030-01-01T00:00:00+00:00"
        )
    elif mutation == "fake_ack":
        next(item for item in obs.frames if item.event == "heartbeat_exchange").data[
            "response"
        ]["activation_ack"] = {"unit": "not an ACK"}
    else:
        frame = [item for item in obs.frames if item.event == "consume_exchange"][-1]
        if mutation == "changed_wire":
            frame.data["request_wire"] += " "
        else:
            frame.data["headers"]["X-AgentGuard-Activation-Ack"] = ack["ack_token"]
    with pytest.raises((AdmissionError, ValueError)):
        _protocol(Facts(obs, store), case, subject)


@pytest.mark.parametrize(
    "leak", [None, "request", "memory", "inbox", "released", "digest"]
)
def test_quarantined_target_requires_actual_withheld_result_and_clean_next_turn(
    tmp_path, leak
):
    import hashlib
    import json
    from agentguard_core import RuntimeOutcomeReceipt
    from scripts.product_runtime.conformance import _target_result_isolation
    from tests.test_product_runtime_admission import receipt_frames
    from tests.test_product_runtime_policy_evidence import _save

    sentinel = "SYNTHETIC QUARANTINED MEMORY CONTENT"
    host = json.dumps({"key": "note", "value": sentinel}).encode()
    original_ref = _save(tmp_path, "host-result.json", host)
    digest = "sha256:" + hashlib.sha256(host).hexdigest()
    request = {"messages": [{"role": "tool", "content": "[quarantined]"}]}
    memory, inbox, released = [], [], "[quarantined]"
    if leak == "request":
        request["messages"][0]["content"] = {"nested": f"prefix {sentinel} suffix"}
    elif leak == "memory":
        memory = [{"key": "new-note", "value": sentinel}]
    elif leak == "inbox":
        inbox = [{"text": f"prefix {sentinel}"}]
    elif leak == "released":
        released = {sentinel: "sensitive key"}
    row = {
        "invocation_id": "unit-target",
        "disposition": "quarantined",
        "original_result_digest": digest if leak != "digest" else "sha256:" + "f" * 64,
        "withheld_content": sentinel,
        "released_result": _save(tmp_path, "released.json", released),
        "next_model_request": _save(tmp_path, "request.json", request),
        "subsequent_memory_writes": _save(tmp_path, "memory.json", memory),
        "subsequent_inbox_messages": _save(tmp_path, "inbox.json", inbox),
        "published_original": False,
    }
    obs = observation(
        [
            (
                "host",
                "tool_result",
                {"invocation_id": "unit-target", "result_digest": digest},
            ),
            ("consumer", "target_result_isolation", row),
        ]
    ).model_dump(mode="json")
    obs["frames"][0]["attachments"] = [original_ref]
    receipt = json.loads(receipt_frames()[0][2]["wire"])
    receipt["evidence"]["result"]["disposition"] = "quarantined"
    receipt["evidence"]["execution"]["tool_result_entered_context"] = False
    facts = Facts(read_model(Observation, obs), EvidenceStore(tmp_path))
    if leak is None:
        _target_result_isolation(
            facts, RuntimeOutcomeReceipt.model_validate(receipt), "unit-target"
        )
    else:
        with pytest.raises(AdmissionError):
            _target_result_isolation(
                facts, RuntimeOutcomeReceipt.model_validate(receipt), "unit-target"
            )
