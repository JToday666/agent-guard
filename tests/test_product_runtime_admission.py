"""Offline signer unit fixtures. These tests are not candidate conformance reports."""

from __future__ import annotations

from copy import deepcopy
from dataclasses import replace
from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path
import stat
from types import SimpleNamespace

import pytest

from agentguard_core import PolicyBundle
from agentguard_core.actions.canonical_json import canonical_sha256
from guard_api.settings import GuardApiSettings
from scripts.product_runtime import signing
from scripts.product_runtime.conformance import (
    Facts,
    _blocked,
    _contains_sentinel,
    _installed_consumer,
    _native,
    _protocol,
    _receipt,
    derive_activation_target,
    policy_templates,
)
from scripts.product_runtime.evidence import EvidenceStore
from scripts.product_runtime.models import (
    AdmissionError,
    EvidenceRef,
    Observation,
    ReviewRecord,
    RuntimeIdentity,
    SigningRequest,
    read_model,
)
from scripts.product_runtime.requirements import (
    requirements_digest,
    requirements_document,
    requirements_for,
)
from tests.support.product_activation import build_test_product_activation
from tests.support.product_tool_catalog import catalog_fixture

pytestmark = pytest.mark.unit
REVISION = "a" * 40
DIGEST = "sha256:" + "b" * 64
REF = {"path": "unit-fixture.json", "size": 0, "raw_sha256": DIGEST}


def observation(frames):
    return read_model(
        Observation,
        {
            "schema_version": "agentguard-product-case-observation/1",
            "runtime": "langgraph",
            "source_revision": REVISION,
            "candidate_manifest_digest": DIGEST,
            "adapter_artifact_digest": DIGEST,
            "case_id": "unit_fixture",
            "scope_id": "unit_fixture",
            "process_id": 101,
            "consumer_module": "agentguard_langgraph_adapter/product_outbox.py",
            "consumer_file": REF,
            "entrypoint": "unit_fixture",
            "authority_kind": "synthetic_contract_fixture",
            "frames": [
                {
                    "sequence": i,
                    "actor": actor,
                    "event": event,
                    "data": data,
                    "attachments": [],
                }
                for i, (actor, event, data) in enumerate(frames)
            ],
        },
    )


def facts(tmp_path, frames):
    return Facts(observation(frames), EvidenceStore(tmp_path))


@pytest.mark.parametrize("runtime,count", [("langgraph", 52), ("openclaw", 54)])
def test_requirements_are_closed_sorted_and_commit_reconciliation(runtime, count):
    rows = requirements_for(runtime)
    assert len(rows) == count == len({row.id for row in rows})
    assert [row.id for row in rows] == sorted(row.id for row in rows)
    assert requirements_digest() == canonical_sha256(requirements_document())
    assert (
        "explicit_original_wire"
        in requirements_document()["permanent_receipt_recovery"]
    )
    assert {row.policy_group for row in rows if row.validator == "policy_chain"} == {
        "allow",
        "ask",
        "deny",
    }


@pytest.mark.parametrize(
    "patch",
    [
        {"size": False},
        {"size": "0"},
        {"path": "../key"},
        {"path": "/key"},
        {"path": "a//b"},
        {"path": "a/./b"},
        {"path": "a\\b"},
        {"extra": True},
        {"raw_sha256": "b" * 64},
    ],
)
def test_reference_rejects_ambiguous_types_paths_and_digests(patch):
    with pytest.raises(AdmissionError):
        read_model(EvidenceRef, REF | patch)


def test_templates_are_complete_valid_and_only_frozen_changes():
    templates = policy_templates()
    assert templates["ask"] == PolicyBundle().model_dump(mode="json")
    allow = deepcopy(templates["ask"])
    allow["allowed_email_domains"].append("agentguard.invalid")
    assert templates["allow"] == allow
    assert templates["deny"]["dangerous_command_markers"][-2:] == [
        "python marker.py",
        "node marker.mjs",
    ]
    assert (
        templates["deny"]["rule_overrides"]["P005_external_send"]["decision"] == "deny"
    )
    assert (
        templates["deny"]["rule_overrides"]["P104_memory_poisoning"]["decision"]
        == "deny"
    )
    templates["allow"]["allowed_email_domains"].clear()
    assert policy_templates()["allow"]["allowed_email_domains"]


@pytest.mark.parametrize("runtime", ["langgraph", "openclaw"])
def test_derived_capability_only_changes_activation(runtime):
    from agentguard_core.decisions.product import build_runtime_capability_report

    fixture = build_test_product_activation()
    active = fixture.capability(runtime)
    values = active.model_dump(mode="json", exclude={"report_digest"})
    values["active"] = False
    for item in values["events"]:
        item["active"] = False
    observed = build_runtime_capability_report(**values)
    assert derive_activation_target(observed.model_dump(mode="json")) == active
    with pytest.raises(AdmissionError):
        derive_activation_target(active.model_dump(mode="json"))
    altered = observed.model_dump(mode="json")
    altered["c3_atomic_replace_and_seal"] = runtime != "langgraph"
    with pytest.raises(ValueError):
        derive_activation_target(altered)


def receipt_frames(status=409):
    from agentguard_langgraph_adapter.activation_ack import ActivationAckV1 as ClientAck
    from agentguard_langgraph_adapter.event_models import (
        PolicyDecision,
        SecurityContext,
        ToolCallEvent,
        ToolDescriptor,
    )
    from agentguard_langgraph_adapter.runtime_receipts import build_runtime_outcome
    from tests.support.product_activation import (
        product_runtime_status_for_activation,
        product_activation_ack_for_status,
    )

    fixture = build_test_product_activation()
    ack = product_activation_ack_for_status(
        fixture, product_runtime_status_for_activation(fixture, "langgraph")
    ).model_dump(mode="json")
    event = ToolCallEvent(
        event_id="event-unit-1",
        trace_id="trace-unit-1",
        security_context=SecurityContext(agent_id=ack["agent_id"]),
        tool=ToolDescriptor(
            name="write", category="file", kind="write", call_id="action-unit-1"
        ),
        arguments={"path": "output.txt", "content": "unit fixture"},
    )
    decision = PolicyDecision(
        decision_id="decision-unit-1",
        decision="allow",
        risk_score=0,
        severity="low",
        reason="unit fixture",
        policy_audit_id="policy-unit-1",
    )
    decision._evaluation_activation_ack = ClientAck.model_validate(ack)
    terminal = build_runtime_outcome(
        event,
        decision,
        execution_status="executed",
        completed_at=(datetime.now(timezone.utc) + timedelta(seconds=2)).isoformat(),
    )
    wire = json.dumps(terminal.to_wire(), sort_keys=True, separators=(",", ":"))
    audit_id = terminal.audit_id
    digest = hashlib.sha256(wire.encode()).hexdigest()
    ack_digest = canonical_sha256(ack)
    exchange = {
        "audit_id": audit_id,
        "wire": wire,
        "wire_digest": digest,
        "activation_ack": ack,
        "ack_digest": ack_digest,
    }
    frames = [
        ("journal", "durable_receipt", exchange | {"phase": "terminal_pending"}),
        (
            "http",
            "receipt_exchange",
            exchange
            | {
                "status": status,
                "response": {"ok": False},
                "observed_at": terminal.timestamp,
                "headers": {"content-type": "application/json"},
            },
        ),
        ("journal", "permanent_rejected", {"wire_digest": digest, "breaker": True}),
    ]
    frames.extend(
        (
            "journal",
            "passive_recovery",
            {
                "operation": operation,
                "additional_posts": 0,
                "additional_invocations": 0,
            },
        )
        for operation in ("automatic_drain", "duplicate_submit", "restart")
    )
    frames.extend(
        [
            ("effect", "recovery_count", {"phase": "before", "count": 1}),
            (
                "http",
                "fault_removed",
                {"fault_kind": "injected_transport_rejection", "audit_id": audit_id},
            ),
            (
                "journal",
                "explicit_reconcile",
                {"audit_id": audit_id, "expected_wire_digest": digest},
            ),
            (
                "consumer",
                "receipts_only_worker",
                {"process_id": 102, "model_requests": 0, "tool_invocations": 0},
            ),
            (
                "http",
                "receipt_exchange",
                exchange
                | {
                    "status": 201,
                    "response": {"ok": True, "audit_id": audit_id},
                    "observed_at": terminal.timestamp,
                    "headers": {"content-type": "application/json"},
                },
            ),
            ("journal", "confirmed", {"audit_id": audit_id, "wire_digest": digest}),
            (
                "postgres",
                "receipt_row",
                {
                    "audit_id": audit_id,
                    "wire_digest": digest,
                    "ack_digest": ack_digest,
                    "row_count": 1,
                    "links": json.loads(wire)["links"],
                },
            ),
            ("effect", "recovery_count", {"phase": "after", "count": 1}),
        ]
    )
    return frames


@pytest.mark.parametrize("status", [409, 422])
def test_permanent_recovery_requires_original_wire_and_ack_explicit_reconcile(
    tmp_path, status
):
    _receipt(facts(tmp_path, receipt_frames(status)), permanent=status)


@pytest.mark.parametrize(
    "event",
    [
        "durable_receipt",
        "permanent_rejected",
        "fault_removed",
        "explicit_reconcile",
        "receipts_only_worker",
        "confirmed",
        "receipt_row",
        "passive_recovery",
    ],
)
def test_permanent_recovery_cannot_be_only_retained_or_pass_claim(tmp_path, event):
    frames = [row for row in receipt_frames() if row[1] != event]
    with pytest.raises((AdmissionError, ValueError)):
        _receipt(facts(tmp_path, frames), permanent=409)


@pytest.mark.parametrize(
    "mutation",
    [
        "ack",
        "wire",
        "extra_effect",
        "missing_pg",
        "still_rejected",
        "reexecute",
        "hot_retry",
        "bool_counter",
    ],
)
def test_permanent_recovery_rejects_replacement_loss_and_false_success(
    tmp_path, mutation
):
    frames = deepcopy(receipt_frames())
    final = [data for actor, event, data in frames if event == "receipt_exchange"][-1]
    if mutation == "ack":
        final["activation_ack"] = {"unit_fixture": "fresh-ack"}
    elif mutation == "wire":
        final["wire"] += " "
    elif mutation == "extra_effect":
        frames[-1][2]["count"] += 1
    elif mutation == "missing_pg":
        next(data for _, event, data in frames if event == "receipt_row")[
            "row_count"
        ] = 0
    elif mutation == "still_rejected":
        final.update(status=422, response={"ok": False})
    elif mutation == "reexecute":
        next(data for _, event, data in frames if event == "receipts_only_worker")[
            "tool_invocations"
        ] = 1
    elif mutation == "hot_retry":
        next(data for _, event, data in frames if event == "passive_recovery")[
            "additional_posts"
        ] = 1
    else:
        frames[-1][2]["count"] = True
    with pytest.raises(AdmissionError):
        _receipt(facts(tmp_path, frames), permanent=409)


def test_unknown_requires_no_observed_terminal_and_zero_reexecution(tmp_path):
    rows = [
        (
            "journal",
            "unknown",
            {
                "terminal_observed": False,
                "intent_durable": True,
                "breaker": True,
                "additional_invocations": 0,
                "drain_posts": 0,
            },
        ),
        ("postgres", "release_gate", {"row_count": 1}),
    ]
    case = SimpleNamespace(receipt_disposition="unknown_retained")
    _protocol(facts(tmp_path, rows), case, "unknown_no_reexecution")
    rows[0][2]["terminal_observed"] = True
    with pytest.raises(AdmissionError):
        _protocol(facts(tmp_path, rows), case, "unknown_no_reexecution")


def test_key_encoding_matches_actual_api_and_secret_read_checks(tmp_path):
    raw = bytes(range(32))
    key = tmp_path / "product.key"
    key.write_bytes(raw)
    key.chmod(0o600)
    assert signing._secret_file(key) == raw
    settings = GuardApiSettings(
        v21_product_activation_server_secret=signing.api_secret_value(raw)
    )
    assert settings.v21_product_activation_server_secret_bytes() == raw
    key.chmod(0o644)
    with pytest.raises(AdmissionError):
        signing._secret_file(key)


@pytest.mark.parametrize("kind", ["short", "long", "symlink", "hardlink"])
def test_key_rejects_ambiguous_or_shared_storage(tmp_path, kind):
    key = tmp_path / "key"
    key.write_bytes(b"k" * ({"short": 31, "long": 33}.get(kind, 32)))
    key.chmod(0o600)
    if kind in {"symlink", "hardlink"}:
        target = tmp_path / "alias"
        target.symlink_to(key) if kind == "symlink" else target.hardlink_to(key)
        key = target
    with pytest.raises((AdmissionError, OSError)):
        signing._secret_file(key)


def unit_signing_inputs(tmp_path):
    """Isolate crypto/output unit tests; never used by the admission CLI."""
    data = catalog_fixture(tmp_path)
    now = datetime.now(timezone.utc)
    request = read_model(
        SigningRequest,
        {
            "schema_version": "agentguard-product-signing-request/1",
            "source_revision": REVISION,
            **{
                name: REF
                for name in (
                    "candidate_manifest",
                    "langgraph_conformance",
                    "openclaw_conformance",
                    "capability_matrix",
                    "tool_catalog",
                    "dataset_manifest",
                    "contract_manifest",
                    "review_record",
                )
            },
            "policy_groups": [
                {"id": group, "policy_bundle": REF}
                for group in ("allow", "ask", "deny")
            ],
            "runtime_identities": [
                {
                    key: getattr(entry, key)
                    for key in (
                        "runtime",
                        "principal_id",
                        "agent_id",
                        "runtime_binding_id",
                        "canary_cohort",
                    )
                }
                for entry in data.bundle.runtimes
            ],
            "issued_at": (now - timedelta(seconds=1)).isoformat(),
            "expires_at": (now + timedelta(hours=1)).isoformat(),
            "signer_key_id": "unit-fixture-key",
        },
    )
    review = read_model(
        ReviewRecord,
        {
            "schema_version": "agentguard-product-signing-review/1",
            "source_revision": REVISION,
            "candidate_manifest_digest": DIGEST,
            "reviewer_id": "unit-fixture-reviewer",
            "reviewer_kind": "ai_reviewer",
            "review_completed": True,
            "authorization_source": "unit_fixture",
            "authorization_text": "Synthetic unit test only; never qualification evidence.",
            "policy_groups": ["allow", "ask", "deny"],
            "runtimes": ["langgraph", "openclaw"],
            "scope": "fixed_isolated_profiles",
            "production_acceptance_claimed": False,
            "long_term_validation_claimed": False,
        },
    )
    entries = tuple(
        entry.model_dump(mode="json") | {"expires_at": request.expires_at}
        for entry in data.bundle.runtimes
    )
    materials = {
        name: SimpleNamespace(data={}, canonical_digest=DIGEST)
        for name in ("dataset_manifest", "contract_manifest", "capability_matrix")
    }
    materials["tool_catalog"] = SimpleNamespace(
        data=data.document, canonical_digest=canonical_sha256(data.document)
    )
    package_root = (
        Path(__file__).resolve().parents[1] / "packages/agentguard-openclaw-plugin"
    )
    candidate = SimpleNamespace(
        canonical_digest=DIGEST,
        installation_reports={
            "openclaw": SimpleNamespace(
                data={"lanes": [{"lane": "product", "plugin_root": str(package_root)}]}
            )
        },
    )
    return signing.VerifiedAdmissionInputs(
        request=request,
        candidate=candidate,
        reports={
            runtime: SimpleNamespace(document=SimpleNamespace(canonical_digest=DIGEST))
            for runtime in ("langgraph", "openclaw")
        },
        policies={
            key: PolicyBundle.model_validate(value)
            for key, value in policy_templates().items()
        },
        materials=materials,
        entries=entries,
        review=review,
        store=SimpleNamespace(recheck_reads=lambda: None),
        request_reference=REF,
        checkout=tmp_path,
        marker=signing._VERIFIED,
    )


def prepare_signing(tmp_path, monkeypatch, *, real_openclaw_reader=False):
    inputs = unit_signing_inputs(tmp_path)
    monkeypatch.setattr(signing, "verify_request", lambda *args, **kwargs: inputs)
    if not real_openclaw_reader:
        # The unit layer isolates the process boundary. The integration case
        # below executes the actual built Node reader with these same outputs.
        def process_boundary(argv, **_kwargs):
            assert argv[0] == "node" and argv[1] == "--input-type=module"
            assert "OpenClawProductManifest.fromFile" in argv[3]
            manifest = json.loads(Path(argv[5]).read_bytes())
            assert manifest["activation_ref_digest"] == argv[6]
            return 0, b"", b""

        monkeypatch.setattr(signing, "bounded_command", process_boundary)
    key, shadow = tmp_path / "product.key", tmp_path / "shadow.key"
    for path, content in ((key, b"p" * 32), (shadow, b"s" * 32)):
        path.write_bytes(content)
        path.chmod(0o600)
    parent = tmp_path / "outputs"
    parent.mkdir(mode=0o700)
    return inputs, key, shadow, parent / "signed"


def test_three_group_signing_uses_real_core_api_loader_and_protected_manifests(
    tmp_path, monkeypatch
):
    inputs, key, shadow, output = prepare_signing(tmp_path, monkeypatch)
    result = signing.sign_verified(
        inputs, key_file=key, shadow_key_file=shadow, output_dir=output
    )
    assert result["product_active_run_completed"] is False
    assert len(set(result["activation_refs"].values())) == 3
    assert stat.S_IMODE(output.stat().st_mode) == 0o700
    for group in ("allow", "ask", "deny"):
        activation = json.loads((output / group / "activation.json").read_bytes())
        assert activation["candidate_artifact_manifest_digest"] == DIGEST
        assert (
            activation["rollout_admission_record"]["tool_inventory_digest"]
            == inputs.entries[1]["tool_inventory_digest"]
        )
        assert (
            stat.S_IMODE((output / group / "activation.json").stat().st_mode) == 0o400
        )
        assert (
            stat.S_IMODE((output / group / "openclaw-manifest.json").stat().st_mode)
            == 0o600
        )
    assert not list(output.parent.glob(".product-sign-*"))


@pytest.mark.parametrize(
    "failure",
    ["same_key", "write_failure", "loader_failure", "existing_output", "unverified"],
)
def test_failed_signing_leaves_no_usable_output(tmp_path, monkeypatch, failure):
    inputs, key, shadow, output = prepare_signing(tmp_path, monkeypatch)
    if failure == "same_key":
        shadow.write_bytes(key.read_bytes())
    elif failure == "write_failure":
        original = signing._write

        def fail(path, value, mode=0o600):
            original(path, value, mode)
            if path.name == "activation.json":
                raise OSError("unit_fixture")

        monkeypatch.setattr(signing, "_write", fail)
    elif failure == "loader_failure":
        monkeypatch.setattr(
            signing,
            "_validate_outputs",
            lambda *args: (_ for _ in ()).throw(AdmissionError("unit_fixture")),
        )
    elif failure == "existing_output":
        output.mkdir()
        (output / "sentinel").write_text("keep")
    else:
        inputs = replace(inputs, marker=object())
    with pytest.raises((AdmissionError, OSError)):
        signing.sign_verified(
            inputs, key_file=key, shadow_key_file=shadow, output_dir=output
        )
    assert not list(output.parent.glob(".product-sign-*"))
    assert output.exists() is (failure == "existing_output")
    if output.exists():
        assert (output / "sentinel").read_text() == "keep"


def test_atomic_commit_does_not_replace_even_empty_existing_directory(tmp_path):
    stage, output = tmp_path / "stage", tmp_path / "output"
    stage.mkdir()
    output.mkdir()
    (stage / "unit").write_text("fixture")
    with pytest.raises(AdmissionError):
        signing._commit_directory(stage, output)
    assert not list(output.iterdir()) and (stage / "unit").exists()


def test_signing_rechecks_real_clock_after_validation(tmp_path, monkeypatch):
    inputs, key, shadow, output = prepare_signing(tmp_path, monkeypatch)
    clocks = iter(
        [
            datetime.now(timezone.utc),
            datetime.fromisoformat(inputs.request.expires_at) + timedelta(seconds=1),
        ]
    )

    class AdvancingClock(datetime):
        @classmethod
        def now(cls, tz=None):
            return next(clocks)

    monkeypatch.setattr(signing, "datetime", AdvancingClock)
    with pytest.raises(AdmissionError):
        signing.sign_verified(
            inputs, key_file=key, shadow_key_file=shadow, output_dir=output
        )
    assert not output.exists() and not list(output.parent.glob(".product-sign-*"))


def test_parent_fsync_failure_removes_committed_outputs(tmp_path, monkeypatch):
    inputs, key, shadow, output = prepare_signing(tmp_path, monkeypatch)
    parent_inode = output.parent.stat().st_ino
    original = signing.os.fsync

    def fail_parent(descriptor):
        if signing.os.fstat(descriptor).st_ino == parent_inode:
            assert output.exists()
            raise OSError("synthetic parent directory fsync failure")
        original(descriptor)

    monkeypatch.setattr(signing.os, "fsync", fail_parent)
    with pytest.raises(OSError):
        signing.sign_verified(
            inputs, key_file=key, shadow_key_file=shadow, output_dir=output
        )
    assert not output.exists() and not list(output.parent.glob(".product-sign-*"))


@pytest.mark.parametrize(
    "offset,duration",
    [
        (timedelta(hours=1), timedelta(hours=2)),
        (-timedelta(days=2), timedelta(days=1)),
        (-timedelta(seconds=1), timedelta(days=15)),
    ],
)
def test_window_rejects_future_expired_or_overlong(offset, duration):
    now = datetime.now(timezone.utc)
    with pytest.raises(AdmissionError):
        signing._window(
            (now + offset).isoformat(), (now + offset + duration).isoformat(), now
        )


@pytest.mark.parametrize(
    "value", ["operator test", "operator/test", "@operator", "a" * 129, "operator\n"]
)
def test_runtime_identity_matches_both_adapter_identifier_readers(value):
    with pytest.raises(AdmissionError):
        read_model(
            RuntimeIdentity,
            {
                "runtime": "openclaw",
                "principal_id": value,
                "agent_id": "agent",
                "runtime_binding_id": "binding",
                "canary_cohort": "unit",
            },
        )


@pytest.mark.parametrize(
    "value",
    [
        "prefix UNIT_SECRET suffix",
        ["prefix UNIT_SECRET suffix"],
        {"payload": {"text": "UNIT_SECRET"}},
        [{"UNIT_SECRET": "value"}],
        {"tool_message": '{"value":"UNIT_\\u0053ECRET"}'},
    ],
)
def test_isolation_checks_substrings_recursively_in_values_and_keys(value):
    assert _contains_sentinel(value, "UNIT_SECRET")
    assert not _contains_sentinel(value, "DIFFERENT_SECRET")


def test_expired_ack_negative_replays_actual_langgraph_reader(tmp_path):
    ack = receipt_frames()[0][2]["activation_ack"]
    rows = [
        (
            "consumer",
            "fault_input",
            {
                "case": "ack.expiry",
                "input": {"activation_ack": ack, "now": ack["expires_at"]},
            },
        ),
        ("consumer", "rejected", {"reason_code": "ack_expired", "new_invocations": 0}),
    ]
    _blocked(facts(tmp_path, rows), expected_reason="ack.expiry")
    rows[0][2]["input"]["now"] = ack["issued_at"]
    with pytest.raises(AdmissionError):
        _blocked(facts(tmp_path, rows), expected_reason="ack.expiry")


def test_report_cannot_choose_its_own_negative_reason(tmp_path):
    rows = [
        (
            "consumer",
            "fault_input",
            {
                "case": "ack.expiry",
                "input": {"x": 1},
                "expected_reason_codes": ["anything"],
            },
        ),
        ("consumer", "rejected", {"reason_code": "anything", "new_invocations": 0}),
    ]
    with pytest.raises(ValueError):
        _blocked(facts(tmp_path, rows), expected_reason="ack.expiry")


@pytest.mark.parametrize(
    "change",
    [
        "missing_outcome",
        "missing_ack",
        "metadata_ack",
        "header_ack",
        "duplicate_header",
    ],
)
def test_receipt_must_be_a_real_outcome_with_same_historical_carriers(tmp_path, change):
    rows = receipt_frames()
    original = rows[0][2]
    if change == "missing_outcome":
        original["wire"] = json.dumps({"audit_id": original["audit_id"], "links": {}})
    elif change == "missing_ack":
        original["activation_ack"] = {"unit_fixture": "not-an-ack"}
    elif change == "metadata_ack":
        payload = json.loads(original["wire"])
        payload["metadata"]["activation_ack"]["ack_token"] = "hmac-sha256:" + "e" * 64
        original["wire"] = json.dumps(payload)
    elif change == "header_ack":
        rows[1][2]["headers"]["X-AgentGuard-Activation-Ack"] = "hmac-sha256:" + "e" * 64
    else:
        rows[1][2]["headers"].update(
            {
                "X-AgentGuard-Activation-Ack": original["activation_ack"]["ack_token"],
                "x-agentguard-activation-ack": original["activation_ack"]["ack_token"],
            }
        )
    with pytest.raises((AdmissionError, ValueError)):
        _receipt(facts(tmp_path, rows), permanent=409)


@pytest.mark.parametrize("tool", ["write", "exec", "edit", "read"])
def test_native_links_distinct_host_response_to_correct_file_effect(tmp_path, tool):
    before = b"original fixture\n"
    args = {
        "write": {"path": "output.txt", "content": "written fixture\n"},
        "exec": {"command": "python marker.py"},
        "edit": {
            "path": "fixture.txt",
            "edits": [{"oldText": "original", "newText": "edited"}],
        },
        "read": {"path": "fixture.txt"},
    }[tool]
    after = {
        "write": b"written fixture\n",
        "exec": before + b"isolated command executed\n",
        "edit": b"edited fixture\n",
        "read": before,
    }[tool]
    response = (
        before
        if tool == "read"
        else json.dumps(
            {"ok": True, "path": "output.txt"}
            if tool != "exec"
            else {"exit_code": 0, "stdout": "marker output", "execution": 1}
        ).encode()
    )
    store = EvidenceStore(tmp_path)
    refs = []
    for index, content in enumerate((before, after, response)):
        path = tmp_path / f"{index}.bin"
        path.write_bytes(content)
        refs.append(store.capture(path.name).reference())
    before_data = {
        "kind": "file",
        "phase": "before",
        "target": "fixture",
        "count": 0,
        "content_digest": refs[0]["raw_sha256"],
        "invocation_id": "invocation",
    }
    after_data = before_data | {
        "phase": "after",
        "count": 1,
        "content_digest": refs[1]["raw_sha256"],
    }
    calls = {"tool_name": tool, "invocation_id": "invocation", "arguments": args}
    obs = observation(
        [
            ("effect", "snapshot", before_data),
            ("model", "tool_call_requested", calls),
            ("host", "tool_invocation", calls),
            (
                "host",
                "tool_result",
                {
                    "invocation_id": "invocation",
                    "is_error": False,
                    "result_digest": refs[2]["raw_sha256"],
                },
            ),
            ("effect", "snapshot", after_data),
        ]
    )
    raw = obs.model_dump(mode="json")
    raw["entrypoint"] = "StateGraph.ToolNode"
    for position, ref in zip((0, 4, 3), refs, strict=True):
        raw["frames"][position]["attachments"] = [ref]
    case = SimpleNamespace(invocation_count=1, model_kind="controlled_local")
    _native(Facts(read_model(Observation, raw), store), case, tool)
    if tool == "write":
        raw["frames"][2]["data"]["arguments"]["content"] = "different content"
        raw["frames"][1]["data"]["arguments"]["content"] = "different content"
        with pytest.raises(AdmissionError):
            _native(Facts(read_model(Observation, raw), store), case, tool)


@pytest.mark.parametrize(
    "change", [None, "copy", "different_case", "package_json", "other_runtime"]
)
def test_consumer_requires_actual_installed_runtime_path_and_case_module(
    tmp_path, change
):
    from pathlib import Path
    from tests.test_product_runtime_candidate import unit_candidate, _verify

    f = unit_candidate.__wrapped__(
        tmp_path,
        extra_python={
            "agentguard-langgraph-adapter": {
                "agentguard_langgraph_adapter/native_tools.py": b"# explicit synthetic unit consumer\n"
            }
        },
    )
    candidate = _verify(f)
    package = next(
        row
        for row in candidate.installation_reports["python"].data["packages"]
        if row["distribution"] == "agentguard-langgraph-adapter"
    )
    path = Path(package["module_file"]).parent / "native_tools.py"
    store = EvidenceStore(f.root)
    raw = observation([("consumer", "unit_fixture", {})]).model_dump(mode="json")
    raw.update(
        case_id="baseline.tool.read",
        consumer_module="agentguard_langgraph_adapter/native_tools.py",
        consumer_file=store.capture(store.relative(path)).reference(),
    )
    if change == "copy":
        copied = f.root / "copied.py"
        copied.write_bytes(path.read_bytes())
        raw["consumer_file"] = store.capture(copied.name).reference()
    elif change == "different_case":
        raw["case_id"] = "contract.receipt.permanent_409"
    elif change == "package_json":
        raw["consumer_module"] = "package.json"
    elif change == "other_runtime":
        raw["runtime"] = "openclaw"
    observed = read_model(Observation, raw)
    if change is None:
        _installed_consumer(observed, candidate, store)
    else:
        with pytest.raises(AdmissionError):
            _installed_consumer(observed, candidate, store)
