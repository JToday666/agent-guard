"""Focused contract tests for the runtime-neutral P0 activation models."""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, cast

import pytest
from jsonschema import Draft202012Validator
from pydantic import ValidationError

from agentguard_core.actions.canonical_json import (
    canonical_hmac_sha256,
    canonical_json_bytes,
    canonical_sha256,
)
from agentguard_core import (
    ActivationAckV1,
    ApprovalReleaseDirectiveV2,
    OPENCLAW_RESIDUAL_BOUNDARIES,
    ProductActivationBundleV1,
    ResidualRiskAcceptanceV1,
    RolloutAdmissionRecordV1,
    RuntimeActivationEntryV1,
    RuntimeCapabilityReportV2,
    RuntimeEventCapabilityV2,
    build_activation_ack,
    build_approval_release_directive,
    build_product_activation_bundle,
    build_residual_risk_acceptance,
    build_rollout_admission_record,
    build_runtime_capability_report,
    legacy_approval_release_projection,
    openclaw_event_residual_boundaries,
    select_product_v21_authority,
    verify_activation_ack,
    verify_product_activation_bundle,
    verify_residual_risk_acceptance,
    verify_rollout_admission_record,
)
from agentguard_core.decisions.competition import V21AuthoritySelectionError
from agentguard_core.decisions.product import PRODUCT_EVENT_TYPES

pytestmark = pytest.mark.contract

ROOT = Path(__file__).resolve().parents[1]
SECRET = b"product-v2-contract-secret-32bytes!!"
DIGESTS = {character: f"sha256:{character * 64}" for character in "0123456789abcdef"}
ISSUED_AT = "2026-09-01T00:00:00+00:00"
EXPIRES_AT = "2026-09-14T00:00:00+00:00"

PRODUCT_SCHEMAS = {
    "activation_ack_v1.schema.json": ActivationAckV1,
    "approval_release_directive_v2.schema.json": ApprovalReleaseDirectiveV2,
    "product_activation_bundle_v1.schema.json": ProductActivationBundleV1,
    "residual_risk_acceptance_v1.schema.json": ResidualRiskAcceptanceV1,
    "rollout_admission_record_v1.schema.json": RolloutAdmissionRecordV1,
    "runtime_activation_entry_v1.schema.json": RuntimeActivationEntryV1,
    "runtime_capability_report_v2.schema.json": RuntimeCapabilityReportV2,
}


def _load_schema(filename: str) -> dict[str, Any]:
    return json.loads((ROOT / "schemas" / filename).read_text(encoding="utf-8"))


def _schema_accepts(filename: str, payload: dict[str, Any]) -> bool:
    return Draft202012Validator(_load_schema(filename)).is_valid(payload)


def _event_capabilities(runtime: str) -> list[RuntimeEventCapabilityV2]:
    enforcement = {
        "context_assembled": "pre_execution_c1",
        "memory_write_proposed": (
            "pre_execution_c3" if runtime == "langgraph" else "pre_execution_c1"
        ),
        "message_send_proposed": (
            "pre_execution_c3" if runtime == "langgraph" else "pre_execution_c1"
        ),
        "model_input_prepared": "pre_execution_c1",
        "model_output_produced": "post_execution_isolation",
        "tool_call_proposed": (
            "pre_execution_c3" if runtime == "langgraph" else "pre_execution_c1"
        ),
        "tool_result_produced": "post_execution_isolation",
    }
    return [
        RuntimeEventCapabilityV2(
            event_type=event_type,
            supported=True,
            active=True,
            enforcement=enforcement[event_type],  # type: ignore[arg-type]
            residual_boundaries=(
                list(openclaw_event_residual_boundaries(event_type))
                if runtime == "openclaw"
                else []
            ),
        )
        for event_type in PRODUCT_EVENT_TYPES
    ]


def _capability(runtime: str) -> RuntimeCapabilityReportV2:
    openclaw = runtime == "openclaw"
    return build_runtime_capability_report(
        runtime=runtime,
        agent_id="main",
        runtime_binding_id=f"binding:{runtime}:main",
        profile_id=(
            "agentguard-openclaw-v2-restricted"
            if openclaw
            else "agentguard-langgraph-v2"
        ),
        supported=True,
        active=True,
        c0_registration=True,
        c1_pre_execution_interception=True,
        c2_correlation=True,
        c3_atomic_replace_and_seal=not openclaw,
        c4_outcome_receipts=True,
        events=_event_capabilities(runtime),
        residual_boundaries=list(OPENCLAW_RESIDUAL_BOUNDARIES) if openclaw else [],
    )


def _activation() -> tuple[
    ProductActivationBundleV1,
    RuntimeCapabilityReportV2,
    RuntimeCapabilityReportV2,
]:
    risk = build_residual_risk_acceptance(
        server_secret=SECRET,
        runtime_version="2026.7.1-2",
        plugin_version="0.1.0-rc.1",
        reviewer_id="reviewer:p0",
        candidate_artifact_digest=DIGESTS["1"],
        profile_id="agentguard-openclaw-v2-restricted",
        profile_digest=DIGESTS["f"],
        agent_id="main",
        runtime_binding_id="binding:openclaw:main",
        host_inventory_digest=DIGESTS["2"],
        plugin_inventory_digest=DIGESTS["3"],
        plugin_order_inventory_digest=DIGESTS["8"],
        tool_inventory_digest=DIGESTS["4"],
        canary_cohort="p0-openclaw",
        environment="internal_rc_canary",
        residual_boundaries=list(OPENCLAW_RESIDUAL_BOUNDARIES),
        issued_at=ISSUED_AT,
        expires_at=EXPIRES_AT,
        signer_key_id="p0-key",
    )
    admission = build_rollout_admission_record(
        server_secret=SECRET,
        candidate_artifact_manifest_digest=DIGESTS["1"],
        source_revision="1234567890abcdef",
        policy_digest=DIGESTS["5"],
        dataset_digest=DIGESTS["6"],
        contract_digest=DIGESTS["7"],
        langgraph_conformance_digest=DIGESTS["8"],
        openclaw_conformance_digest=DIGESTS["9"],
        capability_matrix_digest=DIGESTS["a"],
        tool_inventory_digest=DIGESTS["4"],
        issued_at=ISSUED_AT,
        expires_at=EXPIRES_AT,
        signer_key_id="p0-key",
    )
    langgraph_capability = _capability("langgraph")
    openclaw_capability = _capability("openclaw")
    langgraph = RuntimeActivationEntryV1(
        runtime="langgraph",
        runtime_version="1.2.7",
        plugin_version="0.1.0rc1",
        profile_id="agentguard-langgraph-v2",
        profile_digest=DIGESTS["b"],
        principal_id="principal:lg",
        agent_id="main",
        runtime_binding_id="binding:langgraph:main",
        event_types=list(PRODUCT_EVENT_TYPES),
        adapter_artifact_digest=DIGESTS["c"],
        capability_report_digest=langgraph_capability.report_digest,
        host_inventory_digest=DIGESTS["d"],
        tool_inventory_digest=DIGESTS["e"],
        ask_release_mode="strong_binding",
        residual_boundaries=[],
        canary_cohort="p0-langgraph",
        expires_at=EXPIRES_AT,
    )
    openclaw = RuntimeActivationEntryV1(
        runtime="openclaw",
        runtime_version="2026.7.1-2",
        plugin_version="0.1.0-rc.1",
        profile_id="agentguard-openclaw-v2-restricted",
        profile_digest=DIGESTS["f"],
        principal_id="principal:oc",
        agent_id="main",
        runtime_binding_id="binding:openclaw:main",
        event_types=list(PRODUCT_EVENT_TYPES),
        adapter_artifact_digest=DIGESTS["0"],
        capability_report_digest=openclaw_capability.report_digest,
        host_inventory_digest=DIGESTS["2"],
        plugin_inventory_digest=DIGESTS["3"],
        plugin_order_inventory_digest=DIGESTS["8"],
        tool_inventory_digest=DIGESTS["4"],
        ask_release_mode="restricted_allow_once",
        residual_risk_acceptance_digest=risk.acceptance_ref_digest,
        residual_boundaries=list(OPENCLAW_RESIDUAL_BOUNDARIES),
        canary_cohort="p0-openclaw",
        expires_at=EXPIRES_AT,
    )
    bundle = build_product_activation_bundle(
        server_secret=SECRET,
        rollout_admission_record=admission,
        residual_risk_acceptance=risk,
        candidate_artifact_manifest_digest=DIGESTS["1"],
        rollout_admission_digest=admission.admission_ref_digest,
        policy_digest=DIGESTS["5"],
        dataset_digest=DIGESTS["6"],
        contract_digest=DIGESTS["7"],
        runtimes=[langgraph, openclaw],
        issued_at=ISSUED_AT,
        expires_at=EXPIRES_AT,
        signer_key_id="p0-key",
    )
    return bundle, langgraph_capability, openclaw_capability


def test_signed_activation_is_dual_runtime_and_tamper_evident() -> None:
    bundle, langgraph, openclaw = _activation()

    assert list(PRODUCT_EVENT_TYPES) == [
        "context_assembled",
        "memory_write_proposed",
        "message_send_proposed",
        "model_input_prepared",
        "model_output_produced",
        "tool_call_proposed",
        "tool_result_produced",
    ]
    assert verify_rollout_admission_record(
        bundle.rollout_admission_record, server_secret=SECRET
    )
    assert verify_residual_risk_acceptance(
        bundle.residual_risk_acceptance, server_secret=SECRET
    )
    assert verify_product_activation_bundle(bundle, server_secret=SECRET)
    assert langgraph.c3_atomic_replace_and_seal is True
    assert openclaw.c3_atomic_replace_and_seal is False
    assert bundle.runtime_entry("openclaw").residual_boundaries == list(
        OPENCLAW_RESIDUAL_BOUNDARIES
    )

    tampered = bundle.model_copy(update={"server_signature": f"hmac-sha256:{'0' * 64}"})
    assert not verify_product_activation_bundle(tampered, server_secret=SECRET)

    report = openclaw.model_dump(mode="json")
    report["c3_atomic_replace_and_seal"] = True
    with pytest.raises(ValidationError, match="must not claim C3"):
        RuntimeCapabilityReportV2.model_validate(report)

    invalid_window = bundle.model_dump(mode="json")
    invalid_window["runtimes"][0]["expires_at"] = ISSUED_AT
    with pytest.raises(ValidationError, match="expire after bundle issuance"):
        ProductActivationBundleV1.model_validate(invalid_window)


def test_release_directive_keeps_legacy_openclaw_readers_fail_closed() -> None:
    bundle, langgraph, openclaw = _activation()
    openclaw_directive = build_approval_release_directive(
        runtime="openclaw",
        decision="ask",
        reviewable=True,
        activation_ref_digest=bundle.activation_ref_digest,
        scope_digest=DIGESTS["a"],
        capability_digest=openclaw.report_digest,
        residual_boundaries=list(OPENCLAW_RESIDUAL_BOUNDARIES),
    )
    langgraph_directive = build_approval_release_directive(
        runtime="langgraph",
        decision="ask",
        reviewable=True,
        activation_ref_digest=bundle.activation_ref_digest,
        scope_digest=DIGESTS["b"],
        capability_digest=langgraph.report_digest,
    )

    assert openclaw_directive.mode == "restricted_allow_once"
    assert openclaw_directive.required_runtime_profile == "C1"
    assert openclaw_directive.action_binding == "best_effort_host"
    assert legacy_approval_release_projection(openclaw_directive) == "forbidden"
    assert langgraph_directive.mode == "strong_binding"
    assert langgraph_directive.required_runtime_profile == "C3"
    assert langgraph_directive.action_binding == "exact"
    assert legacy_approval_release_projection(langgraph_directive) == (
        "strong_binding_required"
    )


@pytest.mark.parametrize(
    "boundaries",
    [
        [],
        [OPENCLAW_RESIDUAL_BOUNDARIES[0]],
        list(reversed(OPENCLAW_RESIDUAL_BOUNDARIES)),
        [*OPENCLAW_RESIDUAL_BOUNDARIES, OPENCLAW_RESIDUAL_BOUNDARIES[-1]],
        ["openclaw_invented_boundary"],
    ],
)
def test_restricted_release_requires_exact_frozen_boundaries(
    boundaries: list[str],
) -> None:
    bundle, _, openclaw = _activation()

    with pytest.raises(ValidationError):
        build_approval_release_directive(
            runtime="openclaw",
            decision="ask",
            reviewable=True,
            activation_ref_digest=bundle.activation_ref_digest,
            scope_digest=DIGESTS["a"],
            capability_digest=openclaw.report_digest,
            residual_boundaries=boundaries,
        )


def test_release_builder_rejects_unknown_runtime() -> None:
    bundle, _, openclaw = _activation()

    with pytest.raises(ValueError, match="unsupported product runtime"):
        build_approval_release_directive(
            runtime=cast(Any, "invented-runtime"),
            decision="ask",
            reviewable=True,
            activation_ref_digest=bundle.activation_ref_digest,
            scope_digest=DIGESTS["a"],
            capability_digest=openclaw.report_digest,
            residual_boundaries=list(OPENCLAW_RESIDUAL_BOUNDARIES),
        )


def test_selector_rejects_unknown_event_before_using_authority_inputs() -> None:
    unknown = cast(Any, "invented_event")

    with pytest.raises(
        V21AuthoritySelectionError,
        match="v21-product:unsupported_event_type",
    ):
        select_product_v21_authority(
            event_id="event:unused",
            current_decision=cast(Any, None),
            raw_v21_decision=cast(Any, None),
            assessment=cast(Any, None),
            coverage=cast(Any, None),
            activation=cast(Any, None),
            runtime_entry=cast(Any, None),
            eligibility=cast(Any, None),
            snapshot_id="snapshot:unused",
            state_version=0,
            scope_digest=DIGESTS["0"],
            event_type=unknown,
        )


def test_activation_ack_is_short_lived_and_binds_inventory() -> None:
    bundle, _, openclaw = _activation()
    entry = bundle.runtime_entry("openclaw")
    issued = datetime(2026, 9, 1, tzinfo=timezone.utc)
    ack = build_activation_ack(
        server_secret=SECRET,
        runtime="openclaw",
        runtime_version=entry.runtime_version,
        plugin_version=entry.plugin_version,
        agent_id=entry.agent_id,
        runtime_binding_id=entry.runtime_binding_id,
        profile_id=entry.profile_id,
        activation_ref_digest=bundle.activation_ref_digest,
        capability_digest=openclaw.report_digest,
        host_inventory_digest=entry.host_inventory_digest,
        plugin_inventory_digest=entry.plugin_inventory_digest,
        plugin_order_inventory_digest=entry.plugin_order_inventory_digest,
        tool_inventory_digest=entry.tool_inventory_digest,
        issued_at=issued.isoformat(),
        expires_at=(issued + timedelta(seconds=120)).isoformat(),
    )

    assert verify_activation_ack(
        ack, server_secret=SECRET, now=issued + timedelta(seconds=1)
    )
    assert not verify_activation_ack(
        ack, server_secret=SECRET, now=issued + timedelta(seconds=120)
    )
    tampered = ActivationAckV1.model_construct(
        **{
            **ack.model_dump(mode="json"),
            "plugin_order_inventory_digest": DIGESTS["9"],
        }
    )
    assert not verify_activation_ack(
        tampered, server_secret=SECRET, now=issued + timedelta(seconds=1)
    )
    with pytest.raises(ValidationError, match="requires profile_id"):
        build_activation_ack(
            server_secret=SECRET,
            runtime="openclaw",
            runtime_version=entry.runtime_version,
            plugin_version=entry.plugin_version,
            agent_id=entry.agent_id,
            runtime_binding_id=entry.runtime_binding_id,
            profile_id="wrong-profile",
            activation_ref_digest=bundle.activation_ref_digest,
            capability_digest=openclaw.report_digest,
            host_inventory_digest=entry.host_inventory_digest,
            plugin_inventory_digest=entry.plugin_inventory_digest,
            plugin_order_inventory_digest=entry.plugin_order_inventory_digest,
            tool_inventory_digest=entry.tool_inventory_digest,
            issued_at=issued.isoformat(),
            expires_at=(issued + timedelta(seconds=120)).isoformat(),
        )


def test_python_and_node_share_frozen_p0_activation_projection_vectors() -> None:
    fixture = json.loads(
        (ROOT / "tests/fixtures/product_activation_v2_golden.json").read_text(
            encoding="utf-8"
        )
    )
    key = fixture["test_hmac_key_utf8"].encode("utf-8")
    bundle, _, openclaw = _activation()

    assert fixture["scope"] == "p0_activation_projections_only"
    assert canonical_json_bytes(fixture["canonical_value"]).decode("utf-8") == (
        fixture["canonical_value_json"]
    )
    assert (
        canonical_sha256(fixture["canonical_value"])
        == fixture["canonical_value_digest"]
    )
    assert (
        canonical_hmac_sha256(key, fixture["canonical_value"])
        == fixture["canonical_value_hmac"]
    )
    assert openclaw.digest_projection() == fixture["openclaw_capability_projection"]
    assert openclaw.report_digest == fixture["openclaw_capability_digest"]

    risk = bundle.residual_risk_acceptance
    assert risk.acceptance_ref_digest == fixture["residual_risk_ref_digest"]
    assert (
        canonical_hmac_sha256(key, fixture["residual_risk_signature_payload"])
        == fixture["residual_risk_signature"]
    )
    assert risk.server_signature == fixture["residual_risk_signature"]

    ack_payload = fixture["activation_ack_signature_payload"]["ack"]
    ack = build_activation_ack(
        server_secret=key,
        **{
            field: value
            for field, value in ack_payload.items()
            if field != "schema_version"
        },
    )
    assert ack.token_projection() == ack_payload
    assert ack.ack_token == fixture["activation_ack_token"]


def test_json_schemas_fail_closed_on_runtime_specific_semantics() -> None:
    bundle, langgraph, openclaw = _activation()
    capability_schema = "runtime_capability_report_v2.schema.json"
    directive_schema = "approval_release_directive_v2.schema.json"
    entry_schema = "runtime_activation_entry_v1.schema.json"
    risk_schema = "residual_risk_acceptance_v1.schema.json"

    openclaw_report = openclaw.model_dump(mode="json")
    langgraph_report = langgraph.model_dump(mode="json")
    assert _schema_accepts(capability_schema, openclaw_report)
    assert _schema_accepts(capability_schema, langgraph_report)

    for mutation in (
        {"c3_atomic_replace_and_seal": True},
        {"supported": False},
        {"events": []},
        {
            "events": [
                *openclaw_report["events"][:5],
                {
                    **openclaw_report["events"][5],
                    "enforcement": "pre_execution_c3",
                },
                openclaw_report["events"][6],
            ]
        },
    ):
        assert not _schema_accepts(capability_schema, {**openclaw_report, **mutation})
    assert not _schema_accepts(
        capability_schema,
        {**langgraph_report, "c3_atomic_replace_and_seal": False},
    )

    openclaw_directive = build_approval_release_directive(
        runtime="openclaw",
        decision="ask",
        reviewable=True,
        activation_ref_digest=bundle.activation_ref_digest,
        scope_digest=DIGESTS["a"],
        capability_digest=openclaw.report_digest,
        residual_boundaries=list(OPENCLAW_RESIDUAL_BOUNDARIES),
    ).model_dump(mode="json")
    assert _schema_accepts(directive_schema, openclaw_directive)
    assert not _schema_accepts(
        directive_schema,
        {
            **openclaw_directive,
            "residual_boundaries": [OPENCLAW_RESIDUAL_BOUNDARIES[0]],
        },
    )
    assert not _schema_accepts(
        directive_schema,
        {**openclaw_directive, "required_runtime_profile": "C3"},
    )

    langgraph_entry = bundle.runtime_entry("langgraph").model_dump(mode="json")
    openclaw_entry = bundle.runtime_entry("openclaw").model_dump(mode="json")
    assert _schema_accepts(entry_schema, langgraph_entry)
    assert _schema_accepts(entry_schema, openclaw_entry)
    assert not _schema_accepts(
        entry_schema, {**openclaw_entry, "ask_release_mode": "strong_binding"}
    )
    assert not _schema_accepts(
        entry_schema, {**langgraph_entry, "ask_release_mode": "restricted_allow_once"}
    )
    assert not _schema_accepts(
        entry_schema, {**openclaw_entry, "plugin_inventory_digest": None}
    )

    risk = bundle.residual_risk_acceptance.model_dump(mode="json")
    assert _schema_accepts(risk_schema, risk)
    assert not _schema_accepts(
        risk_schema,
        {**risk, "residual_boundaries": [OPENCLAW_RESIDUAL_BOUNDARIES[0]]},
    )
    assert not _schema_accepts(
        "product_activation_bundle_v1.schema.json",
        {
            **bundle.model_dump(mode="json"),
            "runtimes": list(reversed(bundle.model_dump(mode="json")["runtimes"])),
        },
    )


@pytest.mark.parametrize(("filename", "model"), PRODUCT_SCHEMAS.items())
def test_product_json_schema_matches_pydantic_model(filename: str, model: type) -> None:
    schema = _load_schema(filename)
    Draft202012Validator.check_schema(schema)
    assert len(schema.get("properties", {})) >= 10
    generated = model.model_json_schema(mode="validation")
    generated["$schema"] = "https://json-schema.org/draft/2020-12/schema"
    generated["$id"] = f"https://agentguard.dev/schemas/{filename}"
    assert schema == generated
