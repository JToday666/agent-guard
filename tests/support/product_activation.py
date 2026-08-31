"""Reusable, dynamically time-valid Product V2 activation test fixtures."""

from __future__ import annotations

import base64
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path

from agentguard_core import (
    OPENCLAW_RESIDUAL_BOUNDARIES,
    ProductActivationBundleV1,
    RuntimeActivationEntryV1,
    RuntimeCapabilityReportV2,
    RuntimeEventCapabilityV2,
    build_product_activation_bundle,
    build_residual_risk_acceptance,
    build_rollout_admission_record,
    build_runtime_capability_report,
    openclaw_event_residual_boundaries,
)
from agentguard_core.decisions.product import PRODUCT_EVENT_TYPES

from guard_api.runtime_status import ProductRuntimeStatusV2

TEST_PRODUCT_ACTIVATION_SECRET = b"product-activation-test-secret-material-01"
TEST_PRODUCT_ACTIVATION_SECRET_B64 = base64.urlsafe_b64encode(
    TEST_PRODUCT_ACTIVATION_SECRET
).decode("ascii")
TEST_PRODUCT_ACTIVATION_SIGNER = "product-test-key"

_DIGESTS = {character: f"sha256:{character * 64}" for character in "0123456789abcdef"}


@dataclass(frozen=True, slots=True)
class ProductActivationFixture:
    bundle: ProductActivationBundleV1
    langgraph_capability: RuntimeCapabilityReportV2
    openclaw_capability: RuntimeCapabilityReportV2
    server_secret: bytes
    signer_key_id: str

    def capability(self, runtime: str) -> RuntimeCapabilityReportV2:
        if runtime == "langgraph":
            return self.langgraph_capability
        if runtime == "openclaw":
            return self.openclaw_capability
        raise KeyError(runtime)


def _utc(value: datetime | None) -> datetime:
    current = value or datetime.now(timezone.utc)
    if current.tzinfo is None or current.utcoffset() is None:
        raise ValueError("fixture clock must be timezone-aware")
    return current.astimezone(timezone.utc)


def build_test_runtime_capability(
    runtime: str,
    *,
    supported: bool = True,
    active: bool = True,
) -> RuntimeCapabilityReportV2:
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
    events = [
        RuntimeEventCapabilityV2(
            event_type=event_type,
            supported=True,
            active=active,
            enforcement=enforcement[event_type],  # type: ignore[arg-type]
            residual_boundaries=(
                list(openclaw_event_residual_boundaries(event_type))
                if runtime == "openclaw"
                else []
            ),
        )
        for event_type in PRODUCT_EVENT_TYPES
    ]
    return build_runtime_capability_report(
        runtime=runtime,
        agent_id="main",
        runtime_binding_id=f"binding:{runtime}:main",
        profile_id=(
            "agentguard-openclaw-v2-restricted"
            if runtime == "openclaw"
            else "agentguard-langgraph-v2"
        ),
        supported=supported,
        active=active,
        c0_registration=True,
        c1_pre_execution_interception=True,
        c2_correlation=True,
        c3_atomic_replace_and_seal=runtime == "langgraph",
        c4_outcome_receipts=True,
        events=events,
        residual_boundaries=(
            list(OPENCLAW_RESIDUAL_BOUNDARIES) if runtime == "openclaw" else []
        ),
    )


def build_test_product_activation(
    *,
    now: datetime | None = None,
    server_secret: bytes = TEST_PRODUCT_ACTIVATION_SECRET,
    signer_key_id: str = TEST_PRODUCT_ACTIVATION_SIGNER,
    admission_signer_key_id: str | None = None,
    risk_signer_key_id: str | None = None,
    policy_digest: str | None = None,
) -> ProductActivationFixture:
    """Build a bundle valid from one minute ago through the next day."""

    current = _utc(now).replace(microsecond=0)
    proof_issued = current - timedelta(minutes=2)
    bundle_issued = current - timedelta(minutes=1)
    expires = current + timedelta(days=1)
    proof_issued_at = proof_issued.isoformat()
    bundle_issued_at = bundle_issued.isoformat()
    expires_at = expires.isoformat()
    admission_signer = admission_signer_key_id or signer_key_id
    risk_signer = risk_signer_key_id or signer_key_id
    admitted_policy_digest = policy_digest or _DIGESTS["5"]

    risk = build_residual_risk_acceptance(
        server_secret=server_secret,
        runtime_version="2026.7.1-2",
        plugin_version="0.1.0-rc.1",
        reviewer_id="reviewer:p0-test",
        candidate_artifact_digest=_DIGESTS["1"],
        profile_id="agentguard-openclaw-v2-restricted",
        profile_digest=_DIGESTS["f"],
        agent_id="main",
        runtime_binding_id="binding:openclaw:main",
        host_inventory_digest=_DIGESTS["2"],
        plugin_inventory_digest=_DIGESTS["3"],
        plugin_order_inventory_digest=_DIGESTS["8"],
        tool_inventory_digest=_DIGESTS["4"],
        canary_cohort="p0-openclaw",
        environment="internal_rc_canary",
        residual_boundaries=list(OPENCLAW_RESIDUAL_BOUNDARIES),
        issued_at=proof_issued_at,
        expires_at=expires_at,
        signer_key_id=risk_signer,
    )
    admission = build_rollout_admission_record(
        server_secret=server_secret,
        candidate_artifact_manifest_digest=_DIGESTS["1"],
        source_revision="1234567890abcdef",
        policy_digest=admitted_policy_digest,
        dataset_digest=_DIGESTS["6"],
        contract_digest=_DIGESTS["7"],
        langgraph_conformance_digest=_DIGESTS["8"],
        openclaw_conformance_digest=_DIGESTS["9"],
        capability_matrix_digest=_DIGESTS["a"],
        tool_inventory_digest=_DIGESTS["4"],
        issued_at=proof_issued_at,
        expires_at=expires_at,
        signer_key_id=admission_signer,
    )
    langgraph_capability = build_test_runtime_capability("langgraph")
    openclaw_capability = build_test_runtime_capability("openclaw")
    runtimes = [
        RuntimeActivationEntryV1(
            runtime="langgraph",
            runtime_version="1.2.7",
            plugin_version="0.1.0rc1",
            profile_id="agentguard-langgraph-v2",
            profile_digest=_DIGESTS["b"],
            principal_id="principal:lg",
            agent_id="main",
            runtime_binding_id="binding:langgraph:main",
            event_types=list(PRODUCT_EVENT_TYPES),
            adapter_artifact_digest=_DIGESTS["c"],
            capability_report_digest=langgraph_capability.report_digest,
            host_inventory_digest=_DIGESTS["d"],
            tool_inventory_digest=_DIGESTS["e"],
            ask_release_mode="strong_binding",
            residual_boundaries=[],
            canary_cohort="p0-langgraph",
            expires_at=expires_at,
        ),
        RuntimeActivationEntryV1(
            runtime="openclaw",
            runtime_version="2026.7.1-2",
            plugin_version="0.1.0-rc.1",
            profile_id="agentguard-openclaw-v2-restricted",
            profile_digest=_DIGESTS["f"],
            principal_id="principal:oc",
            agent_id="main",
            runtime_binding_id="binding:openclaw:main",
            event_types=list(PRODUCT_EVENT_TYPES),
            adapter_artifact_digest=_DIGESTS["0"],
            capability_report_digest=openclaw_capability.report_digest,
            host_inventory_digest=_DIGESTS["2"],
            plugin_inventory_digest=_DIGESTS["3"],
            plugin_order_inventory_digest=_DIGESTS["8"],
            tool_inventory_digest=_DIGESTS["4"],
            ask_release_mode="restricted_allow_once",
            residual_risk_acceptance_digest=risk.acceptance_ref_digest,
            residual_boundaries=list(OPENCLAW_RESIDUAL_BOUNDARIES),
            canary_cohort="p0-openclaw",
            expires_at=expires_at,
        ),
    ]
    bundle = build_product_activation_bundle(
        server_secret=server_secret,
        rollout_admission_record=admission,
        residual_risk_acceptance=risk,
        candidate_artifact_manifest_digest=_DIGESTS["1"],
        rollout_admission_digest=admission.admission_ref_digest,
        policy_digest=admitted_policy_digest,
        dataset_digest=_DIGESTS["6"],
        contract_digest=_DIGESTS["7"],
        runtimes=runtimes,
        issued_at=bundle_issued_at,
        expires_at=expires_at,
        signer_key_id=signer_key_id,
    )
    return ProductActivationFixture(
        bundle=bundle,
        langgraph_capability=langgraph_capability,
        openclaw_capability=openclaw_capability,
        server_secret=server_secret,
        signer_key_id=signer_key_id,
    )


def product_runtime_status_for_activation(
    fixture: ProductActivationFixture,
    runtime: str,
    *,
    last_heartbeat_at: datetime | None = None,
) -> ProductRuntimeStatusV2:
    entry = fixture.bundle.runtime_entry(runtime)  # type: ignore[arg-type]
    return ProductRuntimeStatusV2(
        schema_version="2.0",
        runtime=entry.runtime,
        principal_id=entry.principal_id,
        status="loaded",
        loaded=True,
        runtime_id=f"{runtime}-test-host",
        agent_id=entry.agent_id,
        runtime_binding_id=entry.runtime_binding_id,
        profile_id=entry.profile_id,
        runtime_version=entry.runtime_version,
        plugin_version=entry.plugin_version,
        profile_digest=entry.profile_digest,
        adapter_artifact_digest=entry.adapter_artifact_digest,
        reported_activation_ref_digest=fixture.bundle.activation_ref_digest,
        host_inventory_digest=entry.host_inventory_digest,
        plugin_inventory_digest=entry.plugin_inventory_digest,
        plugin_order_inventory_digest=entry.plugin_order_inventory_digest,
        tool_inventory_digest=entry.tool_inventory_digest,
        capability_report=fixture.capability(runtime),
        source="product-activation-test",
        hooks=[],
        fail_closed_stages=[],
        enforcement_mode="enforce",
        last_heartbeat_at=_utc(last_heartbeat_at).isoformat(),
    )


def write_test_product_activation(
    path: Path,
    fixture: ProductActivationFixture,
) -> Path:
    path.write_text(fixture.bundle.model_dump_json(), encoding="utf-8")
    path.chmod(0o400)
    return path


__all__ = [
    "ProductActivationFixture",
    "TEST_PRODUCT_ACTIVATION_SECRET",
    "TEST_PRODUCT_ACTIVATION_SECRET_B64",
    "TEST_PRODUCT_ACTIVATION_SIGNER",
    "build_test_product_activation",
    "build_test_runtime_capability",
    "product_runtime_status_for_activation",
    "write_test_product_activation",
]
