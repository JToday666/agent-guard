"""Strict offline Product admission documents; no runtime authority is issued here."""

from __future__ import annotations

from pathlib import PurePosixPath
from typing import Annotated, Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator
from agentguard_core.actions.canonical_json import canonical_sha256

Digest = Annotated[str, Field(pattern=r"^sha256:[0-9a-f]{64}$")]
Revision = Annotated[str, Field(pattern=r"^[0-9a-f]{40}$")]
Identifier = Annotated[str, Field(min_length=1, max_length=256)]
Runtime = Literal["langgraph", "openclaw"]
PolicyGroup = Literal["allow", "ask", "deny"]


class AdmissionError(ValueError):
    """Fixed public failure; never embed document contents, tokens or secrets."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)


class EvidenceRef(StrictModel):
    path: str = Field(min_length=1, max_length=1024)
    size: int = Field(ge=0)
    raw_sha256: Digest

    @field_validator("path")
    @classmethod
    def canonical_relative_path(cls, value: str) -> str:
        path = PurePosixPath(value)
        if (
            path.is_absolute()
            or str(path) != value
            or any(part in {".", ".."} for part in path.parts)
            or "\\" in value
            or any(ord(char) < 32 for char in value)
        ):
            raise ValueError("evidence_path_invalid")
        return value


class PolicyReference(StrictModel):
    id: PolicyGroup
    policy_bundle: EvidenceRef


class RuntimeIdentity(StrictModel):
    runtime: Runtime
    principal_id: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
    agent_id: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
    runtime_binding_id: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,255}$")
    canary_cohort: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")


class SigningRequest(StrictModel):
    schema_version: Literal["agentguard-product-signing-request/1"]
    source_revision: Revision
    candidate_manifest: EvidenceRef
    langgraph_conformance: EvidenceRef
    openclaw_conformance: EvidenceRef
    capability_matrix: EvidenceRef
    tool_catalog: EvidenceRef
    dataset_manifest: EvidenceRef
    contract_manifest: EvidenceRef
    review_record: EvidenceRef
    policy_groups: list[PolicyReference] = Field(min_length=3, max_length=3)
    runtime_identities: list[RuntimeIdentity] = Field(min_length=2, max_length=2)
    issued_at: str
    expires_at: str
    signer_key_id: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,63}$")


class ReviewRecord(StrictModel):
    schema_version: Literal["agentguard-product-signing-review/1"]
    source_revision: Revision
    candidate_manifest_digest: Digest
    reviewer_id: Identifier
    reviewer_kind: Literal["ai_reviewer", "human_reviewer"]
    review_completed: Literal[True]
    authorization_source: str = Field(min_length=1, max_length=1024)
    authorization_text: str = Field(min_length=1, max_length=8192)
    policy_groups: list[PolicyGroup] = Field(min_length=3, max_length=3)
    runtimes: list[Runtime] = Field(min_length=2, max_length=2)
    scope: Literal["fixed_isolated_profiles"]
    production_acceptance_claimed: Literal[False]
    long_term_validation_claimed: Literal[False]


class ReportMaterials(StrictModel):
    installation: EvidenceRef
    baseline_inventory: EvidenceRef
    product_inventory: EvidenceRef
    observed_capability: EvidenceRef
    activation_target_capability: EvidenceRef
    hook_order: EvidenceRef
    tool_catalog: EvidenceRef


class CaseResult(StrictModel):
    id: Identifier
    status: Literal["PASS", "FAIL", "SKIP", "INCOMPLETE"]
    evidence_kind: Literal["native_baseline", "deterministic_contract"]
    model_kind: Literal["controlled_local", "none"]
    authority_kind: Literal["none", "synthetic_contract_fixture"]
    execution_scope: Literal["native_baseline", "isolated_contract_fixture"]
    scope_id: Identifier
    policy_group: PolicyGroup | None
    policy_digest: Digest | None
    invocation_count: int = Field(ge=0, le=64)
    effects: list[Digest] = Field(max_length=64)
    receipt_disposition: Literal[
        "not_applicable", "confirmed", "rejected_retained", "unknown_retained"
    ]
    hashed_evidence: list[EvidenceRef] = Field(min_length=1, max_length=32)


class ReportPolicy(StrictModel):
    id: PolicyGroup
    policy_digest: Digest


class ReportTotals(StrictModel):
    required: int = Field(ge=1)
    passed: int = Field(ge=0)
    failed: int = Field(ge=0)
    skipped: int = Field(ge=0)


class ConformanceReport(StrictModel):
    schema_version: Literal["agentguard-product-conformance/1"]
    phase: Literal["pre_activation"]
    runtime: Runtime
    source_revision: Revision
    candidate_manifest_digest: Digest
    requirements_version: str
    requirements_digest: Digest
    runtime_version: str
    adapter_version: str
    adapter_artifact_digest: Digest
    product_active_enabled: Literal[False]
    external_provider_requests: Literal[0]
    complete: Literal[True]
    exit_code: Literal[0]
    formal_scope_id: Identifier
    materials: ReportMaterials
    policies: list[ReportPolicy] = Field(min_length=3, max_length=3)
    cases: list[CaseResult] = Field(min_length=1, max_length=128)
    totals: ReportTotals


class TraceFrame(StrictModel):
    """An observed event. Case validators consume facts, not a PASS assertion."""

    sequence: int = Field(ge=0)
    actor: Literal["host", "model", "http", "journal", "consumer", "effect", "postgres"]
    event: str = Field(min_length=1, max_length=128)
    data: dict[str, Any]
    attachments: list[EvidenceRef] = Field(max_length=16)


class Observation(StrictModel):
    schema_version: Literal["agentguard-product-case-observation/1"]
    runtime: Runtime
    source_revision: Revision
    candidate_manifest_digest: Digest
    adapter_artifact_digest: Digest
    case_id: Identifier
    scope_id: Identifier
    process_id: int = Field(ge=1)
    consumer_module: str = Field(min_length=1, max_length=256)
    consumer_file: EvidenceRef
    entrypoint: str = Field(min_length=1, max_length=256)
    authority_kind: Literal["none", "synthetic_contract_fixture"]
    frames: list[TraceFrame] = Field(min_length=1, max_length=4096)


def read_model(model: type[StrictModel], value: Any) -> Any:
    """Reject normalization/default filling as well as unknown/coerced fields."""
    try:
        result = model.model_validate(value)
        if canonical_sha256(result.model_dump(mode="json")) != canonical_sha256(value):
            raise ValueError
        return result
    except Exception:
        raise AdmissionError("admission_document_invalid") from None
