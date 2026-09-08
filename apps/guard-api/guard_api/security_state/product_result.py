"""Bounded server evidence for a Product action's actual native result identity."""

from __future__ import annotations

from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, StringConstraints, model_validator

from agentguard_core import GuardEvent, ToolResultPayload
from agentguard_core.actions.canonical_json import canonical_sha256
from agentguard_core.signals.models import TaintLabel

_REF = Annotated[str, StringConstraints(min_length=1, max_length=512)]
_DIGEST = Annotated[str, StringConstraints(pattern=r"^sha256:[0-9a-f]{64}$")]


class ProductToolResultProof(BaseModel):
    """All fields are hashes/identities; no result, arguments or ACK token."""

    model_config = ConfigDict(extra="forbid", frozen=True, hide_input_in_errors=True)
    schema_version: Literal["1.0"] = "1.0"
    event_id: _REF
    event_digest: _DIGEST
    runtime: Literal["langgraph", "openclaw"]
    trace_id: _REF
    agent_id: _REF
    runtime_binding_id: _REF
    scope_digest: _REF
    task_id: _REF
    task_revision: int = Field(ge=0, strict=True)
    parent_event_id: _REF
    parent_policy_audit_id: _REF
    parent_action_id: _REF
    parent_terminal_audit_id: _REF
    parent_terminal_digest: _DIGEST
    model_commitment_digest: _DIGEST
    native_tool_name: _REF
    native_call_id: _REF
    result_digest: _DIGEST
    taints: tuple[TaintLabel, ...] = ()
    proof_digest: str = ""

    @model_validator(mode="after")
    def _digest(self) -> ProductToolResultProof:
        expected = canonical_sha256(
            self.model_dump(mode="json", exclude={"proof_digest"})
        )
        if self.proof_digest and self.proof_digest != expected:
            raise ValueError("product_tool_result_proof_invalid")
        object.__setattr__(self, "proof_digest", expected)
        return self

    def matches_event(self, event: GuardEvent) -> bool:
        payload = event.payload
        return bool(
            self.proof_digest
            == canonical_sha256(self.model_dump(mode="json", exclude={"proof_digest"}))
            and event.event_type == "tool_result_produced"
            and isinstance(payload, ToolResultPayload)
            and event.event_id == self.event_id
            and event.runtime == self.runtime
            and event.trace_id == self.trace_id
            and event.security_context.agent_id == self.agent_id
            and event.metadata.get("task_id") == self.task_id
            and canonical_sha256(event.model_dump(mode="json")) == self.event_digest
            and payload.tool.name == self.native_tool_name
            and payload.tool.call_id == self.native_call_id
            and canonical_sha256(payload.result.content_preview) == self.result_digest
        )
