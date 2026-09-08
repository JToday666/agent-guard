"""Server-verified Product data transport, distinct from model influence.

These immutable inputs are issued by the authenticated control-plane compiler,
never deserialized from GuardEvent metadata. They commit to evidence and scalar
copies without carrying their plaintext. A proof does not confer source trust,
capability, approval, or an execution permit.
"""

from __future__ import annotations

from typing import Annotated, Literal

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StrictBool,
    StrictInt,
    StringConstraints,
    model_validator,
)

from ..actions.canonical_json import canonical_sha256
from ..actions.models import ActionIR
from ..signals.models import TaintLabel
from .facts import FlowFact

PRODUCT_DATA_VERSION = "product-data-1"
PRODUCT_DATA_COVERAGE_VERSION = "product-data-coverage-1"

Digest = Annotated[str, StringConstraints(pattern=r"^sha256:[0-9a-f]{64}$")]
ScopeDigest = Annotated[
    str, StringConstraints(pattern=r"^(?:hmac-sha256|sha256):[0-9a-f]{64}$")
]
Reference = Annotated[
    str,
    StringConstraints(min_length=1, max_length=2048, pattern=r"^[^\x00-\x1f\x7f]+$"),
]
Pointer = Annotated[
    str,
    StringConstraints(
        min_length=1, max_length=2048, pattern=r"^(?:/(?:[^~/]|~[01])*)+$"
    ),
]


class DataContentBinding(BaseModel):
    """An observed scalar copy; exactness stops at this field boundary."""

    model_config = ConfigDict(extra="forbid", frozen=True, hide_input_in_errors=True)

    source_ref: Reference
    source_json_pointer: Pointer
    value_digest: Digest
    action_id: Reference
    argument_pointer: Pointer
    sink_role: Literal["selector", "content"]
    resource_ref: Reference | None = None


class VerifiedProductData(BaseModel):
    """Complete bounded dependency evidence issued after server verification.

    ``source_refs`` includes the actual model source and every verified ancestor;
    ``memory_refs`` contains canonical memory identities from that closure and
    any current memory resource. ``taints`` is their monotonic union. An empty
    memory set is therefore positive evidence of absence, not missing input.
    The compiler must have confirmed the original model terminal and output
    checkpoint. ``content_evidence_digest`` commits to that complete parent chain.
    """

    model_config = ConfigDict(extra="forbid", frozen=True, hide_input_in_errors=True)

    schema_version: Literal["1.0"] = "1.0"
    event_id: Reference
    action_id: Reference
    runtime: Literal["langgraph", "openclaw"]
    runtime_binding_id: Reference
    scope_digest: ScopeDigest
    task_id: Reference
    task_revision: Annotated[StrictInt, Field(ge=0)]
    tool_name: Reference
    tool_descriptor_digest: Digest
    input_schema_digest: Digest
    semantics_digest: Digest
    argument_digest: Digest
    model_source_ref: Reference
    model_output_event_id: Reference
    model_output_audit_id: Reference
    model_output_digest: Digest
    content_evidence_digest: Digest
    required_argument_pointers: Annotated[
        tuple[Pointer, ...], Field(min_length=1, max_length=256)
    ]
    bindings: Annotated[
        tuple[DataContentBinding, ...], Field(min_length=1, max_length=256)
    ]
    source_refs: Annotated[tuple[Reference, ...], Field(min_length=1, max_length=256)]
    direct_source_refs: Annotated[
        tuple[Reference, ...], Field(min_length=1, max_length=256)
    ]
    artifact_refs: Annotated[tuple[Reference, ...], Field(max_length=512)] = ()
    memory_refs: Annotated[tuple[Reference, ...], Field(max_length=256)]
    first_write_memory_ref: Reference | None = None
    taints: Annotated[tuple[TaintLabel, ...], Field(max_length=5)]
    hostile_instruction: StrictBool
    closure_complete: Literal[True]
    proof_digest: str = ""

    @model_validator(mode="after")
    def _bind(self) -> VerifiedProductData:
        if self.model_source_ref != f"source:model:{self.model_output_event_id}":
            raise ValueError("product_data_model_identity_invalid")
        for field in (
            "required_argument_pointers",
            "source_refs",
            "direct_source_refs",
            "artifact_refs",
            "memory_refs",
            "taints",
        ):
            values = getattr(self, field)
            if len(set(values)) != len(values):
                raise ValueError("product_data_duplicate_reference")
            object.__setattr__(self, field, tuple(sorted(values)))
        if (
            self.model_source_ref not in self.direct_source_refs
            or not set(self.direct_source_refs).issubset(self.source_refs)
            or any(not ref.startswith("memory://") for ref in self.memory_refs)
        ):
            raise ValueError("product_data_dependency_invalid")
        if set(self.artifact_refs).intersection((*self.source_refs, *self.memory_refs)):
            raise ValueError("product_data_artifact_identity_invalid")
        if (
            self.first_write_memory_ref is not None
            and self.first_write_memory_ref not in self.memory_refs
        ):
            raise ValueError("product_data_memory_identity_invalid")
        pointers = [binding.argument_pointer for binding in self.bindings]
        if len(set(pointers)) != len(pointers) or set(pointers) != set(
            self.required_argument_pointers
        ):
            raise ValueError("product_data_binding_coverage_invalid")
        if any(
            binding.action_id != self.action_id
            or binding.source_ref != self.model_source_ref
            for binding in self.bindings
        ):
            raise ValueError("product_data_binding_identity_invalid")
        object.__setattr__(
            self,
            "bindings",
            tuple(sorted(self.bindings, key=lambda item: item.argument_pointer)),
        )
        expected = canonical_sha256(
            {
                "version": PRODUCT_DATA_VERSION,
                **self.model_dump(mode="json", exclude={"proof_digest"}),
            }
        )
        if self.proof_digest and self.proof_digest != expected:
            raise ValueError("product_data_digest_mismatch")
        object.__setattr__(self, "proof_digest", expected)
        return self

    def integrity_valid(self) -> bool:
        """Reject unchecked model_copy/model_construct or later nested mutation."""
        try:
            return (
                type(self) is VerifiedProductData
                and VerifiedProductData.model_validate(
                    self.model_dump(mode="json")
                ).proof_digest
                == self.proof_digest
            )
        except Exception:
            return False

    def matches_action(self, action: ActionIR) -> bool:
        from ..actions.product_tools import product_tool_resource_identity

        if not self.integrity_valid():
            return False
        if any(
            getattr(self, field) != getattr(action, field)
            for field in (
                "event_id",
                "action_id",
                "runtime",
                "runtime_binding_id",
                "scope_digest",
                "task_id",
                "task_revision",
                "tool_name",
                "argument_digest",
            )
        ):
            return False
        identity = product_tool_resource_identity(
            self.tool_name, self.tool_descriptor_digest, self.semantics_digest
        )
        if not any(
            resource.kind == "tool"
            and resource.canonical_id == identity
            and resource.tool_name == self.tool_name
            and resource.tool_schema_digest == self.input_schema_digest
            and resource.provider_binding_id == self.runtime_binding_id
            for resource in action.resources
        ):
            return False
        resource_refs = {
            resource.canonical_id
            for resource in (*action.resources, *action.destinations)
        }
        if not {
            resource.canonical_id
            for resource in (*action.resources, *action.destinations)
            if resource.kind != "tool"
        }.issubset({*self.artifact_refs, *self.memory_refs}):
            return False
        if any(
            binding.resource_ref is not None
            and binding.resource_ref not in resource_refs
            for binding in self.bindings
        ):
            return False
        if not {
            resource.canonical_id
            for resource in action.resources
            if resource.kind == "memory"
        }.issubset(self.memory_refs):
            return False
        if self.first_write_memory_ref is not None and (
            action.action_type != "memory_write"
            or self.first_write_memory_ref
            not in {
                resource.canonical_id
                for resource in action.resources
                if resource.kind == "memory"
            }
            or not any(
                binding.argument_pointer == "/value"
                and binding.sink_role == "content"
                and binding.resource_ref == self.first_write_memory_ref
                for binding in self.bindings
            )
        ):
            return False
        items = action.canonical_arguments.items
        if set(self.required_argument_pointers) != {
            item.json_pointer for item in items
        }:
            return False
        values = {item.json_pointer: canonical_sha256(item.value) for item in items}
        return all(
            values[binding.argument_pointer] == binding.value_digest
            for binding in self.bindings
        )

    def covers_control_flow(self, flow: FlowFact) -> bool:
        """Only a proved model influence edge may be separated from byte flow."""
        return (
            flow.scope_digest == self.scope_digest
            and flow.relation == "influenced_by"
            and flow.strength == "possible"
            and flow.origin == "semantic_inferred"
            and flow.source_ref in self.source_refs
            and (
                flow.target_ref == f"action:{self.action_id}"
                or flow.target_ref in self.source_refs
                or flow.target_ref in self.artifact_refs
                or (
                    flow.target_ref.startswith("model_output:")
                    and f"source:model:{flow.target_ref.removeprefix('model_output:')}"
                    in self.source_refs
                )
            )
            and set(flow.taints).issubset(self.taints)
        )

    def covers_flow_endpoints(self, flow: FlowFact) -> bool:
        from ..actions.product_tools import product_tool_resource_identity

        known = {
            *self.source_refs,
            *self.artifact_refs,
            *self.memory_refs,
            *(f"memory:{ref}" for ref in self.memory_refs),
            f"action:{self.action_id}",
            f"message:{self.event_id}",
            f"model_output:{self.model_output_event_id}",
            product_tool_resource_identity(
                self.tool_name, self.tool_descriptor_digest, self.semantics_digest
            ),
        }
        return flow.source_ref in known and flow.target_ref in known

    @property
    def reviewable(self) -> bool:
        return (
            self.integrity_valid()
            and not self.hostile_instruction
            and not {
                "CREDENTIAL",
                "SENSITIVE",
                "EXTERNAL_INSTRUCTION",
                "PERSISTENT_UNTRUSTED",
            }.intersection(self.taints)
        )
