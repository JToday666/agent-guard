"""Write-time materialization of deterministic, browser-safe provenance facts."""

from __future__ import annotations

import hashlib
import json
import re
import unicodedata
from collections.abc import Iterable
from typing import Any

from agentguard_core import (
    ActionCriticReview,
    AuditEvent,
    ProvenanceEdge,
    ProvenanceNode,
)

from guard_api.models import ApprovalRequest
from guard_api.storage.base import ControlPlaneStore, ProvenanceConflictError

from .redaction import (
    REDACTED,
    SUMMARY_TEXT_LIMIT,
    bound_redacted_value,
    scrub_text,
    truncate_text,
)

UnknownRecord = dict[str, Any]
_SAFE_ID_COMPONENT = re.compile(r"^[A-Za-z0-9._-]{1,160}$")
_USER_SOURCE_TYPES = frozenset({"human", "operator", "user", "user_request"})


class ProvenanceWriter:
    """Persist only facts present in a newly written audit lifecycle record."""

    def __init__(self, *, store: ControlPlaneStore) -> None:
        self.store = store

    def record_audit_event(
        self,
        event: AuditEvent,
        *,
        approval: ApprovalRequest | None = None,
        critic_review: ActionCriticReview | None = None,
    ) -> None:
        audit_node = self._audit_node(event)
        self._add_node(audit_node)

        if event.record_type == "policy_evaluation":
            self._record_policy_evaluation(
                event,
                audit_node,
                approval=approval,
                critic_review=critic_review,
            )
            return
        if event.record_type == "runtime_outcome":
            self._record_runtime_outcome(event, audit_node)
            return
        if event.record_type == "config_audit":
            self._record_config_audit(event, audit_node)
            return
        if event.record_type == "runtime_observation":
            return
        self._record_legacy_event(event, audit_node)

    def update_approval(self, approval: ApprovalRequest) -> None:
        """Update an already materialized approval without creating orphan facts."""

        decision_id = _approval_decision_id(approval)
        approval_node_id = f"approval:{approval.approval_id}"
        decision_node_id = f"decision:{decision_id}" if decision_id else None
        approval_node = self.store.get_provenance_node(approval_node_id)
        decision_node = (
            self.store.get_provenance_node(decision_node_id)
            if decision_node_id is not None
            else None
        )
        for node in (approval_node, decision_node):
            if node is not None and node.trace_id != approval.trace_id:
                raise ProvenanceConflictError(node.node_id)
        if approval_node is None and decision_node is None:
            return
        self._record_approval(approval, decision_id=decision_id)

    def _record_policy_evaluation(
        self,
        event: AuditEvent,
        audit_node: ProvenanceNode,
        *,
        approval: ApprovalRequest | None,
        critic_review: ActionCriticReview | None,
    ) -> None:
        evidence = _record(event.evidence)
        guard_event = _record(evidence.get("guard_event"))
        guard_decision = _record(evidence.get("guard_decision"))
        event_id = _first_string(
            event.links.get("event_id"), guard_event.get("event_id")
        )
        decision_id = _first_string(
            event.links.get("decision_id"), guard_decision.get("decision_id")
        )

        task_node = self._task_node(event, guard_event)
        if task_node is not None:
            self._add_node(task_node)

        primary_source = _record(guard_event.get("source"))
        source_nodes: list[ProvenanceNode] = []
        primary_source_node = self._source_node(event, primary_source)
        if primary_source_node is not None:
            self._add_node(primary_source_node)
            source_nodes.append(primary_source_node)
            source_type = _first_string(
                primary_source.get("type"), primary_source.get("source_type")
            )
            if (
                task_node is not None
                and source_type is not None
                and source_type.lower() in _USER_SOURCE_TYPES
            ):
                self._add_edge(
                    event.trace_id,
                    primary_source_node.node_id,
                    task_node.node_id,
                    "received_from",
                    "causal",
                    event.timestamp,
                )

        context_sources = [
            item
            for item in _array(guard_event.get("context_sources"))
            if isinstance(item, dict)
        ]
        context_source_nodes: list[ProvenanceNode] = []
        for item in context_sources:
            source_node = self._source_node(event, item)
            if source_node is None:
                continue
            existing = next(
                (
                    candidate
                    for candidate in source_nodes
                    if candidate.node_id == source_node.node_id
                ),
                None,
            )
            if existing is None:
                self._add_node(source_node)
                source_nodes.append(source_node)
                existing = source_node
            if not any(
                candidate.node_id == existing.node_id
                for candidate in context_source_nodes
            ):
                context_source_nodes.append(existing)

        context_node: ProvenanceNode | None = None
        if event_id is not None and (
            context_sources or event.event_type == "context_assembled"
        ):
            context_node = ProvenanceNode(
                node_id=f"context:{event_id}",
                trace_id=event.trace_id,
                kind="context",
                ref_id=event_id,
                label="assembled context",
                timestamp=event.timestamp,
                metadata={
                    "phase": "context_intent",
                    "source_count": len(context_sources),
                },
            )
            self._add_node(context_node)
            for source_node in context_source_nodes:
                self._add_edge(
                    event.trace_id,
                    source_node.node_id,
                    context_node.node_id,
                    "assembled_into",
                    "causal",
                    event.timestamp,
                )
            if task_node is not None:
                self._add_edge(
                    event.trace_id,
                    task_node.node_id,
                    context_node.node_id,
                    "influenced",
                    "causal",
                    event.timestamp,
                )

        model_intent_node: ProvenanceNode | None = None
        model_intent = _first_string(guard_event.get("model_intent"))
        if event_id is not None and model_intent is not None:
            model_intent_node = ProvenanceNode(
                node_id=f"model_intent:{event_id}",
                trace_id=event.trace_id,
                kind="model_intent",
                ref_id=event_id,
                label=model_intent,
                timestamp=event.timestamp,
                metadata={"phase": "context_intent"},
            )
            self._add_node(model_intent_node)
            if context_node is not None:
                self._add_edge(
                    event.trace_id,
                    context_node.node_id,
                    model_intent_node.node_id,
                    "influenced",
                    "causal",
                    event.timestamp,
                )

        action_node = self._action_node(event, guard_event)
        if action_node is not None:
            self._add_node(action_node)
            if model_intent_node is not None:
                self._add_edge(
                    event.trace_id,
                    model_intent_node.node_id,
                    action_node.node_id,
                    "proposed_action",
                    "causal",
                    event.timestamp,
                )

        resource_nodes = self._resource_nodes(event, guard_event)
        for resource_node in resource_nodes:
            self._add_node(resource_node)
            if action_node is not None:
                self._add_edge(
                    event.trace_id,
                    action_node.node_id,
                    resource_node.node_id,
                    "targets",
                    "causal",
                    event.timestamp,
                )

        rule_nodes = self._rule_nodes(event, guard_decision, decision_id=decision_id)
        for rule_node, rule_evidence in rule_nodes:
            self._add_node(rule_node)
            for resource_node in resource_nodes:
                target = _first_string(resource_node.metadata.get("target_summary"))
                if target and _rule_evidence_references_target(rule_evidence, target):
                    self._add_edge(
                        event.trace_id,
                        resource_node.node_id,
                        rule_node.node_id,
                        "detected_by",
                        "detection",
                        event.timestamp,
                    )

        decision_node = self._decision_node(
            event, guard_decision, decision_id=decision_id
        )
        if decision_node is None:
            return
        self._add_node(decision_node)
        evaluation_subject = self._evaluation_subject_node(
            event,
            event_id=event_id,
            action_node=action_node,
            context_node=context_node,
            model_intent_node=model_intent_node,
        )
        if evaluation_subject is not None:
            if evaluation_subject.node_id not in {
                node.node_id
                for node in (action_node, context_node, model_intent_node)
                if node is not None
            }:
                self._add_node(evaluation_subject)
            self._add_edge(
                event.trace_id,
                evaluation_subject.node_id,
                decision_node.node_id,
                "evaluated_to",
                "policy",
                event.timestamp,
            )

        policy_node = self._policy_node(event, evidence)
        if policy_node is not None:
            self._add_node(policy_node)
            self._add_edge(
                event.trace_id,
                decision_node.node_id,
                policy_node.node_id,
                "evaluated_under",
                "policy",
                event.timestamp,
            )

        if approval is None:
            approval_id = event.links.get("approval_id")
            approval = self.store.get_approval(approval_id) if approval_id else None
        if approval is not None:
            _validate_approval_link(
                approval,
                trace_id=event.trace_id,
                action_id=action_node.ref_id if action_node is not None else None,
                decision_id=decision_node.ref_id,
            )
            self._record_approval(approval, decision_id=decision_node.ref_id)

        if critic_review is not None:
            if critic_review.trace_id != event.trace_id or (
                event_id is not None and critic_review.event_id != event_id
            ):
                raise ProvenanceConflictError(f"review:{critic_review.review_id}")
            review_node = ProvenanceNode(
                node_id=f"review:{critic_review.review_id}",
                trace_id=event.trace_id,
                kind="review",
                ref_id=critic_review.review_id,
                label=critic_review.verdict,
                timestamp=critic_review.created_at,
                metadata={
                    "reviewer": critic_review.reviewer,
                    "verdict": critic_review.verdict,
                    "confidence": critic_review.confidence,
                    "degraded": critic_review.degraded,
                    "phase": "tool_policy",
                },
            )
            self._add_node(review_node)
            self._add_edge(
                event.trace_id,
                decision_node.node_id,
                review_node.node_id,
                "reviewed_by",
                "detection",
                critic_review.created_at,
            )

        self._add_edge(
            event.trace_id,
            decision_node.node_id,
            audit_node.node_id,
            "recorded_as",
            "audit",
            event.timestamp,
        )

    def _record_runtime_outcome(
        self, event: AuditEvent, audit_node: ProvenanceNode
    ) -> None:
        evidence = _record(event.evidence)
        execution = _record(evidence.get("execution"))
        intervention = _record(evidence.get("intervention"))
        result = _record(evidence.get("result"))
        side_effects = _record(evidence.get("side_effects"))
        result_node = ProvenanceNode(
            node_id=f"runtime_result:{event.audit_id}",
            trace_id=event.trace_id,
            kind="runtime_result",
            ref_id=event.audit_id,
            label=_first_string(execution.get("status"), event.event_type)
            or "runtime result",
            timestamp=event.timestamp,
            metadata={
                "phase": "outcome_audit",
                "execution_status": execution.get("status"),
                "intervention_type": intervention.get("type"),
                "result_disposition": result.get("disposition"),
                "result_summary": result.get("summary"),
                "side_effect_measurement": side_effects.get("measurement_status"),
                "side_effect_count": side_effects.get("count"),
            },
        )
        self._add_node(result_node)

        approval_id = event.links.get("approval_id")
        if approval_id:
            approval = self.store.get_approval(approval_id)
            if approval is not None:
                _validate_approval_link(
                    approval,
                    trace_id=event.trace_id,
                    action_id=event.links.get("action_id"),
                    decision_id=event.links.get("decision_id"),
                )
                self._record_approval(
                    approval, decision_id=event.links.get("decision_id")
                )
            self._add_edge(
                event.trace_id,
                f"approval:{approval_id}",
                result_node.node_id,
                "released_by",
                "approval",
                event.timestamp,
            )
        decision_id = event.links.get("decision_id")
        if decision_id:
            self._add_edge(
                event.trace_id,
                f"decision:{decision_id}",
                result_node.node_id,
                "executed_as",
                "execution",
                event.timestamp,
            )
        action_id = event.links.get("action_id")
        if action_id:
            self._add_edge(
                event.trace_id,
                f"action:{action_id}",
                result_node.node_id,
                "produced",
                "execution",
                event.timestamp,
            )
        self._add_edge(
            event.trace_id,
            result_node.node_id,
            audit_node.node_id,
            "recorded_as",
            "audit",
            event.timestamp,
        )

    def _record_config_audit(
        self, event: AuditEvent, audit_node: ProvenanceNode
    ) -> None:
        config_event_id = event.links.get("config_audit_event_id")
        if not config_event_id:
            return
        config_node = ProvenanceNode(
            node_id=f"config_audit:{config_event_id}",
            trace_id=event.trace_id,
            kind="config_audit",
            ref_id=config_event_id,
            label=event.summary,
            timestamp=event.timestamp,
            metadata={
                "phase": "outcome_audit",
                "target_type": event.metadata.get("target_type"),
                "finding_count": event.metadata.get("finding_count"),
                "severity": event.severity,
            },
        )
        self._add_node(config_node)
        self._add_edge(
            event.trace_id,
            config_node.node_id,
            audit_node.node_id,
            "recorded_as",
            "audit",
            event.timestamp,
        )

    def _record_legacy_event(
        self, event: AuditEvent, audit_node: ProvenanceNode
    ) -> None:
        source_id = event.links.get("config_audit_event_id") or event.links.get(
            "event_id"
        )
        if source_id is None:
            return
        source_kind = "config_audit" if event.event_type == "config_audit" else "event"
        source_node = ProvenanceNode(
            node_id=f"{source_kind}:{source_id}",
            trace_id=event.trace_id,
            kind=source_kind,
            ref_id=source_id,
            label=event.event_type,
            timestamp=event.timestamp,
            metadata={"runtime": event.runtime, "stage": event.stage},
        )
        self._add_node(source_node)
        self._add_edge(
            event.trace_id,
            source_node.node_id,
            audit_node.node_id,
            "recorded_as",
            "audit",
            event.timestamp,
        )

    def _record_approval(
        self, approval: ApprovalRequest, *, decision_id: str | None
    ) -> ProvenanceNode:
        label = (
            approval.decision
            if approval.status == "resolved" and approval.decision
            else approval.status
        )
        node = ProvenanceNode(
            node_id=f"approval:{approval.approval_id}",
            trace_id=approval.trace_id,
            kind="approval",
            ref_id=approval.approval_id,
            label=label,
            timestamp=approval.created_at,
            metadata={
                "phase": "outcome_audit",
                "status": approval.status,
                "decision": approval.decision,
                "created_at": approval.created_at,
                "expires_at": approval.expires_at,
                "resolved_at": approval.resolved_at,
                "resolution_source": approval.resolution_source,
                "resolved_by": approval.resolved_by,
                "resolution_reason": approval.resolution_reason,
            },
        )
        stored = self._add_node(node)
        if decision_id:
            self._add_edge(
                approval.trace_id,
                f"decision:{decision_id}",
                stored.node_id,
                "requested_approval",
                "approval",
                approval.created_at,
            )
        return stored

    def _audit_node(self, event: AuditEvent) -> ProvenanceNode:
        event_payload = event.model_dump(mode="json")
        integrity = _record(event_payload.get("integrity"))
        phase = "input_trust" if event.stage == "trace_started" else "outcome_audit"
        return ProvenanceNode(
            node_id=f"audit:{event.audit_id}",
            trace_id=event.trace_id,
            kind="audit",
            ref_id=event.audit_id,
            label=event.summary or event.event_type,
            timestamp=event.timestamp,
            metadata={
                "phase": phase,
                "record_type": event.record_type or "legacy",
                "runtime": event.runtime,
                "stage": event.stage,
                "event_type": event.event_type,
                "integrity_sequence": integrity.get("sequence"),
            },
        )

    def _task_node(
        self, event: AuditEvent, guard_event: UnknownRecord
    ) -> ProvenanceNode | None:
        task = _first_string(guard_event.get("user_task"))
        if task is None:
            return None
        return ProvenanceNode(
            node_id=f"task:{event.trace_id}",
            trace_id=event.trace_id,
            kind="task",
            ref_id=event.trace_id,
            label=task,
            timestamp=event.timestamp,
            metadata={"phase": "input_trust", "summary": task},
        )

    def _source_node(
        self, event: AuditEvent, source: UnknownRecord
    ) -> ProvenanceNode | None:
        source_type = _first_string(source.get("type"), source.get("source_type"))
        source_trust = _first_string(
            source.get("trust_level"), source.get("source_trust"), source.get("trust")
        )
        if source_type is None or source_trust is None:
            return None
        source_id = _first_string(source.get("source_id"), source.get("id"))
        component, ref_id = _stable_source_reference(
            source_id,
            {
                "source_type": source_type,
                "source_trust": source_trust,
                "summary": _first_string(source.get("summary"), source.get("label")),
            },
        )
        label = _first_string(source.get("label"), source.get("summary"), source_type)
        if label is None:
            return None
        return ProvenanceNode(
            node_id=f"source:{event.trace_id}:{component}",
            trace_id=event.trace_id,
            kind="source",
            ref_id=ref_id,
            label=label,
            timestamp=event.timestamp,
            metadata={
                "phase": "input_trust",
                "source_type": source_type,
                "source_trust": source_trust,
            },
        )

    def _action_node(
        self,
        event: AuditEvent,
        guard_event: UnknownRecord,
    ) -> ProvenanceNode | None:
        action_id = event.links.get("action_id")
        if not action_id:
            return None
        tool = _record(guard_event.get("tool"))
        tool_call_id = _first_string(tool.get("call_id"))
        if tool_call_id is not None and tool_call_id != action_id:
            raise ProvenanceConflictError(f"action:{action_id}:tool.call_id")
        action_name = _first_string(
            tool.get("name"), event.metadata.get("action_name"), event.event_type
        )
        if action_name is None:
            return None
        return ProvenanceNode(
            node_id=f"action:{action_id}",
            trace_id=event.trace_id,
            kind="action",
            ref_id=action_id,
            label=action_name,
            timestamp=event.timestamp,
            metadata={
                "phase": "tool_policy",
                "action_name": action_name,
                "action_category": tool.get("category"),
            },
        )

    def _evaluation_subject_node(
        self,
        event: AuditEvent,
        *,
        event_id: str | None,
        action_node: ProvenanceNode | None,
        context_node: ProvenanceNode | None,
        model_intent_node: ProvenanceNode | None,
    ) -> ProvenanceNode | None:
        if action_node is not None:
            return action_node
        if event.event_type == "context_assembled" and context_node is not None:
            return context_node
        if model_intent_node is not None:
            return model_intent_node
        if context_node is not None:
            return context_node
        if event_id is None:
            return None
        return ProvenanceNode(
            node_id=f"event:{event_id}",
            trace_id=event.trace_id,
            kind="event",
            ref_id=event_id,
            label=event.event_type,
            timestamp=event.timestamp,
            metadata={
                "phase": _event_phase(event.event_type),
                "event_type": event.event_type,
            },
        )

    def _resource_nodes(
        self, event: AuditEvent, guard_event: UnknownRecord
    ) -> list[ProvenanceNode]:
        nodes: list[ProvenanceNode] = []
        for item in _array(guard_event.get("normalized_resources")):
            resource = _record(item)
            resource_type = _first_string(
                resource.get("resource_type"), resource.get("type")
            )
            operation = _first_string(resource.get("operation"))
            target = _first_string(resource.get("target"), resource.get("value"))
            direction = _first_string(resource.get("direction"))
            if (
                resource_type is None
                or operation is None
                or target is None
                or direction is None
            ):
                continue
            canonical = {
                "resource_type": resource_type,
                "operation": operation,
                "target": target,
                "direction": direction,
            }
            digest = _canonical_digest(canonical)
            nodes.append(
                ProvenanceNode(
                    node_id=f"resource:{event.trace_id}:sha256:{digest}",
                    trace_id=event.trace_id,
                    kind="resource",
                    ref_id=f"sha256:{digest}",
                    label=target,
                    timestamp=event.timestamp,
                    metadata={
                        "phase": "tool_policy",
                        "resource_type": resource_type,
                        "operation": operation,
                        "direction": direction,
                        "target_summary": target,
                        "sensitivity": resource.get("sensitivity"),
                    },
                )
            )
        return _unique_nodes(nodes)

    def _rule_nodes(
        self,
        event: AuditEvent,
        guard_decision: UnknownRecord,
        *,
        decision_id: str | None,
    ) -> list[tuple[ProvenanceNode, list[str]]]:
        if decision_id is None:
            return []
        detailed = _array(guard_decision.get("rule_hits"))
        rows: list[UnknownRecord]
        if detailed:
            rows = [_record(item) for item in detailed]
        else:
            rows = [{"rule_id": rule_id} for rule_id in event.rule_hits]
        nodes: list[tuple[ProvenanceNode, list[str]]] = []
        for row in rows:
            rule_id = _first_string(row.get("rule_id"), row.get("id"))
            if rule_id is None:
                continue
            evidence = [
                value
                for value in (
                    _first_string(item) for item in _array(row.get("evidence"))
                )
                if value is not None
            ]
            nodes.append(
                (
                    ProvenanceNode(
                        node_id=f"rule:{decision_id}:{rule_id}",
                        trace_id=event.trace_id,
                        kind="rule",
                        ref_id=rule_id,
                        label=_first_string(
                            row.get("rule_name"), row.get("name"), rule_id
                        )
                        or rule_id,
                        timestamp=event.timestamp,
                        metadata={
                            "phase": "tool_policy",
                            "decision_id": decision_id,
                            "severity": row.get("severity"),
                            "reason_summary": row.get("reason"),
                        },
                    ),
                    evidence,
                )
            )
        return nodes

    def _decision_node(
        self,
        event: AuditEvent,
        guard_decision: UnknownRecord,
        *,
        decision_id: str | None,
    ) -> ProvenanceNode | None:
        if decision_id is None:
            return None
        decision = _first_string(guard_decision.get("decision"), event.decision)
        if decision is None:
            return None
        return ProvenanceNode(
            node_id=f"decision:{decision_id}",
            trace_id=event.trace_id,
            kind="decision",
            ref_id=decision_id,
            label=decision,
            timestamp=event.timestamp,
            metadata={
                "phase": "tool_policy",
                "decision": decision,
                "risk_score": guard_decision.get("risk_score", event.risk_score),
                "severity": guard_decision.get("severity", event.severity),
                "reason_summary": guard_decision.get("reason", event.reason),
            },
        )

    def _policy_node(
        self, event: AuditEvent, evidence: UnknownRecord
    ) -> ProvenanceNode | None:
        policy = _record(evidence.get("policy"))
        bundle_id = _first_string(policy.get("bundle_id"))
        version = _first_string(policy.get("version"))
        revision = policy.get("revision")
        revision_ref = str(revision) if isinstance(revision, int) else version
        if bundle_id is None or revision_ref is None:
            return None
        ref_id = f"{bundle_id}:{revision_ref}"
        return ProvenanceNode(
            node_id=f"policy:{event.trace_id}:{ref_id}",
            trace_id=event.trace_id,
            kind="policy",
            ref_id=ref_id,
            label=f"{bundle_id} {revision_ref}",
            timestamp=event.timestamp,
            metadata={
                "phase": "tool_policy",
                "bundle_id": bundle_id,
                "version": version,
                "revision": revision if isinstance(revision, int) else None,
                "canonical_digest": policy.get("canonical_digest")
                or policy.get("digest"),
                "canonicalization": policy.get("canonicalization"),
            },
        )

    def _add_node(self, node: ProvenanceNode) -> ProvenanceNode:
        safe_metadata = bound_redacted_value(node.metadata)
        safe_node = node.model_copy(
            update={
                "label": truncate_text(scrub_text(node.label), SUMMARY_TEXT_LIMIT),
                "metadata": safe_metadata if isinstance(safe_metadata, dict) else {},
            }
        )
        return self.store.add_provenance_node(safe_node)

    def _add_edge(
        self,
        trace_id: str,
        source_node_id: str,
        target_node_id: str,
        relation: str,
        relation_type: str,
        timestamp: str,
    ) -> None:
        source = self.store.get_provenance_node(source_node_id)
        target = self.store.get_provenance_node(target_node_id)
        if (
            source is None
            or target is None
            or source.trace_id != trace_id
            or target.trace_id != trace_id
        ):
            return
        self.store.add_provenance_edge(
            ProvenanceEdge(
                edge_id=f"edge:{relation}:{source_node_id}:{target_node_id}",
                trace_id=trace_id,
                source_node_id=source_node_id,
                target_node_id=target_node_id,
                relation=relation,
                timestamp=timestamp,
                metadata={"relation_type": relation_type},
            )
        )


def _record(value: object) -> UnknownRecord:
    return value if isinstance(value, dict) else {}


def _event_phase(event_type: str) -> str:
    if event_type in {"context_assembled", "model_input_prepared"}:
        return "context_intent"
    if event_type == "model_output_produced":
        return "outcome_audit"
    return "tool_policy"


def _array(value: object) -> list[object]:
    return value if isinstance(value, list) else []


def _first_string(*values: object) -> str | None:
    for value in values:
        if isinstance(value, str) and value.strip():
            return value.strip()
    return None


def _canonical_digest(value: object) -> str:
    normalized = _normalize_unicode(value)
    encoded = json.dumps(
        normalized, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _normalize_unicode(value: object) -> object:
    if isinstance(value, str):
        return unicodedata.normalize("NFC", value)
    if isinstance(value, dict):
        return {str(key): _normalize_unicode(nested) for key, nested in value.items()}
    if isinstance(value, list):
        return [_normalize_unicode(item) for item in value]
    return value


def _stable_source_reference(
    source_id: str | None, fallback: UnknownRecord
) -> tuple[str, str]:
    if (
        source_id is not None
        and _SAFE_ID_COMPONENT.fullmatch(source_id)
        and scrub_text(source_id) == source_id
        and REDACTED not in source_id
    ):
        return source_id, source_id
    digest = _canonical_digest({"source_id": source_id, **fallback})
    return f"sha256:{digest}", f"sha256:{digest}"


def _rule_evidence_references_target(evidence: Iterable[str], target: str) -> bool:
    if target == REDACTED:
        return False
    markers = {
        target,
        f"resource={target}",
        f"resource_target={target}",
        f"target={target}",
    }
    return any(item in markers for item in evidence)


def _approval_decision_id(approval: ApprovalRequest) -> str | None:
    decision = _record(approval.evidence.get("decision"))
    return _first_string(decision.get("decision_id"))


def _validate_approval_link(
    approval: ApprovalRequest,
    *,
    trace_id: str,
    action_id: str | None,
    decision_id: str | None,
) -> None:
    if approval.trace_id != trace_id:
        raise ProvenanceConflictError(f"approval:{approval.approval_id}:trace_id")
    if action_id is not None and approval.action_id != action_id:
        raise ProvenanceConflictError(f"approval:{approval.approval_id}:action_id")
    approval_decision_id = _approval_decision_id(approval)
    if (
        decision_id is not None
        and approval_decision_id is not None
        and approval_decision_id != decision_id
    ):
        raise ProvenanceConflictError(f"approval:{approval.approval_id}:decision_id")


def _unique_nodes(nodes: Iterable[ProvenanceNode]) -> list[ProvenanceNode]:
    unique: dict[str, ProvenanceNode] = {}
    for node in nodes:
        unique.setdefault(node.node_id, node)
    return list(unique.values())
