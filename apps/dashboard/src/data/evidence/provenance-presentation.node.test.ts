import assert from "node:assert/strict";
import test from "node:test";

import type {
  NormalizedAuditEvidence,
  ProvenanceGraph,
  ProvenanceNode,
} from "../../types/dashboard.ts";
import { projectCtPresentation } from "./provenance-presentation.ts";

const digest = `sha256:${"a".repeat(64)}`;
const traceId = "trace-s2-typed";
const auditId = "audit-s2-typed";
const eventId = "event-s2-typed";
const sourceRef = "source:web:event-s2-typed:0";
const contextRef = "context:event-s2-typed";

function evidenceRef() {
  return {
    ref_id: `ct-envelope:${auditId}`,
    kind: "audit_event",
    record_type: "policy_evaluation",
    record_id: auditId,
    json_pointer: "/evidence/ct_transient_facts",
    digest,
    redaction_state: "summary_only",
  };
}

function event(envelope: unknown): NormalizedAuditEvidence {
  return {
    auditId,
    eventId,
    source: { type: "web_fetch", label: null, trustLevel: "untrusted" },
    raw: { evidence: { ct_transient_facts: envelope } },
  } as NormalizedAuditEvidence;
}

function fullEnvelope() {
  return {
    schema_version: "1.1",
    payload: {
      fact_builder_version: "ct-fact-2",
      commit_id: `ct-commit:${eventId}`,
      bundle_digest: digest,
      overlay_digest: digest,
      projection_id: "projection:s2",
      projection_eligible: true,
      source_identity: {
        source_record_type: "runtime_observation",
        source_record_id: `ct-facts:${eventId}`,
        source_revision: 1,
      },
      bundle: {
        event_id: eventId,
        bundle_digest: digest,
        overlay_digest: digest,
        source_facts: [
          {
            source_id: sourceRef,
            source_type: "web",
            trust: "untrusted",
            taints: ["UNTRUSTED", "EXTERNAL_INSTRUCTION"],
          },
        ],
      },
    },
  };
}

function node(
  nodeId: string,
  kind: "source" | "context",
  refId: string,
  extra: Record<string, unknown>,
): ProvenanceNode {
  return {
    nodeId,
    traceId,
    kind,
    refId,
    label: kind,
    timestamp: "2026-08-16T00:00:00Z",
    metadata: {
      contract: "ct-provenance/1.0",
      kind: "node",
      node_kind: kind,
      node_ref: { ref_type: kind, ref_id: refId },
      taints: kind === "source" ? ["UNTRUSTED", "EXTERNAL_INSTRUCTION"] : [],
      coverage: "complete",
      evidence_refs: [evidenceRef()],
      ...extra,
    },
  };
}

function graph(): ProvenanceGraph {
  return {
    traceId,
    nodes: [
      node("ctnode:source", "source", sourceRef, {
        source_type: "web",
        trust: "untrusted",
        verification_state: "verified",
        fact_authority: "untrusted_claim",
      }),
      node("ctnode:context", "context", contextRef, {
        scope_digest: digest,
        manifest_event_id: null,
      }),
    ],
    edges: [
      {
        edgeId: "ctedge:assembled",
        traceId,
        sourceNodeId: "ctnode:source",
        targetNodeId: "ctnode:context",
        relation: "assembled_into",
        timestamp: "2026-08-16T00:00:00Z",
        metadata: {
          contract: "ct-provenance/1.0",
          kind: "edge",
          flow_id: "flow:assembled",
          flow_relation: "assembled_into",
          source_ref: sourceRef,
          target_ref: contextRef,
          flow_strength: "exact",
          flow_origin: "observed",
          coverage: "complete",
          evidence_refs: [evidenceRef()],
        },
      },
    ],
    window: {
      nodeLimit: 1000,
      returnedNodeCount: 2,
      nodesHaveMore: false,
      edgeLimit: 2000,
      returnedEdgeCount: 1,
      edgesHaveMore: false,
      hasMore: false,
    },
  };
}

test("projects only fully validated typed Source/Flow metadata", () => {
  const result = projectCtPresentation({
    traceId,
    elementSourceMode: "live",
    events: [event(fullEnvelope())],
    provenance: graph(),
  });
  assert.equal(result.presentation.contractKind, "ct-provenance/1.0");
  assert.equal(result.provenanceAvailability, "recorded");
  assert.equal(result.presentation.edges[0]?.certainty, "confirmed");
  assert.equal(result.presentation.edges[0]?.ctFlowRelation, "assembled_into");
  assert.deepEqual(result.contentByEventId.get(eventId), {
    availability: "recorded",
    stableSourceRefs: [sourceRef],
    rawSourceTypes: ["web_fetch"],
    normalizedCtSourceTypes: ["web"],
    ctNormalizationAvailability: "recorded",
    trustLabels: ["untrusted"],
    taints: ["EXTERNAL_INSTRUCTION", "UNTRUSTED"],
    provenanceNodeIds: ["ctnode:source"],
  });
});

test("invalid typed metadata stays legacy and cannot drive certainty", () => {
  const invalid = graph();
  invalid.edges[0]!.metadata.source_ref = "source:forged";
  const result = projectCtPresentation({
    traceId,
    elementSourceMode: "live",
    events: [event(fullEnvelope())],
    provenance: invalid,
  });
  assert.equal(result.presentation.contractKind, "mixed");
  assert.equal(result.presentation.edges[0]?.ctFlowRelation, null);
  assert.equal(result.presentation.edges[0]?.certainty, "unknown");
  assert.equal(result.provenanceAvailability, "partial");
});

test("BudgetDroppedRef is partial rather than an empty recorded fact set", () => {
  const result = projectCtPresentation({
    traceId,
    elementSourceMode: "live",
    events: [event({ _budget_dropped: true, _envelope_sha256: `sha256:${"b".repeat(64)}` })],
    provenance: null,
  });
  assert.equal(result.factAvailability, "partial");
  assert.equal(result.contentByEventId.get(eventId)?.availability, "partial");
});
