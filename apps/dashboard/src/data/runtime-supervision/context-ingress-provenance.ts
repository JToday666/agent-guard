import type { ProvenanceEdge, ProvenanceGraph, ProvenanceNode } from "../../types/dashboard.ts";
import type { Availability } from "../../types/runtime-supervision.ts";
import type { LoadedRuntimeSupervisionFixture } from "./runtime-supervision-fixture.ts";

export const MOCK_CONTEXT_INGRESS_DEMO_TRACE_ID = "trace_005" as const;

export type LoadedContextIngressPreviewFixture = Extract<
  LoadedRuntimeSupervisionFixture,
  { readonly fixtureKind: "context_ingress_preview" }
>;

type LoadedProvenanceNode =
  LoadedContextIngressPreviewFixture["provenancePresentation"]["nodes"][number];
type LoadedProvenanceEdge =
  LoadedContextIngressPreviewFixture["provenancePresentation"]["edges"][number];

function phaseFor(nodeKind: LoadedProvenanceNode["nodeKind"]): string {
  if (nodeKind === "source") return "input_trust";
  if (nodeKind === "context" || nodeKind === "model_input" || nodeKind === "memory") {
    return "context_intent";
  }
  return "tool_policy";
}

function graphKind(nodeKind: LoadedProvenanceNode["nodeKind"]): string {
  // The legacy graph calls this lane `model_intent`. Preserve the frozen
  // contract kind separately in metadata so the Preview remains typed.
  return nodeKind === "model_input" ? "model_intent" : nodeKind;
}

function nodeLabel(node: LoadedProvenanceNode): string {
  if (node.nodeKind === "source") return "Web 内容来源";
  if (node.nodeKind === "context") return "上下文拼接";
  if (node.nodeKind === "model_input") return "模型输入";
  if (node.nodeKind === "memory") return "记忆内容";
  if (node.nodeKind === "action") return "高影响动作";
  return "内容流节点";
}

function nodeSpecificMetadata(node: LoadedProvenanceNode): Record<string, unknown> {
  if (node.nodeKind === "source") {
    return {
      ct_normalization_availability: node.ctNormalizationAvailability,
      normalized_ct_source_type: node.normalizedCtSourceType,
      raw_source_type: node.rawSourceType,
      trust: node.trust,
      verification_state: node.verificationState,
    };
  }
  if (node.nodeKind === "context") {
    return {
      manifest_event_id: node.manifestEventId,
      scope_digest: node.scopeDigest,
    };
  }
  if (node.nodeKind === "model_input") {
    return {
      context_ref: node.contextRef,
      event_id: node.eventId,
      model_call_ref: node.modelCallRef,
    };
  }
  if (node.nodeKind === "memory") {
    return {
      memory_ref: node.memoryRef,
      memory_trust: node.trust,
    };
  }
  if (node.nodeKind === "action") return { action_id: node.actionId };
  return {};
}

function edgeAvailability(coverage: LoadedProvenanceEdge["coverage"]): Availability {
  if (coverage === "complete") return "recorded";
  if (coverage === "partial" || coverage === "stale") return "partial";
  if (coverage === "not_applicable") return "not_applicable";
  return "unavailable";
}

function rewriteSourceRefs(
  sourceRefs: readonly { readonly kind: string; readonly id: string }[],
  traceId: string,
): Array<{ kind: string; id: string; trace_id: string }> {
  return sourceRefs.map((sourceRef) => ({
    id: sourceRef.id,
    kind: sourceRef.kind,
    trace_id: traceId,
  }));
}

function mapNode(
  node: LoadedProvenanceNode,
  fixture: LoadedContextIngressPreviewFixture,
  traceId: string,
  timestamp: string,
): ProvenanceNode {
  return {
    kind: graphKind(node.nodeKind),
    label: nodeLabel(node),
    metadata: {
      ...nodeSpecificMetadata(node),
      availability: node.semantics.availability,
      certainty: node.semantics.certainty,
      critical: true,
      decision_authority: node.semantics.decisionAuthority,
      derived_for_display: node.semantics.derivedForDisplay,
      display_mode: node.displayMode,
      element_source_mode: node.semantics.elementSourceMode,
      fact_authority: node.semantics.factAuthority,
      fixture_id: fixture.metadata.fixtureId,
      fixture_schema_version: fixture.metadata.fixtureSchemaVersion,
      phase: phaseFor(node.nodeKind),
      presentation_node_kind: node.nodeKind,
      source_mode: fixture.metadata.sourceMode,
      source_refs: rewriteSourceRefs(node.semantics.sourceRefs, traceId),
      status: "MOCK PREVIEW",
      summary: node.safeExcerpt,
      taints: [...node.taints],
    },
    nodeId: node.provenanceNodeId,
    refId: node.refId,
    timestamp,
    traceId,
  };
}

function mapEdge(
  edge: LoadedProvenanceEdge,
  fixture: LoadedContextIngressPreviewFixture,
  traceId: string,
  timestamp: string,
): ProvenanceEdge {
  return {
    edgeId: edge.edgeId,
    metadata: {
      availability: edgeAvailability(edge.coverage),
      certainty: edge.certainty,
      coverage: edge.coverage,
      ct_flow_relation: edge.ctFlowRelation,
      fixture_id: fixture.metadata.fixtureId,
      flow_origin: edge.flowOrigin,
      flow_strength: edge.flowStrength,
      legacy_relation_type: edge.legacyRelationType,
      relation_type: "ct_flow",
      source_mode: fixture.metadata.sourceMode,
      source_refs: rewriteSourceRefs(edge.sourceRefs, traceId),
      wire_relation: edge.wireRelation,
    },
    relation: edge.wireRelation,
    sourceNodeId: edge.sourceNodeId,
    targetNodeId: edge.targetNodeId,
    timestamp,
    traceId,
  };
}

/**
 * Adds synthetic content ingress only to the mock Preview provenance graph.
 * The fixture explicitly carries no execution-graph edges, and this mapper
 * accepts/returns ProvenanceGraph so it cannot modify the execution projection.
 */
export function mergeMockContextIngressProvenance(
  baseGraph: ProvenanceGraph,
  fixture: LoadedContextIngressPreviewFixture,
  timestamp: string,
): ProvenanceGraph {
  if (baseGraph.traceId !== MOCK_CONTEXT_INGRESS_DEMO_TRACE_ID) return baseGraph;
  if (fixture.executionGraphEdges.length !== 0) {
    throw new Error("Mock context ingress fixture must not contain execution graph edges");
  }

  const nodes = fixture.provenancePresentation.nodes.map((node) =>
    mapNode(node, fixture, baseGraph.traceId, timestamp),
  );
  const edges = fixture.provenancePresentation.edges.map((edge) =>
    mapEdge(edge, fixture, baseGraph.traceId, timestamp),
  );
  const existingNodeIds = new Set(baseGraph.nodes.map(({ nodeId }) => nodeId));
  const existingEdgeIds = new Set(baseGraph.edges.map(({ edgeId }) => edgeId));
  if (nodes.some(({ nodeId }) => existingNodeIds.has(nodeId))) {
    throw new Error("Mock context ingress provenance node collides with base graph");
  }
  if (edges.some(({ edgeId }) => existingEdgeIds.has(edgeId))) {
    throw new Error("Mock context ingress provenance edge collides with base graph");
  }

  return {
    edges: [...baseGraph.edges, ...edges],
    nodes: [...baseGraph.nodes, ...nodes],
    traceId: baseGraph.traceId,
    window: {
      ...baseGraph.window,
      edgeLimit: Math.max(baseGraph.window.edgeLimit, baseGraph.edges.length + edges.length),
      nodeLimit: Math.max(baseGraph.window.nodeLimit, baseGraph.nodes.length + nodes.length),
      returnedEdgeCount: baseGraph.edges.length + edges.length,
      returnedNodeCount: baseGraph.nodes.length + nodes.length,
    },
  };
}
