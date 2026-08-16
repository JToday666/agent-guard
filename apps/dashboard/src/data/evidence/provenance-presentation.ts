import type {
  ExecutionStepViewModel,
  NormalizedAuditEvidence,
  ProvenanceEdge,
  ProvenanceGraph,
  ProvenanceNode,
} from "../../types/dashboard.ts";
import type {
  Availability,
  ContentIngressSummary,
  CtFlowRelation,
  CtProvenanceNodeKind,
  DisplayEvidenceSemantics,
  DisplayFactAuthority,
  ElementSourceMode,
  EvidenceCertainty,
  EvidenceLocator,
  ProvenanceEdgePresentation,
  ProvenanceNodePresentation,
  ProvenancePresentationViewModel,
  SupervisionWarning,
} from "../../types/runtime-supervision.ts";

type JsonRecord = Record<string, unknown>;
type Coverage = "complete" | "partial" | "stale" | "unknown" | "not_applicable";
type CtParseKind = "absent" | "valid" | "budget_dropped" | "unsupported" | "invalid";

interface ParsedSourceFact {
  sourceId: string;
  sourceType: ContentIngressSummary["normalizedCtSourceTypes"][number];
  trust: "trusted" | "untrusted" | "unknown";
  taints: string[];
}

interface ParsedEnvelope {
  kind: CtParseKind;
  eventId: string | null;
  sourceFacts: ParsedSourceFact[];
  issues: string[];
}

interface ProjectionResult {
  presentation: ProvenancePresentationViewModel;
  provenanceAvailability: Availability;
  factAvailability: Availability;
  contentByEventId: Map<string, ContentIngressSummary>;
}

const CONTRACT = "ct-provenance/1.0";
const CT_RELATIONS = new Set<CtFlowRelation>([
  "received_from",
  "read_from",
  "derived_from",
  "assembled_into",
  "influenced_by",
  "returned_by",
  "written_to",
  "persisted_to",
  "loaded_from_memory",
  "sent_to",
]);
const NODE_KINDS = new Set<CtProvenanceNodeKind>([
  "source",
  "context",
  "model_input",
  "memory",
  "action",
  "other",
]);
const SOURCE_TYPES = new Set<ParsedSourceFact["sourceType"]>([
  "user",
  "web",
  "email",
  "tool_result",
  "mcp",
  "rag",
  "memory",
  "file",
  "model",
  "runtime",
  "other",
]);
const AUTHORITIES = new Set<Exclude<DisplayFactAuthority, "none">>([
  "authoritative",
  "trusted_claim",
  "untrusted_claim",
  "model_judgment",
]);
const COVERAGES = new Set<Coverage>(["complete", "partial", "stale", "unknown", "not_applicable"]);

function record(value: unknown): JsonRecord {
  return value !== null && typeof value === "object" && !Array.isArray(value)
    ? (value as JsonRecord)
    : {};
}

function text(value: unknown): string | null {
  return typeof value === "string" && value.length > 0 ? value : null;
}

function strings(value: unknown): string[] | null {
  if (!Array.isArray(value)) return null;
  if (!value.every((item) => typeof item === "string" && item.length > 0)) return null;
  return [...new Set(value as string[])].sort();
}

function sha256(value: unknown): string | null {
  const digest = text(value);
  return digest && /^sha256:[0-9a-f]{64}$/.test(digest) ? digest : null;
}

function coverage(value: unknown): Coverage | null {
  return typeof value === "string" && COVERAGES.has(value as Coverage) ? (value as Coverage) : null;
}

function locator(recordId: string, traceId: string): EvidenceLocator {
  return { kind: "audit", id: recordId, traceId };
}

function evidenceLocators(value: unknown, traceId: string): EvidenceLocator[] | null {
  if (!Array.isArray(value) || value.length === 0) return null;
  const result: EvidenceLocator[] = [];
  for (const item of value) {
    const row = record(item);
    const recordId = text(row.record_id);
    if (
      !text(row.ref_id) ||
      row.kind !== "audit_event" ||
      row.record_type !== "policy_evaluation" ||
      !recordId ||
      row.json_pointer !== "/evidence/ct_transient_facts" ||
      !sha256(row.digest) ||
      row.redaction_state !== "summary_only"
    ) {
      return null;
    }
    result.push(locator(recordId, traceId));
  }
  return result;
}

function parseEnvelope(event: NormalizedAuditEvidence): ParsedEnvelope {
  const evidence = record(record(event.raw).evidence);
  if (!("ct_transient_facts" in evidence)) {
    return { kind: "absent", eventId: event.eventId, sourceFacts: [], issues: [] };
  }
  const envelope = record(evidence.ct_transient_facts);
  if (envelope._budget_dropped === true) {
    return {
      kind: sha256(envelope._envelope_sha256) ? "budget_dropped" : "invalid",
      eventId: event.eventId,
      sourceFacts: [],
      issues: sha256(envelope._envelope_sha256) ? [] : ["CT_DROPPED_DIGEST_INVALID"],
    };
  }
  const version = text(envelope.schema_version);
  if (version !== "1.0" && version !== "1.1") {
    return {
      kind: "unsupported",
      eventId: event.eventId,
      sourceFacts: [],
      issues: ["CT_ENVELOPE_VERSION_UNSUPPORTED"],
    };
  }
  const payload = record(envelope.payload);
  if (payload._budget_dropped === true) {
    return {
      kind: sha256(payload._envelope_sha256) ? "budget_dropped" : "invalid",
      eventId: event.eventId,
      sourceFacts: [],
      issues: sha256(payload._envelope_sha256) ? [] : ["CT_DROPPED_DIGEST_INVALID"],
    };
  }
  const bundle = record(payload.bundle);
  const bundleEventId = text(bundle.event_id);
  const bundleDigest = sha256(payload.bundle_digest);
  const embeddedBundleDigest = sha256(bundle.bundle_digest);
  const sourceIdentity = record(payload.source_identity);
  const sourceRecordId = text(sourceIdentity.source_record_id);
  const issues: string[] = [];
  if (!bundleEventId || !bundleDigest || embeddedBundleDigest !== bundleDigest) {
    issues.push("CT_BUNDLE_IDENTITY_INVALID");
  }
  if (event.eventId && bundleEventId !== event.eventId) issues.push("CT_EVENT_ID_MISMATCH");
  if (
    sourceIdentity.source_record_type !== "runtime_observation" ||
    sourceIdentity.source_revision !== 1 ||
    !sourceRecordId ||
    (event.eventId && sourceRecordId !== `ct-facts:${event.eventId}`)
  ) {
    issues.push("CT_SOURCE_IDENTITY_INVALID");
  }
  if (version === "1.1") {
    if (payload.fact_builder_version !== "ct-fact-2") {
      issues.push("CT_FACT_BUILDER_VERSION_INVALID");
    }
    const eligible = payload.projection_eligible;
    if (
      typeof eligible !== "boolean" ||
      (eligible === true && !text(payload.projection_id)) ||
      (eligible === false && payload.projection_id !== null)
    ) {
      issues.push("CT_PROJECTION_IDENTITY_INVALID");
    }
    const outerOverlay = sha256(payload.overlay_digest);
    const innerOverlay = sha256(bundle.overlay_digest);
    if (!outerOverlay || outerOverlay !== innerOverlay) {
      issues.push("CT_OVERLAY_DIGEST_INVALID");
    }
  } else if (
    payload.fact_builder_version !== undefined &&
    payload.fact_builder_version !== "ct-fact-1"
  ) {
    issues.push("CT_FACT_BUILDER_VERSION_INVALID");
  }

  const sourceFacts: ParsedSourceFact[] = [];
  if (!Array.isArray(bundle.source_facts)) {
    issues.push("CT_SOURCE_FACTS_INVALID");
  } else {
    for (const item of bundle.source_facts) {
      const fact = record(item);
      const sourceId = text(fact.source_id);
      const sourceType = text(fact.source_type);
      const trust = text(fact.trust);
      const taints = strings(fact.taints);
      if (
        !sourceId ||
        !sourceType ||
        !SOURCE_TYPES.has(sourceType as ParsedSourceFact["sourceType"]) ||
        (trust !== "trusted" && trust !== "untrusted" && trust !== "unknown") ||
        taints === null
      ) {
        issues.push("CT_SOURCE_FACT_INVALID");
        continue;
      }
      sourceFacts.push({
        sourceId,
        sourceType: sourceType as ParsedSourceFact["sourceType"],
        trust,
        taints,
      });
    }
  }
  return {
    kind: issues.length ? "invalid" : "valid",
    eventId: bundleEventId ?? event.eventId,
    sourceFacts,
    issues,
  };
}

function semantics(
  sourceMode: ElementSourceMode,
  traceId: string,
  availability: Availability,
  certainty: EvidenceCertainty,
  authority: DisplayFactAuthority,
  refs: EvidenceLocator[],
): DisplayEvidenceSemantics {
  return {
    elementSourceMode: sourceMode,
    availability,
    certainty,
    decisionAuthority: "none",
    factAuthority: authority,
    derivedForDisplay: true,
    sourceRefs: refs.length ? refs : [{ kind: "fact", id: "unresolved", traceId }],
  };
}

function parseNode(
  node: ProvenanceNode,
  traceId: string,
  sourceMode: ElementSourceMode,
): ProvenanceNodePresentation | null {
  const metadata = node.metadata;
  if (metadata.contract !== CONTRACT || metadata.kind !== "node") return null;
  const kind = text(metadata.node_kind);
  const nodeRef = record(metadata.node_ref);
  const refType = text(nodeRef.ref_type);
  const refId = text(nodeRef.ref_id);
  const taints = strings(metadata.taints);
  const nodeCoverage = coverage(metadata.coverage);
  const refs = evidenceLocators(metadata.evidence_refs, traceId);
  if (
    !kind ||
    !NODE_KINDS.has(kind as CtProvenanceNodeKind) ||
    kind !== node.kind ||
    refType !== kind ||
    refId !== node.refId ||
    node.traceId !== traceId ||
    taints === null ||
    !nodeCoverage ||
    refs === null
  ) {
    return null;
  }
  const nodeKind = kind as CtProvenanceNodeKind;
  const availability: Availability =
    nodeCoverage === "complete"
      ? "recorded"
      : nodeCoverage === "not_applicable"
        ? "not_applicable"
        : nodeCoverage === "partial"
          ? "partial"
          : "unavailable";
  const base = {
    provenanceNodeId: node.nodeId,
    nodeKind,
    refType,
    refId,
    taints,
    displayMode: "metadata_only" as const,
    safeExcerpt: null,
  };
  if (nodeKind === "source") {
    const sourceType = text(metadata.source_type);
    const trust = text(metadata.trust);
    const verification = text(metadata.verification_state);
    const authority = text(metadata.fact_authority);
    if (
      !sourceType ||
      !SOURCE_TYPES.has(sourceType as ParsedSourceFact["sourceType"]) ||
      (trust !== "trusted" && trust !== "untrusted" && trust !== "unknown") ||
      (verification !== "verified" &&
        verification !== "unverified" &&
        verification !== "not_applicable") ||
      !authority ||
      !AUTHORITIES.has(authority as Exclude<DisplayFactAuthority, "none">)
    ) {
      return null;
    }
    return {
      ...base,
      nodeKind,
      rawSourceType: sourceType,
      normalizedCtSourceType: sourceType,
      ctNormalizationAvailability: availability,
      trust,
      verificationState: verification,
      semantics: semantics(
        sourceMode,
        traceId,
        availability,
        nodeCoverage === "complete" ? "supported" : "unknown",
        authority as Exclude<DisplayFactAuthority, "none">,
        refs,
      ),
    };
  }
  if (nodeKind === "context") {
    const scopeDigest = sha256(metadata.scope_digest);
    const manifest = metadata.manifest_event_id;
    if (!scopeDigest || (manifest !== null && !text(manifest))) return null;
    return {
      ...base,
      nodeKind,
      scopeDigest,
      manifestEventId: manifest as string | null,
      semantics: semantics(sourceMode, traceId, availability, "supported", "trusted_claim", refs),
    };
  }
  if (nodeKind === "model_input") {
    const eventId = text(metadata.event_id);
    const contextRef = text(metadata.context_ref);
    const modelCallRef = metadata.model_call_ref;
    if (!eventId || !contextRef || (modelCallRef !== null && !text(modelCallRef))) return null;
    return {
      ...base,
      nodeKind,
      eventId,
      contextRef,
      modelCallRef: modelCallRef as string | null,
      semantics: semantics(sourceMode, traceId, availability, "supported", "trusted_claim", refs),
    };
  }
  if (nodeKind === "memory") {
    const memoryRef = text(metadata.memory_ref);
    const trust = text(metadata.trust);
    const authority = text(metadata.fact_authority);
    if (
      !memoryRef ||
      (trust !== "trusted" && trust !== "untrusted" && trust !== "unknown") ||
      !authority ||
      !AUTHORITIES.has(authority as Exclude<DisplayFactAuthority, "none">)
    ) {
      return null;
    }
    return {
      ...base,
      nodeKind,
      memoryRef,
      trust,
      factAuthority: authority as Exclude<DisplayFactAuthority, "none">,
      semantics: semantics(
        sourceMode,
        traceId,
        availability,
        "supported",
        authority as Exclude<DisplayFactAuthority, "none">,
        refs,
      ),
    };
  }
  if (nodeKind === "action") {
    const actionId = text(metadata.action_id);
    if (!actionId) return null;
    return {
      ...base,
      nodeKind,
      actionId,
      semantics: semantics(sourceMode, traceId, availability, "supported", "trusted_claim", refs),
    };
  }
  if (nodeCoverage !== "unknown" && nodeCoverage !== "not_applicable") return null;
  return {
    ...base,
    nodeKind: "other",
    semantics: semantics(sourceMode, traceId, "unavailable", "unknown", "none", refs),
  };
}

function edgeCertainty(
  edgeCoverage: Coverage,
  strength: ProvenanceEdgePresentation["flowStrength"],
  origin: ProvenanceEdgePresentation["flowOrigin"],
  refsValid: boolean,
): EvidenceCertainty {
  if (!refsValid || edgeCoverage === "stale" || edgeCoverage === "unknown") return "unknown";
  if (edgeCoverage === "not_applicable") return "unknown";
  if (origin === "semantic_inferred" || strength === "possible") return "possible";
  if (edgeCoverage === "partial") return "supported";
  if (strength === "exact" && (origin === "observed" || origin === "deterministic")) {
    return "confirmed";
  }
  return strength === "strong" ? "supported" : "unknown";
}

function legacyEdge(edge: ProvenanceEdge): ProvenanceEdgePresentation {
  return {
    edgeId: edge.edgeId,
    sourceNodeId: edge.sourceNodeId,
    targetNodeId: edge.targetNodeId,
    wireRelation: edge.relation,
    ctFlowRelation: null,
    legacyRelationType: text(edge.metadata.relation_type),
    certainty: "unknown",
    flowStrength: "unknown",
    flowOrigin: "unknown",
    coverage: "unknown",
    sourceRefs: [],
  };
}

function parseEdge(
  edge: ProvenanceEdge,
  traceId: string,
  typedNodes: Map<string, ProvenanceNodePresentation>,
): ProvenanceEdgePresentation | null {
  const metadata = edge.metadata;
  if (metadata.contract !== CONTRACT || metadata.kind !== "edge") return null;
  const relation = text(metadata.flow_relation);
  const flowId = text(metadata.flow_id);
  const sourceRef = text(metadata.source_ref);
  const targetRef = text(metadata.target_ref);
  const strength = text(metadata.flow_strength);
  const origin = text(metadata.flow_origin);
  const edgeCoverage = coverage(metadata.coverage);
  const refs = evidenceLocators(metadata.evidence_refs, traceId);
  const source = typedNodes.get(edge.sourceNodeId);
  const target = typedNodes.get(edge.targetNodeId);
  if (
    !flowId ||
    !relation ||
    !CT_RELATIONS.has(relation as CtFlowRelation) ||
    edge.relation !== relation ||
    edge.traceId !== traceId ||
    !source ||
    !target ||
    source.refId !== sourceRef ||
    target.refId !== targetRef ||
    (strength !== "exact" && strength !== "strong" && strength !== "possible") ||
    (origin !== "observed" && origin !== "deterministic" && origin !== "semantic_inferred") ||
    !edgeCoverage ||
    refs === null
  ) {
    return null;
  }
  return {
    edgeId: edge.edgeId,
    sourceNodeId: edge.sourceNodeId,
    targetNodeId: edge.targetNodeId,
    wireRelation: edge.relation,
    ctFlowRelation: relation as CtFlowRelation,
    legacyRelationType: null,
    certainty: edgeCertainty(edgeCoverage, strength, origin, refs.length > 0),
    flowStrength: strength,
    flowOrigin: origin,
    coverage: edgeCoverage,
    sourceRefs: refs,
  };
}

function rawSourceTypes(event: NormalizedAuditEvidence): string[] {
  return event.source.type ? [event.source.type] : [];
}

function emptyContent(
  availability: Availability,
  event: NormalizedAuditEvidence,
): ContentIngressSummary {
  return {
    availability,
    stableSourceRefs: [],
    rawSourceTypes: rawSourceTypes(event),
    normalizedCtSourceTypes: [],
    ctNormalizationAvailability: availability,
    trustLabels: [],
    taints: [],
    provenanceNodeIds: [],
  };
}

export function projectCtPresentation(input: {
  traceId: string;
  elementSourceMode: ElementSourceMode;
  events: readonly NormalizedAuditEvidence[];
  provenance?: ProvenanceGraph | null;
}): ProjectionResult {
  const envelopes = input.events.map((event) => ({ event, parsed: parseEnvelope(event) }));
  const graph = input.provenance;
  const warnings: SupervisionWarning[] = [];
  const validNodes = new Map<string, ProvenanceNodePresentation>();
  let typedCandidateCount = 0;
  let invalidTypedCount = 0;
  for (const node of graph?.nodes ?? []) {
    if (node.metadata.contract !== CONTRACT) continue;
    typedCandidateCount += 1;
    const parsed = parseNode(node, input.traceId, input.elementSourceMode);
    if (parsed) validNodes.set(node.nodeId, parsed);
    else invalidTypedCount += 1;
  }
  const edges: ProvenanceEdgePresentation[] = [];
  let validTypedEdgeCount = 0;
  for (const edge of graph?.edges ?? []) {
    if (edge.metadata.contract !== CONTRACT) {
      edges.push(legacyEdge(edge));
      continue;
    }
    typedCandidateCount += 1;
    const parsed = parseEdge(edge, input.traceId, validNodes);
    if (parsed) {
      validTypedEdgeCount += 1;
      edges.push(parsed);
    } else {
      invalidTypedCount += 1;
      edges.push(legacyEdge(edge));
    }
  }
  const legacyCount = (graph?.nodes.length ?? 0) + (graph?.edges.length ?? 0) - typedCandidateCount;
  const validTypedCount = validNodes.size + validTypedEdgeCount;
  const contractKind =
    validTypedCount === 0
      ? "legacy"
      : legacyCount > 0 || invalidTypedCount > 0
        ? "mixed"
        : "ct-provenance/1.0";
  if (invalidTypedCount) {
    warnings.push({
      code: "unsupported_contract",
      severity: "warning",
      message: `${invalidTypedCount} 个 CT 溯源元素未通过身份或引用校验，已按 legacy/unknown 展示。`,
      sourceRefs: [],
    });
  }
  const truncated = Boolean(
    graph?.window.hasMore || graph?.window.nodesHaveMore || graph?.window.edgesHaveMore,
  );
  const envelopePartial = envelopes.some(({ parsed }) =>
    ["budget_dropped", "invalid"].includes(parsed.kind),
  );
  const envelopeValid = envelopes.some(({ parsed }) => parsed.kind === "valid");
  const envelopeUnsupported = envelopes.some(({ parsed }) => parsed.kind === "unsupported");
  if (envelopeUnsupported) {
    warnings.push({
      code: "unsupported_contract",
      severity: "warning",
      message: "存在无法解释的 CT envelope 版本，未启用其安全展示语义。",
      sourceRefs: [],
    });
  }
  const provenanceAvailability: Availability =
    validTypedCount === 0
      ? "unavailable"
      : truncated || invalidTypedCount > 0 || contractKind === "mixed" || envelopePartial
        ? "partial"
        : "recorded";
  const factAvailability: Availability = envelopeValid
    ? envelopePartial
      ? "partial"
      : "recorded"
    : envelopePartial
      ? "partial"
      : "unavailable";

  const nodeIdByRef = new Map(
    [...validNodes.values()].map((node) => [node.refId, node.provenanceNodeId]),
  );
  const contentByEventId = new Map<string, ContentIngressSummary>();
  for (const { event, parsed } of envelopes) {
    if (!event.eventId) continue;
    if (parsed.kind === "budget_dropped" || parsed.kind === "invalid") {
      contentByEventId.set(event.eventId, emptyContent("partial", event));
      continue;
    }
    if (parsed.kind !== "valid") {
      contentByEventId.set(event.eventId, emptyContent("unavailable", event));
      continue;
    }
    if (parsed.sourceFacts.length === 0) {
      contentByEventId.set(event.eventId, emptyContent("not_applicable", event));
      continue;
    }
    const missingNode = parsed.sourceFacts.some((fact) => !nodeIdByRef.has(fact.sourceId));
    const availability: Availability =
      missingNode || provenanceAvailability !== "recorded" ? "partial" : "recorded";
    contentByEventId.set(event.eventId, {
      availability,
      stableSourceRefs: parsed.sourceFacts.map((fact) => fact.sourceId),
      rawSourceTypes: rawSourceTypes(event),
      normalizedCtSourceTypes: [...new Set(parsed.sourceFacts.map((fact) => fact.sourceType))],
      ctNormalizationAvailability: availability,
      trustLabels: [...new Set(parsed.sourceFacts.map((fact) => fact.trust))],
      taints: [...new Set(parsed.sourceFacts.flatMap((fact) => fact.taints))].sort(),
      provenanceNodeIds: parsed.sourceFacts.flatMap((fact) => {
        const nodeId = nodeIdByRef.get(fact.sourceId);
        return nodeId ? [nodeId] : [];
      }),
    });
  }
  return {
    presentation: {
      contractKind,
      nodes: [...validNodes.values()].sort((a, b) =>
        a.provenanceNodeId.localeCompare(b.provenanceNodeId),
      ),
      edges: edges.sort((a, b) => a.edgeId.localeCompare(b.edgeId)),
      warnings,
    },
    provenanceAvailability,
    factAvailability,
    contentByEventId,
  };
}

function mergeAvailability(values: Availability[]): Availability {
  if (values.length === 0) return "unavailable";
  if (values.every((value) => value === "not_applicable")) return "not_applicable";
  if (values.every((value) => value === "recorded" || value === "not_applicable")) {
    return "recorded";
  }
  if (values.every((value) => value === "unavailable")) return "unavailable";
  return "partial";
}

export function applyCtContentToSteps(
  steps: readonly ExecutionStepViewModel[],
  contentByEventId: ReadonlyMap<string, ContentIngressSummary>,
): ExecutionStepViewModel[] {
  return steps.map((step) => {
    const summaries = step.eventIds.flatMap((eventId) => {
      const summary = contentByEventId.get(eventId);
      return summary ? [summary] : [];
    });
    if (!summaries.length) return step;
    const contentIngressSummary: ContentIngressSummary = {
      availability: mergeAvailability(summaries.map((item) => item.availability)),
      stableSourceRefs: [...new Set(summaries.flatMap((item) => item.stableSourceRefs))],
      rawSourceTypes: [...new Set(summaries.flatMap((item) => item.rawSourceTypes))],
      normalizedCtSourceTypes: [
        ...new Set(summaries.flatMap((item) => item.normalizedCtSourceTypes)),
      ],
      ctNormalizationAvailability: mergeAvailability(
        summaries.map((item) => item.ctNormalizationAvailability),
      ),
      trustLabels: [...new Set(summaries.flatMap((item) => item.trustLabels))],
      taints: [...new Set(summaries.flatMap((item) => item.taints))],
      provenanceNodeIds: [...new Set(summaries.flatMap((item) => item.provenanceNodeIds))],
    };
    return {
      ...step,
      supervision: { ...step.supervision, contentIngressSummary },
    };
  });
}
