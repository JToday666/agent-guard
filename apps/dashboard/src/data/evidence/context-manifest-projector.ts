import type { NormalizedAuditEvidence } from "../../types/dashboard.ts";
import type {
  Availability,
  ContextManifestChunkPresentation,
  ContextManifestCountsPresentation,
  ContextManifestViewModel,
  SupervisionWarning,
} from "../../types/runtime-supervision.ts";

type UnknownRecord = Record<string, unknown>;

const SHA256_RE = /^sha256:[0-9a-f]{64}$/;
const SCOPE_DIGEST_RE = /^(?:sha256|hmac-sha256):[0-9a-f]{64}$/;
const AUDIT_ID_RE = /^audit_context_manifest_[0-9a-f]{64}$/;
const UNSAFE_IDENTIFIER_RE =
  /fingerprint|runtime[_-]?binding|lease[_-]?token|nonce|credential|password|secret|(?:^|[_:-])token(?:$|[_:-])/i;
const SENSITIVE_LABEL_RE =
  /^(?:fingerprint|runtime[_-]?binding|lease[_-]?token|nonce|credential|password|secret|token)$/i;
const UNSAFE_VALUE_RE =
  /(?:hmac-sha256|lease-v1):[0-9a-f]{64}|agt_tok_[0-9a-f]{32}|bearer\s+[A-Za-z0-9._~+/=-]{8,}|\b(?:sk|pk)-[A-Za-z0-9_-]{8,}\b|[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/i;
const SAFE_REASON_RE = /^[A-Za-z0-9][A-Za-z0-9._:/+-]{0,127}$/;
const COMPARTMENTS = new Set([
  "authority",
  "authenticated_task",
  "trusted_runtime_fact",
  "untrusted_evidence",
  "memory_context",
  "model_derived",
]);
const TRUST = new Set(["trusted", "untrusted", "unknown"]);
const FACT_AUTHORITY = new Set([
  "authoritative",
  "trusted_claim",
  "untrusted_claim",
  "model_judgment",
]);
const TAINTS = new Set([
  "UNTRUSTED",
  "EXTERNAL_INSTRUCTION",
  "SENSITIVE",
  "CREDENTIAL",
  "PERSISTENT_UNTRUSTED",
]);
const TRANSFORM_STATES = new Set(["preserved", "annotated", "quarantined", "excluded"]);
const EVIDENCE_KINDS = new Set([
  "guard_event",
  "audit_event",
  "task_fact",
  "source_fact",
  "flow_fact",
  "memory_fact",
  "capability_grant",
  "recent_action",
  "policy_rule",
  "runtime_receipt",
  "semantic_judgment",
  "declassification",
  "degradation",
]);
const REDACTION_STATES = new Set(["none", "redacted", "summary_only"]);

class InvalidManifest extends Error {}

interface ParsedCarrier {
  eventId: string;
  signature: string;
  view: ContextManifestViewModel;
}

export interface ContextManifestProjection {
  contextManifestByEventId: Record<string, ContextManifestViewModel>;
  availability: Availability;
  warnings: SupervisionWarning[];
}

function record(value: unknown): UnknownRecord {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new InvalidManifest("expected object");
  }
  return value as UnknownRecord;
}

function exactKeys(
  value: UnknownRecord,
  required: readonly string[],
  optional: readonly string[] = [],
): void {
  const allowed = new Set([...required, ...optional]);
  if (required.some((key) => !Object.prototype.hasOwnProperty.call(value, key))) {
    throw new InvalidManifest("required field missing");
  }
  if (Object.keys(value).some((key) => !allowed.has(key))) {
    throw new InvalidManifest("unknown field");
  }
}

function nonEmptyString(value: unknown, maxLength = 512): string {
  if (typeof value !== "string" || !value || value.length > maxLength) {
    throw new InvalidManifest("invalid string");
  }
  return value;
}

function safeIdentifier(value: unknown, maxLength = 512): string {
  const parsed = nonEmptyString(value, maxLength);
  if (
    (UNSAFE_IDENTIFIER_RE.test(parsed) && !SENSITIVE_LABEL_RE.test(parsed)) ||
    UNSAFE_VALUE_RE.test(parsed)
  ) {
    throw new InvalidManifest("unsafe identifier");
  }
  return parsed;
}

function sha256(value: unknown): string {
  const parsed = nonEmptyString(value);
  if (!SHA256_RE.test(parsed)) throw new InvalidManifest("invalid sha256");
  return parsed;
}

function nonNegativeInteger(value: unknown): number {
  if (!Number.isInteger(value) || (value as number) < 0) {
    throw new InvalidManifest("invalid count");
  }
  return value as number;
}

function bool(value: unknown): boolean {
  if (typeof value !== "boolean") throw new InvalidManifest("invalid boolean");
  return value;
}

function enumValue<T extends string>(value: unknown, allowed: ReadonlySet<string>): T {
  if (typeof value !== "string" || !allowed.has(value)) {
    throw new InvalidManifest("unknown enum value");
  }
  return value as T;
}

function stringArray(
  value: unknown,
  maximum: number,
  parse: (item: unknown) => string = nonEmptyString,
): string[] {
  if (!Array.isArray(value) || value.length > maximum) {
    throw new InvalidManifest("invalid bounded array");
  }
  const parsed = value.map((item) => parse(item));
  if (new Set(parsed).size !== parsed.length) throw new InvalidManifest("duplicate array value");
  return parsed;
}

function safeReasonArray(value: unknown): string[] {
  return stringArray(value, 64, (item) => {
    const parsed = nonEmptyString(item, 128);
    if (!SAFE_REASON_RE.test(parsed) || UNSAFE_VALUE_RE.test(parsed)) {
      throw new InvalidManifest("invalid reason code");
    }
    return parsed;
  });
}

function validateEvidenceRefs(value: unknown): void {
  if (!Array.isArray(value) || value.length > 64) {
    throw new InvalidManifest("invalid evidence refs");
  }
  const signatures = new Set<string>();
  for (const item of value) {
    const ref = record(item);
    exactKeys(ref, [
      "ref_id",
      "kind",
      "record_type",
      "record_id",
      "json_pointer",
      "digest",
      "redaction_state",
    ]);
    nonEmptyString(ref.ref_id);
    enumValue(ref.kind, EVIDENCE_KINDS);
    nonEmptyString(ref.record_type);
    nonEmptyString(ref.record_id);
    if (ref.json_pointer !== null) nonEmptyString(ref.json_pointer);
    sha256(ref.digest);
    enumValue(ref.redaction_state, REDACTION_STATES);
    const signature = stableStringify(ref);
    if (signatures.has(signature)) throw new InvalidManifest("duplicate evidence ref");
    signatures.add(signature);
  }
}

function parseCounts(value: unknown): ContextManifestCountsPresentation {
  const counts = record(value);
  exactKeys(counts, [
    "total",
    "returned",
    "included",
    "excluded",
    "quarantined",
    "sensitive",
    "untrusted",
    "by_source_type",
  ]);
  const total = nonNegativeInteger(counts.total);
  const returned = nonNegativeInteger(counts.returned);
  const included = nonNegativeInteger(counts.included);
  const excluded = nonNegativeInteger(counts.excluded);
  const quarantined = nonNegativeInteger(counts.quarantined);
  const sensitive = nonNegativeInteger(counts.sensitive);
  const untrusted = nonNegativeInteger(counts.untrusted);
  if (
    returned > 20 ||
    returned > total ||
    included + excluded !== total ||
    quarantined > excluded ||
    sensitive > total ||
    untrusted > total
  ) {
    throw new InvalidManifest("inconsistent counts");
  }
  const sourceCounts = record(counts.by_source_type);
  const bySourceType: Record<string, number> = {};
  for (const [key, item] of Object.entries(sourceCounts).sort(([left], [right]) =>
    left.localeCompare(right),
  )) {
    const safeKey = safeIdentifier(key, 128);
    bySourceType[safeKey] = nonNegativeInteger(item);
  }
  if (Object.values(bySourceType).reduce((sum, item) => sum + item, 0) !== total) {
    throw new InvalidManifest("source counts do not cover total");
  }
  return {
    total,
    returned,
    included,
    excluded,
    quarantined,
    sensitive,
    untrusted,
    bySourceType,
  };
}

function validateSequence(value: unknown, runtime: string, index: number): void {
  const sequence = record(value);
  exactKeys(sequence, ["domain", "producer_binding_id", "value"]);
  if (
    sequence.domain !== "runtime" ||
    sequence.producer_binding_id !== `runtime:${runtime}` ||
    sequence.value !== index
  ) {
    throw new InvalidManifest("invalid runtime sequence");
  }
}

function restrictedPreview(chunk: {
  compartment: string;
  sensitive: boolean;
  taints: readonly string[];
  transformState: string;
}): boolean {
  return (
    chunk.sensitive ||
    chunk.taints.includes("CREDENTIAL") ||
    chunk.taints.includes("SENSITIVE") ||
    ["authority", "trusted_runtime_fact", "model_derived"].includes(chunk.compartment) ||
    ["quarantined", "excluded"].includes(chunk.transformState)
  );
}

function safePreview(value: unknown, restricted: boolean): string | null {
  if (value === null) return null;
  if (typeof value !== "string" || value.length > 240 || restricted) {
    throw new InvalidManifest("restricted or oversized preview");
  }
  if (UNSAFE_IDENTIFIER_RE.test(value) || UNSAFE_VALUE_RE.test(value)) return null;
  return value;
}

function parseChunk(
  value: unknown,
  runtime: string,
  scopeDigest: string,
  contextRef: string,
  index: number,
): ContextManifestChunkPresentation & { rawContentDigest: string } {
  const chunk = record(value);
  exactKeys(chunk, [
    "schema_version",
    "chunk_id",
    "scope_digest",
    "context_ref",
    "source_ref",
    "source_type",
    "compartment",
    "trust",
    "fact_authority",
    "taints",
    "content_digest",
    "content_preview",
    "instruction_like",
    "sensitive",
    "transform_state",
    "sequence",
    "evidence_refs",
  ]);
  if (chunk.schema_version !== "1.0") throw new InvalidManifest("unknown chunk version");
  if (chunk.scope_digest !== scopeDigest || chunk.context_ref !== contextRef) {
    throw new InvalidManifest("chunk identity mismatch");
  }
  const compartment = enumValue<ContextManifestChunkPresentation["compartment"]>(
    chunk.compartment,
    COMPARTMENTS,
  );
  const trust = enumValue<ContextManifestChunkPresentation["trust"]>(chunk.trust, TRUST);
  const factAuthority = enumValue<ContextManifestChunkPresentation["factAuthority"]>(
    chunk.fact_authority,
    FACT_AUTHORITY,
  );
  const taints = stringArray(chunk.taints, 5, (item) =>
    enumValue(item, TAINTS),
  ) as ContextManifestChunkPresentation["taints"];
  const transformState = enumValue<ContextManifestChunkPresentation["transformState"]>(
    chunk.transform_state,
    TRANSFORM_STATES,
  );
  const instructionLike = bool(chunk.instruction_like);
  const sensitive = bool(chunk.sensitive);
  const rawContentDigest = sha256(chunk.content_digest);
  validateSequence(chunk.sequence, runtime, index);
  validateEvidenceRefs(chunk.evidence_refs);

  if (sensitive && transformState !== "excluded") {
    throw new InvalidManifest("sensitive chunk was not excluded");
  }
  if (
    compartment === "untrusted_evidence" &&
    (trust !== "untrusted" ||
      ["authoritative", "trusted_claim"].includes(factAuthority) ||
      (instructionLike && !["quarantined", "excluded"].includes(transformState)))
  ) {
    throw new InvalidManifest("untrusted evidence gained authority");
  }
  if (
    factAuthority === "authoritative" &&
    (trust !== "trusted" || !["authority", "authenticated_task"].includes(compartment))
  ) {
    throw new InvalidManifest("invalid authoritative chunk");
  }
  if (
    compartment === "trusted_runtime_fact" &&
    (chunk.source_type !== "runtime" || trust !== "trusted" || factAuthority !== "trusted_claim")
  ) {
    throw new InvalidManifest("invalid runtime fact");
  }
  if (compartment === "model_derived" && factAuthority !== "model_judgment") {
    throw new InvalidManifest("invalid model-derived authority");
  }

  const isRestricted = restrictedPreview({ compartment, sensitive, taints, transformState });
  const preview = safePreview(chunk.content_preview, isRestricted);
  return {
    chunkId: safeIdentifier(chunk.chunk_id),
    sourceRef: safeIdentifier(chunk.source_ref),
    sourceType: safeIdentifier(chunk.source_type, 128),
    compartment,
    trust,
    factAuthority,
    taints,
    transformState,
    transformationAction: null,
    disposition:
      transformState === "quarantined"
        ? "quarantined"
        : transformState === "excluded"
          ? "excluded"
          : "included",
    reasonCodes: [],
    contentDigest: isRestricted ? null : rawContentDigest,
    safePreview: preview,
    instructionLike,
    sensitive,
    rawContentDigest,
  };
}

function parseFullManifest(
  value: unknown,
  auditId: string,
  eventId: string,
  links: UnknownRecord,
  runtime: string,
  traceId: string,
): ContextManifestViewModel {
  const manifest = record(value);
  exactKeys(manifest, [
    "schema_version",
    "plan_id",
    "event_id",
    "scope_digest",
    "runtime",
    "context_ref",
    "plan_digest",
    "manifest_digest",
    "counts",
    "chunks",
    "transformations",
    "excluded_chunk_ids",
    "reason_codes",
    "evidence_refs",
    "completeness",
  ]);
  if (manifest.schema_version !== "1.0") throw new InvalidManifest("unknown manifest version");
  const planId = safeIdentifier(manifest.plan_id);
  const contextRef = safeIdentifier(manifest.context_ref);
  const payloadEventId = safeIdentifier(manifest.event_id);
  const payloadRuntime = safeIdentifier(manifest.runtime, 128);
  if (
    payloadEventId !== eventId ||
    payloadRuntime !== runtime ||
    links.event_id !== eventId ||
    links.plan_id !== planId ||
    links.context_ref !== contextRef
  ) {
    throw new InvalidManifest("manifest links mismatch");
  }
  const scopeDigest = nonEmptyString(manifest.scope_digest);
  if (!SCOPE_DIGEST_RE.test(scopeDigest)) throw new InvalidManifest("invalid scope digest");
  const planDigest = sha256(manifest.plan_digest);
  const manifestDigest = sha256(manifest.manifest_digest);
  const counts = parseCounts(manifest.counts);
  if (!Array.isArray(manifest.chunks) || manifest.chunks.length > 20) {
    throw new InvalidManifest("invalid chunks");
  }
  const chunks = manifest.chunks.map((chunk, index) =>
    parseChunk(chunk, runtime, scopeDigest, contextRef, index),
  );
  if (
    chunks.length !== counts.returned ||
    new Set(chunks.map((chunk) => chunk.chunkId)).size !== chunks.length
  ) {
    throw new InvalidManifest("returned chunk count mismatch");
  }

  const excludedChunkIds = stringArray(manifest.excluded_chunk_ids, 20, safeIdentifier);
  const expectedExcluded = chunks
    .filter((chunk) => chunk.disposition !== "included")
    .map((chunk) => chunk.chunkId)
    .sort();
  if (excludedChunkIds.slice().sort().join("\u0000") !== expectedExcluded.join("\u0000")) {
    throw new InvalidManifest("excluded chunk identities mismatch");
  }
  if (!Array.isArray(manifest.transformations) || manifest.transformations.length > 20) {
    throw new InvalidManifest("invalid transformations");
  }
  const chunkById = new Map(chunks.map((chunk) => [chunk.chunkId, chunk]));
  const transformedIds = new Set<string>();
  const transformationIds = new Set<string>();
  for (const item of manifest.transformations) {
    const transformation = record(item);
    exactKeys(transformation, [
      "transformation_id",
      "chunk_id",
      "action",
      "input_digest",
      "output_digest",
      "mechanism_id",
      "mechanism_version",
      "declassification_id",
      "reason_codes",
      "evidence_refs",
    ]);
    const transformationId = safeIdentifier(transformation.transformation_id);
    const chunkId = safeIdentifier(transformation.chunk_id);
    if (transformationIds.has(transformationId) || transformedIds.has(chunkId)) {
      throw new InvalidManifest("duplicate transformation identity");
    }
    transformationIds.add(transformationId);
    transformedIds.add(chunkId);
    const chunk = chunkById.get(chunkId);
    if (!chunk) throw new InvalidManifest("transformation references unknown chunk");
    const action = enumValue<"annotate" | "quarantine" | "exclude">(
      transformation.action,
      new Set(["annotate", "quarantine", "exclude"]),
    );
    const expectedAction: string | undefined = {
      annotated: "annotate",
      quarantined: "quarantine",
      excluded: "exclude",
    }[chunk.transformState as "annotated" | "quarantined" | "excluded"];
    if (
      expectedAction !== action ||
      sha256(transformation.input_digest) !== chunk.rawContentDigest ||
      transformation.mechanism_id !== "ct-context-builder" ||
      transformation.mechanism_version !== "1.0" ||
      transformation.declassification_id !== null
    ) {
      throw new InvalidManifest("invalid transformation binding");
    }
    if (
      (action === "annotate" && sha256(transformation.output_digest) !== chunk.rawContentDigest) ||
      (action !== "annotate" && transformation.output_digest !== null)
    ) {
      throw new InvalidManifest("invalid transformation output");
    }
    chunk.transformationAction = action;
    chunk.reasonCodes = safeReasonArray(transformation.reason_codes);
    validateEvidenceRefs(transformation.evidence_refs);
  }
  const expectedTransformed = chunks
    .filter((chunk) => chunk.transformState !== "preserved")
    .map((chunk) => chunk.chunkId);
  if (
    expectedTransformed.some((chunkId) => !transformedIds.has(chunkId)) ||
    transformedIds.size !== expectedTransformed.length
  ) {
    throw new InvalidManifest("transformation coverage mismatch");
  }
  const reasonCodes = safeReasonArray(manifest.reason_codes);
  validateEvidenceRefs(manifest.evidence_refs);

  const completeness = record(manifest.completeness);
  exactKeys(completeness, ["status", "truncated", "omitted_digest"]);
  const truncated = bool(completeness.truncated);
  if (truncated) {
    if (completeness.status !== "partial") throw new InvalidManifest("invalid partial status");
    sha256(completeness.omitted_digest);
  } else if (completeness.status !== "complete" || completeness.omitted_digest !== null) {
    throw new InvalidManifest("invalid completeness status");
  }
  if (truncated !== counts.returned < counts.total) {
    throw new InvalidManifest("completeness does not match counts");
  }

  return {
    schemaVersion: "context-manifest-presentation/0.1",
    eventId,
    availability: truncated ? "partial" : "recorded",
    state: "recorded",
    auditId,
    planId,
    contextRef,
    planDigest,
    manifestDigest,
    counts,
    chunks: chunks.map(({ rawContentDigest: _rawContentDigest, ...chunk }) => chunk),
    reasonCodes,
    missingReasons: truncated ? ["MANIFEST_CHUNK_WINDOW_TRUNCATED"] : [],
    sourceRefs: [
      { kind: "audit", id: auditId, traceId },
      { kind: "event", id: eventId, traceId },
    ],
  };
}

function validateCarrierEnvelope(
  event: NormalizedAuditEvidence,
  traceId: string,
): {
  auditId: string;
  eventId: string;
  links: UnknownRecord;
  manifest: unknown;
  runtime: string;
  raw: UnknownRecord;
} {
  const raw = record(event.raw);
  exactKeys(
    raw,
    [
      "audit_id",
      "schema_version",
      "record_type",
      "trace_id",
      "case_id",
      "runtime",
      "timestamp",
      "stage",
      "event_type",
      "attack_type",
      "is_malicious",
      "summary",
      "decision",
      "risk_score",
      "severity",
      "blocked",
      "resource_targets",
      "rule_hits",
      "reason",
      "links",
      "latency_ms",
      "metadata",
      "evidence",
    ],
    ["integrity"],
  );
  const auditId = nonEmptyString(raw.audit_id);
  const eventId = event.eventId ? safeIdentifier(event.eventId) : "";
  const runtime = safeIdentifier(raw.runtime, 128);
  if (
    !AUDIT_ID_RE.test(auditId) ||
    raw.schema_version !== "0.4" ||
    raw.record_type !== "runtime_observation" ||
    raw.trace_id !== traceId ||
    raw.stage !== "context_build" ||
    raw.event_type !== "context_manifest_recorded" ||
    raw.attack_type !== null ||
    raw.is_malicious !== null ||
    raw.summary !== "Bounded context manifest recorded" ||
    raw.decision !== null ||
    raw.risk_score !== null ||
    raw.severity !== null ||
    raw.blocked !== null ||
    !Array.isArray(raw.resource_targets) ||
    raw.resource_targets.length !== 0 ||
    !Array.isArray(raw.rule_hits) ||
    raw.rule_hits.length !== 0 ||
    raw.reason !== "context_manifest_projection" ||
    raw.latency_ms !== null ||
    !eventId ||
    event.auditId !== auditId
  ) {
    throw new InvalidManifest("invalid carrier envelope");
  }
  if (raw.case_id !== null && typeof raw.case_id !== "string") {
    throw new InvalidManifest("invalid case id");
  }
  nonEmptyString(raw.timestamp);
  if (raw.integrity !== undefined) {
    const integrity = record(raw.integrity);
    exactKeys(integrity, ["sequence", "prev_hash", "event_hash", "canonicalization"]);
    if (
      !Number.isInteger(integrity.sequence) ||
      (integrity.sequence as number) < 1 ||
      (integrity.prev_hash !== null &&
        (typeof integrity.prev_hash !== "string" || !/^[0-9a-f]{64}$/.test(integrity.prev_hash))) ||
      typeof integrity.event_hash !== "string" ||
      !/^[0-9a-f]{64}$/.test(integrity.event_hash) ||
      integrity.canonicalization !== "jcs:rfc8785"
    ) {
      throw new InvalidManifest("invalid audit integrity");
    }
  }
  const links = record(raw.links);
  exactKeys(links, ["event_id", "plan_id", "context_ref"]);
  const linkEventId = safeIdentifier(links.event_id);
  safeIdentifier(links.plan_id);
  safeIdentifier(links.context_ref);
  if (linkEventId !== eventId) throw new InvalidManifest("normalized event link mismatch");
  const metadata = record(raw.metadata);
  exactKeys(metadata, ["contract", "producer", "producer_binding_id"]);
  if (
    metadata.contract !== "context-manifest-audit/1.0" ||
    metadata.producer !== "guard_api_context_builder" ||
    metadata.producer_binding_id !== "guard-api:context-builder:1"
  ) {
    throw new InvalidManifest("unknown manifest producer");
  }
  const evidence = record(raw.evidence);
  exactKeys(evidence, ["context_manifest"]);
  return { auditId, eventId, links, manifest: evidence.context_manifest, runtime, raw };
}

function parseCarrier(event: NormalizedAuditEvidence, traceId: string): ParsedCarrier {
  const { auditId, eventId, links, manifest, runtime, raw } = validateCarrierEnvelope(
    event,
    traceId,
  );
  const payload = record(manifest);
  if (Object.prototype.hasOwnProperty.call(payload, "_budget_dropped")) {
    exactKeys(payload, ["_budget_dropped", "_manifest_sha256", "reason"]);
    if (payload._budget_dropped !== true || payload.reason !== "audit_evidence_budget") {
      throw new InvalidManifest("invalid budget reference");
    }
    const manifestDigest = sha256(payload._manifest_sha256);
    const planId = safeIdentifier(links.plan_id);
    const contextRef = safeIdentifier(links.context_ref);
    return {
      eventId,
      signature: stableStringify(raw),
      view: {
        schemaVersion: "context-manifest-presentation/0.1",
        eventId,
        availability: "partial",
        state: "budget_dropped",
        auditId,
        planId,
        contextRef,
        planDigest: null,
        manifestDigest,
        counts: null,
        chunks: [],
        reasonCodes: ["audit_evidence_budget"],
        missingReasons: ["MANIFEST_DROPPED_BY_AUDIT_BUDGET"],
        sourceRefs: [
          { kind: "audit", id: auditId, traceId },
          { kind: "event", id: eventId, traceId },
        ],
      },
    };
  }
  return {
    eventId,
    signature: stableStringify(raw),
    view: parseFullManifest(manifest, auditId, eventId, links, runtime, traceId),
  };
}

function stableValue(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(stableValue);
  if (!value || typeof value !== "object") return value;
  return Object.fromEntries(
    Object.entries(value as UnknownRecord)
      .sort(([left], [right]) => left.localeCompare(right))
      .map(([key, item]) => [key, stableValue(item)]),
  );
}

function stableStringify(value: unknown): string {
  return JSON.stringify(stableValue(value));
}

function placeholder(
  eventId: string,
  traceId: string,
  state: ContextManifestViewModel["state"],
  reason: string,
): ContextManifestViewModel {
  return {
    schemaVersion: "context-manifest-presentation/0.1",
    eventId,
    availability: state === "missing" ? "unavailable" : "partial",
    state,
    auditId: null,
    planId: null,
    contextRef: null,
    planDigest: null,
    manifestDigest: null,
    counts: null,
    chunks: [],
    reasonCodes: [],
    missingReasons: [reason],
    sourceRefs: [{ kind: "event", id: eventId, traceId }],
  };
}

function projectionAvailability(values: readonly ContextManifestViewModel[]): Availability {
  if (!values.length) return "not_applicable";
  if (values.every((value) => value.availability === "recorded")) return "recorded";
  if (values.every((value) => value.availability === "unavailable")) return "unavailable";
  return "partial";
}

export function projectContextManifests(input: {
  traceId: string;
  events: readonly NormalizedAuditEvidence[];
  auditWindowTruncated: boolean;
}): ContextManifestProjection {
  const contextEventIds = new Set(
    input.events.flatMap((event) =>
      event.eventType === "context_assembled" && event.eventId ? [event.eventId] : [],
    ),
  );
  const candidatesByEventId = new Map<string, ParsedCarrier[]>();
  const invalidByEventId = new Set<string>();
  const warnings: SupervisionWarning[] = [];

  for (const event of input.events) {
    if (
      event.recordType !== "runtime_observation" ||
      event.eventType !== "context_manifest_recorded"
    ) {
      continue;
    }
    const linkedEventId = event.eventId;
    if (!linkedEventId || !contextEventIds.has(linkedEventId)) {
      warnings.push({
        code: "correlation_conflict",
        severity: "warning",
        message: "Context Manifest 未唯一关联当前 Trace 中的 context_assembled 事件。",
        sourceRefs: [{ kind: "audit", id: event.auditId, traceId: input.traceId }],
      });
      continue;
    }
    try {
      const parsed = parseCarrier(event, input.traceId);
      const candidates = candidatesByEventId.get(parsed.eventId) ?? [];
      candidates.push(parsed);
      candidatesByEventId.set(parsed.eventId, candidates);
    } catch {
      invalidByEventId.add(linkedEventId);
      warnings.push({
        code: "unsupported_contract",
        severity: "warning",
        message: `Context 事件 ${linkedEventId} 的 Manifest 不符合已知严格契约，未展示其原始载荷。`,
        sourceRefs: [{ kind: "audit", id: event.auditId, traceId: input.traceId }],
      });
    }
  }

  const entries: Array<[string, ContextManifestViewModel]> = [];
  for (const eventId of [...contextEventIds].sort()) {
    const candidates = candidatesByEventId.get(eventId) ?? [];
    const signatures = new Set(candidates.map((candidate) => candidate.signature));
    if (invalidByEventId.has(eventId) && candidates.length === 0) {
      entries.push([
        eventId,
        placeholder(eventId, input.traceId, "invalid", "CONTEXT_MANIFEST_SCHEMA_INVALID"),
      ]);
      continue;
    }
    if (invalidByEventId.has(eventId) || signatures.size > 1) {
      entries.push([
        eventId,
        placeholder(
          eventId,
          input.traceId,
          "correlation_conflict",
          "CONTEXT_MANIFEST_CORRELATION_CONFLICT",
        ),
      ]);
      warnings.push({
        code: "correlation_conflict",
        severity: "warning",
        message: `Context 事件 ${eventId} 存在不一致的 Manifest 证据，冲突载荷不会展示。`,
        sourceRefs: [{ kind: "event", id: eventId, traceId: input.traceId }],
      });
      continue;
    }
    if (candidates.length) {
      entries.push([eventId, candidates[0]!.view]);
      continue;
    }
    entries.push([
      eventId,
      input.auditWindowTruncated
        ? placeholder(
            eventId,
            input.traceId,
            "window_truncated",
            "CONTEXT_MANIFEST_OUTSIDE_AUDIT_WINDOW",
          )
        : placeholder(eventId, input.traceId, "missing", "CONTEXT_MANIFEST_NOT_RECORDED"),
    ]);
  }
  if (input.auditWindowTruncated && contextEventIds.size) {
    warnings.push({
      code: "window_truncated",
      severity: "warning",
      message: "审计窗口已截断；缺失的 Context Manifest 可能位于当前窗口之外。",
      sourceRefs: [],
    });
  }
  const contextManifestByEventId = Object.fromEntries(entries);
  return {
    contextManifestByEventId,
    availability: projectionAvailability(Object.values(contextManifestByEventId)),
    warnings,
  };
}
