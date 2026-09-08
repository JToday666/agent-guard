import type {
  GuardEvent,
  GuardEvaluationResponse,
  JsonObject,
} from "../types.js";
import {
  freezeProductValue,
  snapshotProductJson,
  productActionError,
} from "../mapping/product-events.js";
import { restrictedCanonicalJson, restrictedDigest } from "./canonical.js";
import type {
  ProductContextConsumer,
  ProductContextSource,
  ProductPreparedContext,
} from "./product-content-types.js";

export type ProductContextExpectation = Readonly<{
  scopeDigest: string;
  taskSummary: string;
}>;
const PLAN_KEYS =
  "schema_version plan_id event_id scope_digest runtime context_ref chunks transformations excluded_chunk_ids reason_codes evidence_refs plan_digest";
const CHUNK_KEYS =
  "schema_version chunk_id scope_digest context_ref source_ref source_type compartment trust fact_authority taints content_digest content_preview instruction_like sensitive transform_state sequence evidence_refs";
const TRANSFORM_KEYS =
  "transformation_id chunk_id action input_digest output_digest mechanism_id mechanism_version declassification_id reason_codes evidence_refs";
const ID = /^[A-Za-z0-9][A-Za-z0-9._:/-]{0,511}$/u;
const SHA = /^sha256:[0-9a-f]{64}$/u;
const SCOPE = /^(?:sha256|hmac-sha256):[0-9a-f]{64}$/u;
const TAINTS = new Set([
  "UNTRUSTED",
  "EXTERNAL_INSTRUCTION",
  "SENSITIVE",
  "CREDENTIAL",
  "PERSISTENT_UNTRUSTED",
]);
const SOURCES = new Set([
  "user",
  "runtime",
  "model",
  "memory",
  "web",
  "rag",
  "email",
  "tool_result",
  "mcp",
  "file",
]);
const EXCLUDED = new Set(["excluded", "quarantined"]);

function fail(): never {
  return productActionError("product_context_plan_invalid");
}
function object(value: unknown): JsonObject {
  if (!value || typeof value !== "object" || Array.isArray(value)) fail();
  return value as JsonObject;
}
function keys(value: JsonObject, expected: string): void {
  if (
    Object.keys(value).sort().join(" ") !== expected.split(" ").sort().join(" ")
  )
    fail();
}
function identity(value: unknown): string {
  if (typeof value !== "string" || !ID.test(value)) fail();
  return value;
}
function texts(value: unknown, max = 256): string[] {
  if (!Array.isArray(value) || value.length > max) fail();
  const result = value.map((x) => {
    if (typeof x !== "string" || !x || x.length > 512) fail();
    return x;
  });
  if (new Set(result).size !== result.length) fail();
  return result;
}
function refs(value: unknown): void {
  if (!Array.isArray(value) || value.length > 32) fail();
  const ids = new Set<string>();
  for (const raw of value) {
    const ref = object(raw);
    keys(
      ref,
      "ref_id kind record_type record_id json_pointer digest redaction_state",
    );
    const id = identity(ref.ref_id);
    if (ids.has(id)) fail();
    ids.add(id);
    identity(ref.record_id);
    identity(ref.record_type);
    identity(ref.kind);
    if (
      typeof ref.digest !== "string" ||
      !SCOPE.test(ref.digest) ||
      !["none", "redacted", "summary_only"].includes(
        String(ref.redaction_state),
      ) ||
      (ref.json_pointer !== null &&
        (typeof ref.json_pointer !== "string" ||
          !ref.json_pointer.startsWith("/") ||
          ref.json_pointer.length > 1024))
    )
      fail();
  }
}
function annotate(
  content: unknown,
  sourceRef: string,
  taints: string[],
): string {
  const body = (
    typeof content === "string" ? content : restrictedCanonicalJson(content)
  )
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;");
  return `<agentguard-context authority="evidence-only" source_ref="${sourceRef}" taints="${taints.join(",") || "UNTRUSTED"}">\n${body}\n</agentguard-context>`;
}

/** The caller supplies the TaskIngress identity, never a value inferred from the plan. */
export function createProductContextConsumer(
  expected: ProductContextExpectation,
): ProductContextConsumer {
  const fixed = freezeProductValue(
    snapshotProductJson(expected),
  ) as ProductContextExpectation;
  if (
    !SCOPE.test(fixed.scopeDigest) ||
    typeof fixed.taskSummary !== "string" ||
    !fixed.taskSummary
  )
    fail();
  return (event, evaluation, sources) =>
    prepareProductContext(event, evaluation, sources, fixed);
}

/** Reconstruct the only permitted model messages from complete local source bytes. */
export function prepareProductContext(
  event: GuardEvent,
  evaluation: GuardEvaluationResponse,
  sources: readonly ProductContextSource[],
  expected: ProductContextExpectation,
): ProductPreparedContext {
  try {
    return prepare(event, evaluation, sources, expected);
  } catch {
    return fail();
  }
}
function prepare(
  eventInput: GuardEvent,
  evaluationInput: GuardEvaluationResponse,
  sourceInput: readonly ProductContextSource[],
  expected: ProductContextExpectation,
): ProductPreparedContext {
  const event = object(snapshotProductJson(eventInput));
  const evaluation = object(snapshotProductJson(evaluationInput));
  const sources = snapshotProductJson(sourceInput);
  const authority = object(evaluation.decision_authority);
  const decision = object(evaluation.decision);
  if (
    event.runtime !== "openclaw" ||
    event.event_type !== "context_assembled" ||
    authority.source !== "v21" ||
    authority.mode !== "active" ||
    authority.selection_basis !== "profile_all" ||
    authority.legacy_floor_applied !== false ||
    decision.decision !== "allow" ||
    !SCOPE.test(expected.scopeDigest) ||
    !expected.taskSummary
  )
    fail();
  const eventId = identity(event.event_id);
  const payload = object(event.payload),
    descriptors = payload.sources;
  if (
    !Array.isArray(sources) ||
    sources.length < 1 ||
    sources.length > 20 ||
    !Array.isArray(descriptors) ||
    descriptors.length !== sources.length ||
    Buffer.byteLength(restrictedCanonicalJson(sources)) > 64 * 1024
  )
    fail();
  const plan = object(evaluation.context_plan);
  keys(plan, PLAN_KEYS);
  const { plan_digest: suppliedDigest, ...projection } = plan;
  if (
    plan.schema_version !== "1.0" ||
    plan.event_id !== eventId ||
    plan.runtime !== "openclaw" ||
    plan.scope_digest !== expected.scopeDigest ||
    plan.context_ref !== `context:${eventId}` ||
    typeof suppliedDigest !== "string" ||
    !SHA.test(suppliedDigest) ||
    restrictedDigest(projection) !== suppliedDigest
  )
    fail();
  const planId = identity(plan.plan_id),
    contextRef = identity(plan.context_ref);
  texts(plan.reason_codes);
  refs(plan.evidence_refs);
  const excluded = new Set(texts(plan.excluded_chunk_ids));
  const chunks = plan.chunks;
  if (
    !Array.isArray(chunks) ||
    chunks.length !== sources.length ||
    !Array.isArray(plan.transformations)
  )
    fail();
  const byChunk = new Map<string, { state: string; digest: string }>();
  const sourceRefs = new Set<string>(),
    localIds = new Set<string>(),
    actualExcluded = new Set<string>();
  const messages: unknown[] = [],
    visibleSourceRefs: string[] = [];
  let taskCount = 0;
  for (let i = 0; i < sources.length; i++) {
    const source = object(sources[i]),
      descriptor = object(descriptors[i]),
      chunk = object(chunks[i]);
    const localId = identity(source.source_id);
    if (localIds.has(localId)) fail();
    localIds.add(localId);
    if (
      typeof source.source_type !== "string" ||
      !SOURCES.has(source.source_type) ||
      !["trusted", "untrusted", "unknown"].includes(
        String(source.source_trust),
      ) ||
      !["system", "user", "assistant", "tool"].includes(String(source.role)) ||
      source.content === undefined
    )
      fail();
    const digest = restrictedDigest(source.content);
    if (
      descriptor.sequence_index !== i ||
      descriptor.content_digest !== digest ||
      descriptor.source_id !== localId ||
      descriptor.source_type !== source.source_type ||
      descriptor.source_trust !== source.source_trust ||
      descriptor.role !== source.role ||
      descriptor.summary !==
        (typeof source.content === "string"
          ? source.content
          : restrictedCanonicalJson(source.content)) ||
      typeof descriptor.contains_instruction_like_text !== "boolean" ||
      typeof descriptor.contains_sensitive_data !== "boolean"
    )
      fail();
    keys(chunk, CHUNK_KEYS);
    const chunkId = identity(chunk.chunk_id),
      sourceRef = identity(chunk.source_ref);
    const expectedRef =
      source.source_type === "memory"
        ? `memory:${eventId}:${i}`
        : `source:${source.source_type}:${eventId}:${i}`;
    if (
      byChunk.has(chunkId) ||
      sourceRefs.has(sourceRef) ||
      sourceRef !== expectedRef ||
      chunk.schema_version !== "1.0" ||
      chunk.scope_digest !== expected.scopeDigest ||
      chunk.context_ref !== contextRef ||
      chunk.content_digest !== digest ||
      chunk.content_preview !== null ||
      chunk.source_type !== source.source_type ||
      typeof chunk.instruction_like !== "boolean" ||
      typeof chunk.sensitive !== "boolean"
    )
      fail();
    sourceRefs.add(sourceRef);
    const sequence = object(chunk.sequence);
    keys(sequence, "domain producer_binding_id value");
    if (
      sequence.domain !== "runtime" ||
      sequence.producer_binding_id !== "runtime:openclaw" ||
      sequence.value !== i
    )
      fail();
    const taints = texts(chunk.taints);
    if (taints.some((x) => !TAINTS.has(x))) fail();
    refs(chunk.evidence_refs);
    const state = String(chunk.transform_state),
      compartment = String(chunk.compartment);
    if (
      !["preserved", "annotated", "quarantined", "excluded"].includes(state) ||
      ![
        "authenticated_task",
        "trusted_runtime_fact",
        "untrusted_evidence",
        "memory_context",
        "model_derived",
      ].includes(compartment) ||
      !["trusted", "untrusted", "unknown"].includes(String(chunk.trust)) ||
      ![
        "authoritative",
        "trusted_claim",
        "untrusted_claim",
        "model_judgment",
      ].includes(String(chunk.fact_authority))
    )
      fail();
    byChunk.set(chunkId, { state, digest });
    const expectedCompartment =
      source.source_type === "user"
        ? "authenticated_task"
        : source.source_type === "runtime"
          ? EXCLUDED.has(state)
            ? "untrusted_evidence"
            : "trusted_runtime_fact"
          : source.source_type === "memory"
            ? "memory_context"
            : source.source_type === "model"
              ? "model_derived"
              : "untrusted_evidence";
    if (
      compartment !== expectedCompartment ||
      (descriptor.contains_instruction_like_text === true &&
        chunk.instruction_like !== true) ||
      (descriptor.contains_sensitive_data === true && chunk.sensitive !== true)
    )
      fail();
    if (EXCLUDED.has(state)) {
      if (
        source.source_type === "runtime" &&
        (chunk.trust !== "untrusted" ||
          chunk.fact_authority !== "untrusted_claim" ||
          !taints.includes("UNTRUSTED"))
      )
        fail();
      actualExcluded.add(chunkId);
      continue;
    }
    if (
      excluded.has(chunkId) ||
      source.role !== "user" ||
      chunk.sensitive === true ||
      taints.includes("SENSITIVE") ||
      taints.includes("CREDENTIAL") ||
      taints.includes("EXTERNAL_INSTRUCTION") ||
      compartment === "model_derived" ||
      compartment === "trusted_runtime_fact"
    )
      fail();
    if (compartment === "authenticated_task") {
      if (
        state !== "preserved" ||
        source.content !== expected.taskSummary ||
        chunk.trust !== "trusted" ||
        chunk.fact_authority !== "authoritative" ||
        taints.length ||
        ++taskCount !== 1
      )
        fail();
    } else if (compartment === "untrusted_evidence") {
      if (
        state !== "annotated" ||
        chunk.trust !== "untrusted" ||
        chunk.fact_authority !== "untrusted_claim" ||
        chunk.instruction_like === true ||
        !taints.includes("UNTRUSTED")
      )
        fail();
    } else if (compartment === "memory_context") {
      if (
        source.source_trust !== "trusted" ||
        state !== "preserved" ||
        chunk.trust !== "trusted" ||
        chunk.fact_authority !== "trusted_claim" ||
        taints.length
      )
        fail();
    } else fail();
    messages.push({
      role: "user",
      content:
        state === "annotated"
          ? annotate(source.content, sourceRef, taints)
          : source.content,
    });
    visibleSourceRefs.push(sourceRef);
  }
  if (
    taskCount !== 1 ||
    excluded.size !== actualExcluded.size ||
    [...excluded].some((x) => !actualExcluded.has(x))
  )
    fail();
  const transformed = new Set<string>(),
    transformationIds = new Set<string>();
  const actionByState: Record<string, string> = {
    annotated: "annotate",
    quarantined: "quarantine",
    excluded: "exclude",
  };
  for (const raw of plan.transformations) {
    const tr = object(raw);
    keys(tr, TRANSFORM_KEYS);
    const trId = identity(tr.transformation_id),
      chunkId = identity(tr.chunk_id),
      entry = byChunk.get(chunkId);
    if (
      transformationIds.has(trId) ||
      transformed.has(chunkId) ||
      !entry ||
      tr.action !== actionByState[entry.state] ||
      tr.input_digest !== entry.digest ||
      tr.output_digest !==
        (entry.state === "annotated" ? entry.digest : null) ||
      tr.mechanism_id !== "ct-context-builder" ||
      tr.mechanism_version !== "1.0" ||
      tr.declassification_id !== null
    )
      fail();
    texts(tr.reason_codes);
    refs(tr.evidence_refs);
    transformationIds.add(trId);
    transformed.add(chunkId);
  }
  if (
    [...byChunk].some(
      ([id, entry]) => (entry.state !== "preserved") !== transformed.has(id),
    )
  )
    fail();
  return freezeProductValue({
    messages,
    planId,
    planDigest: suppliedDigest,
    contextRef,
    visibleSourceRefs,
  });
}
