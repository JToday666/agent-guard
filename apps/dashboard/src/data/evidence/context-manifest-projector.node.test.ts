import assert from "node:assert/strict";
import test from "node:test";

import { mapAuditEvent } from "../../api/guard-api-mappers.ts";
import type { GuardAuditEventDto } from "../../api/guard-api-types.ts";
import type { NormalizedAuditEvidence } from "../../types/dashboard.ts";
import { buildTraceEvidenceViewModel } from "./trace-evidence.ts";
import { projectContextManifests } from "./context-manifest-projector.ts";

const TRACE_ID = "trace_manifest_1";
const EVENT_ID = "event_context_1";
const AUDIT_ID = `audit_context_manifest_${"a".repeat(64)}`;
const digest = (character: string) => `sha256:${character.repeat(64)}`;

function normalized(
  fields: Pick<NormalizedAuditEvidence, "auditId" | "eventId" | "eventType" | "recordType" | "raw">,
): NormalizedAuditEvidence {
  return fields as NormalizedAuditEvidence;
}

function contextEvent(raw: unknown = {}): NormalizedAuditEvidence {
  return normalized({
    auditId: "audit_policy_context_1",
    eventId: EVENT_ID,
    eventType: "context_assembled",
    recordType: "policy_evaluation",
    raw,
  });
}

function fullManifest() {
  return {
    schema_version: "1.0",
    plan_id: "context_plan_1",
    event_id: EVENT_ID,
    scope_digest: digest("b"),
    runtime: "langgraph",
    context_ref: "context_ref_1",
    plan_digest: digest("c"),
    manifest_digest: digest("d"),
    counts: {
      total: 2,
      returned: 2,
      included: 1,
      excluded: 1,
      quarantined: 1,
      sensitive: 0,
      untrusted: 1,
      by_source_type: { file: 1, web: 1 },
    },
    chunks: [
      {
        schema_version: "1.0",
        chunk_id: "chunk_task_1",
        scope_digest: digest("b"),
        context_ref: "context_ref_1",
        source_ref: "source_task_1",
        source_type: "file",
        compartment: "authenticated_task",
        trust: "trusted",
        fact_authority: "authoritative",
        taints: [],
        content_digest: digest("e"),
        content_preview: "Quarterly total 42",
        instruction_like: false,
        sensitive: false,
        transform_state: "preserved",
        sequence: {
          domain: "runtime",
          producer_binding_id: "runtime:langgraph",
          value: 0,
        },
        evidence_refs: [],
      },
      {
        schema_version: "1.0",
        chunk_id: "chunk_web_1",
        scope_digest: digest("b"),
        context_ref: "context_ref_1",
        source_ref: "source_web_1",
        source_type: "web",
        compartment: "untrusted_evidence",
        trust: "untrusted",
        fact_authority: "untrusted_claim",
        taints: ["UNTRUSTED", "EXTERNAL_INSTRUCTION"],
        content_digest: digest("f"),
        content_preview: null,
        instruction_like: true,
        sensitive: false,
        transform_state: "quarantined",
        sequence: {
          domain: "runtime",
          producer_binding_id: "runtime:langgraph",
          value: 1,
        },
        evidence_refs: [],
      },
    ],
    transformations: [
      {
        transformation_id: "transformation_web_1",
        chunk_id: "chunk_web_1",
        action: "quarantine",
        input_digest: digest("f"),
        output_digest: null,
        mechanism_id: "ct-context-builder",
        mechanism_version: "1.0",
        declassification_id: null,
        reason_codes: ["external_instruction"],
        evidence_refs: [],
      },
    ],
    excluded_chunk_ids: ["chunk_web_1"],
    reason_codes: ["external_instruction_quarantined"],
    evidence_refs: [],
    completeness: { status: "complete", truncated: false, omitted_digest: null },
  };
}

function carrier(payload: unknown = fullManifest(), auditId = AUDIT_ID): NormalizedAuditEvidence {
  const raw = carrierDto(payload, auditId);
  return normalized({
    auditId,
    eventId: EVENT_ID,
    eventType: "context_manifest_recorded",
    recordType: "runtime_observation",
    raw,
  });
}

function carrierDto(payload: unknown = fullManifest(), auditId = AUDIT_ID) {
  return {
    audit_id: auditId,
    schema_version: "0.4",
    record_type: "runtime_observation",
    trace_id: TRACE_ID,
    case_id: null,
    runtime: "langgraph",
    timestamp: "2026-08-17T08:00:00Z",
    stage: "context_build",
    event_type: "context_manifest_recorded",
    attack_type: null,
    is_malicious: null,
    summary: "Bounded context manifest recorded",
    decision: null,
    risk_score: null,
    severity: null,
    blocked: null,
    resource_targets: [],
    rule_hits: [],
    reason: "context_manifest_projection",
    links: {
      event_id: EVENT_ID,
      plan_id: "context_plan_1",
      context_ref: "context_ref_1",
    },
    latency_ms: null,
    metadata: {
      contract: "context-manifest-audit/1.0",
      producer: "guard_api_context_builder",
      producer_binding_id: "guard-api:context-builder:1",
    },
    evidence: { context_manifest: payload },
  } as GuardAuditEventDto;
}

function liveMappedEvents(payload: unknown): NormalizedAuditEvidence[] {
  const contextDto = {
    audit_id: "audit_policy_context_1",
    schema_version: "0.4",
    record_type: "policy_evaluation",
    trace_id: TRACE_ID,
    case_id: null,
    runtime: "langgraph",
    timestamp: "2026-08-17T07:59:59Z",
    stage: "context_build",
    event_type: "context_assembled",
    attack_type: null,
    is_malicious: null,
    summary: "Context assembled",
    decision: "allow",
    risk_score: 0,
    severity: "low",
    blocked: false,
    resource_targets: [],
    rule_hits: [],
    reason: "context_ready",
    links: { decision_id: "decision_context_1", event_id: EVENT_ID },
    latency_ms: 1,
    metadata: {},
  } as GuardAuditEventDto;
  const rows = [mapAuditEvent(contextDto), mapAuditEvent(carrierDto(payload))];
  return buildTraceEvidenceViewModel(TRACE_ID, rows, [], null).events;
}

test("strictly projects a full manifest by the exact context event link", () => {
  const result = projectContextManifests({
    traceId: TRACE_ID,
    events: [contextEvent(), carrier()],
    auditWindowTruncated: false,
  });

  assert.equal(result.availability, "recorded");
  const manifest = result.contextManifestByEventId[EVENT_ID]!;
  assert.equal(manifest.state, "recorded");
  assert.equal(manifest.planId, "context_plan_1");
  assert.equal(manifest.contextRef, "context_ref_1");
  assert.equal(manifest.planDigest, digest("c"));
  assert.equal(manifest.manifestDigest, digest("d"));
  assert.deepEqual(manifest.counts, {
    total: 2,
    returned: 2,
    included: 1,
    excluded: 1,
    quarantined: 1,
    sensitive: 0,
    untrusted: 1,
    bySourceType: { file: 1, web: 1 },
  });
  assert.deepEqual(
    manifest.chunks.map((chunk) => ({
      disposition: chunk.disposition,
      preview: chunk.safePreview,
      transform: chunk.transformationAction,
    })),
    [
      { disposition: "included", preview: "Quarterly total 42", transform: null },
      { disposition: "quarantined", preview: null, transform: "quarantine" },
    ],
  );
});

test("projects the typed audit-budget reference as partial without guessing chunks", () => {
  const result = projectContextManifests({
    traceId: TRACE_ID,
    events: [
      contextEvent(),
      carrier({
        _budget_dropped: true,
        _manifest_sha256: digest("d"),
        reason: "audit_evidence_budget",
      }),
    ],
    auditWindowTruncated: false,
  });

  const manifest = result.contextManifestByEventId[EVENT_ID]!;
  assert.equal(result.availability, "partial");
  assert.equal(manifest.state, "budget_dropped");
  assert.equal(manifest.manifestDigest, digest("d"));
  assert.equal(manifest.counts, null);
  assert.deepEqual(manifest.chunks, []);
});

test("distinguishes a missing manifest from a truncated audit window", () => {
  const missing = projectContextManifests({
    traceId: TRACE_ID,
    events: [contextEvent()],
    auditWindowTruncated: false,
  }).contextManifestByEventId[EVENT_ID]!;
  const truncated = projectContextManifests({
    traceId: TRACE_ID,
    events: [contextEvent()],
    auditWindowTruncated: true,
  }).contextManifestByEventId[EVENT_ID]!;

  assert.deepEqual([missing.state, missing.availability], ["missing", "unavailable"]);
  assert.deepEqual([truncated.state, truncated.availability], ["window_truncated", "partial"]);
});

test("a conflicting replay wins over displayable manifest content", () => {
  const drifted = structuredClone(fullManifest());
  drifted.manifest_digest = digest("9");
  const result = projectContextManifests({
    traceId: TRACE_ID,
    events: [
      contextEvent(),
      carrier(),
      carrier(drifted, `audit_context_manifest_${"9".repeat(64)}`),
    ],
    auditWindowTruncated: false,
  });

  const manifest = result.contextManifestByEventId[EVENT_ID]!;
  assert.equal(manifest.state, "correlation_conflict");
  assert.equal(manifest.availability, "partial");
  assert.deepEqual(manifest.chunks, []);
  assert.equal(manifest.manifestDigest, null);
});

test("unknown schema values degrade without exposing raw payloads", () => {
  const invalid = structuredClone(fullManifest());
  invalid.chunks[0]!.compartment = "future_authority";
  invalid.chunks[0]!.content_preview = "credential=must-never-render";
  const result = projectContextManifests({
    traceId: TRACE_ID,
    events: [contextEvent(), carrier(invalid)],
    auditWindowTruncated: false,
  });

  const manifest = result.contextManifestByEventId[EVENT_ID]!;
  assert.equal(manifest.state, "invalid");
  assert.equal(manifest.availability, "partial");
  assert.doesNotMatch(JSON.stringify(manifest), /must-never-render/);
});

test("accepts the live sensitive-exclusion reason code without displaying its digest", () => {
  const payload = fullManifest();
  const sensitive = payload.chunks[0]!;
  sensitive.sensitive = true;
  sensitive.taints = ["SENSITIVE", "CREDENTIAL"];
  sensitive.transform_state = "excluded";
  sensitive.content_preview = null;
  sensitive.source_ref = "credential";
  payload.counts.included = 0;
  payload.counts.excluded = 2;
  payload.counts.sensitive = 1;
  payload.excluded_chunk_ids = ["chunk_task_1", "chunk_web_1"];
  payload.transformations.unshift({
    transformation_id: "transformation_task_1",
    chunk_id: "chunk_task_1",
    action: "exclude",
    input_digest: digest("e"),
    output_digest: null,
    mechanism_id: "ct-context-builder",
    mechanism_version: "1.0",
    declassification_id: null,
    reason_codes: ["SENSITIVE_OR_CREDENTIAL"],
    evidence_refs: [],
  });

  const manifest = projectContextManifests({
    traceId: TRACE_ID,
    events: liveMappedEvents(payload),
    auditWindowTruncated: false,
  }).contextManifestByEventId[EVENT_ID]!;

  assert.equal(manifest.availability, "recorded");
  assert.equal(manifest.chunks[0]!.disposition, "excluded");
  assert.deepEqual(manifest.chunks[0]!.reasonCodes, ["SENSITIVE_OR_CREDENTIAL"]);
  assert.equal(manifest.chunks[0]!.contentDigest, null);
  assert.equal(manifest.chunks[0]!.safePreview, null);
});

test("never infers a manifest from context ingress or Provenance-like raw evidence", () => {
  const result = projectContextManifests({
    traceId: TRACE_ID,
    events: [contextEvent({ evidence: { context_manifest: fullManifest() } })],
    auditWindowTruncated: false,
  });

  assert.equal(result.contextManifestByEventId[EVENT_ID]!.state, "missing");
});

test("drops credential-like preview values while preserving safe artifact sha256", () => {
  const payload = fullManifest();
  payload.chunks[0]!.content_preview = `opaque=agt_tok_${"1".repeat(32)}`;
  const hidden = projectContextManifests({
    traceId: TRACE_ID,
    events: [contextEvent(), carrier(payload)],
    auditWindowTruncated: false,
  }).contextManifestByEventId[EVENT_ID]!;
  assert.equal(hidden.chunks[0]!.safePreview, null);
  assert.doesNotMatch(JSON.stringify(hidden), /agt_tok_/);

  const safePayload = fullManifest();
  safePayload.chunks[0]!.content_preview = `artifact=${digest("8")}`;
  const safe = projectContextManifests({
    traceId: TRACE_ID,
    events: [contextEvent(), carrier(safePayload)],
    auditWindowTruncated: false,
  }).contextManifestByEventId[EVENT_ID]!;
  assert.equal(safe.chunks[0]!.safePreview, `artifact=${digest("8")}`);
});
