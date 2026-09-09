// Synthetic authority/plan metadata exercises the production context reader.
// Real Host/API composition remains the separate HTTP integration evidence.
import assert from "node:assert/strict";
import test from "node:test";
import {
  buildProductContextEvent,
  productMemorySourceId,
} from "../dist/mapping/product-content-events.js";
import { prepareProductContext } from "../dist/runtime/product-context-plan.js";
import { restrictedDigest } from "../dist/runtime/canonical.js";

const SCOPE = `sha256:${"a".repeat(64)}`;
const TASK = "Read the isolated memory entry without promoting its trust.";

function fixture(namespace = "/workspace/runtime/memory.sqlite", key = "fixture") {
  const sources = [
    {
      source_id: "user:task_context",
      source_type: "user",
      source_trust: "trusted",
      role: "user",
      content: TASK,
    },
    {
      source_id: productMemorySourceId(namespace, key),
      source_type: "memory",
      source_trust: "untrusted",
      role: "user",
      content: JSON.stringify({ key, value: "excluded-memory-canary" }),
    },
  ];
  const event = structuredClone(
    buildProductContextEvent(
      {
        agentId: "main",
        sessionKey: "agent:main:context",
        taskId: "task_context",
        userTask: TASK,
        traceId: "trace_context",
        provider: "controlled",
        modelId: "local",
      },
      sources,
    ),
  );
  const chunks = sources.map((source, index) => ({
    schema_version: "1.0",
    chunk_id: `chunk_${index}`,
    scope_digest: SCOPE,
    context_ref: `context:${event.event_id}`,
    source_ref:
      index === 0
        ? `source:user:${event.event_id}:0`
        : `memory:${event.event_id}:1`,
    source_type: source.source_type,
    compartment: index === 0 ? "authenticated_task" : "memory_context",
    trust: index === 0 ? "trusted" : "unknown",
    fact_authority: index === 0 ? "authoritative" : "untrusted_claim",
    taints: index === 0 ? [] : ["UNTRUSTED", "PERSISTENT_UNTRUSTED"],
    content_digest: restrictedDigest(source.content),
    content_preview: null,
    instruction_like: false,
    sensitive: false,
    transform_state: index === 0 ? "preserved" : "excluded",
    sequence: {
      domain: "runtime",
      producer_binding_id: "runtime:openclaw",
      value: index,
    },
    evidence_refs: [],
  }));
  const plan = {
    schema_version: "1.0",
    plan_id: "plan_context",
    event_id: event.event_id,
    scope_digest: SCOPE,
    runtime: "openclaw",
    context_ref: `context:${event.event_id}`,
    chunks,
    transformations: [
      {
        transformation_id: "transform_memory",
        chunk_id: chunks[1].chunk_id,
        action: "exclude",
        input_digest: chunks[1].content_digest,
        output_digest: null,
        mechanism_id: "ct-context-builder",
        mechanism_version: "1.0",
        declassification_id: null,
        reason_codes: ["MEMORY_NOT_ACTIVE_TRACE_SAFE"],
        evidence_refs: [],
      },
    ],
    excluded_chunk_ids: [chunks[1].chunk_id],
    reason_codes: ["MEMORY_NOT_ACTIVE_TRACE_SAFE"],
    evidence_refs: [],
  };
  const evaluation = {
    decision: { decision: "allow" },
    decision_authority: {
      source: "v21",
      mode: "active",
      selection_basis: "profile_all",
      legacy_floor_applied: false,
    },
    context_plan: { ...plan, plan_digest: restrictedDigest(plan) },
  };
  return {
    event,
    evaluation,
    sources,
    expected: { scopeDigest: SCOPE, taskSummary: TASK },
  };
}
function consume(f) {
  return prepareProductContext(f.event, f.evaluation, f.sources, f.expected);
}
function resign(f) {
  const { plan_digest: _digest, ...plan } = f.evaluation.context_plan;
  f.evaluation.context_plan.plan_digest = restrictedDigest(plan);
}

for (const [namespace, key] of [
  ["/workspace/runtime/memory.sqlite", "fixture"],
  ["/workspace/记忆\\archive/memory.sqlite", "段/1"],
])
  for (const state of ["excluded", "quarantined"])
    test(`canonical memory segments ${namespace} remain absent when ${state}`, () => {
      const f = fixture(namespace, key);
      f.evaluation.context_plan.chunks[1].transform_state = state;
      f.evaluation.context_plan.transformations[0].action =
        state === "excluded" ? "exclude" : "quarantine";
      resign(f);
      const original = JSON.stringify(f);
      const result = consume(f);
      assert.deepEqual(JSON.parse(JSON.stringify(result.messages)), [
        { role: "user", content: TASK },
      ]);
      assert.deepEqual(result.visibleSourceRefs, [
        f.evaluation.context_plan.chunks[0].source_ref,
      ]);
      assert.equal(
        JSON.stringify(result).includes("excluded-memory-canary"),
        false,
      );
      assert.equal(JSON.stringify(f), original);
    });

for (const malformed of [
  "memory:/namespace/key",
  "memory://namespace",
  "memory:///key",
  "memory://namespace/",
  "memory://namespace/key/extra",
  "memory://namespace/key\\",
  "memory://namespace\\q/key",
  "memory://namespace/\u0000key",
  `memory://${"n".repeat(4097)}/key`,
  `memory://namespace/${"k".repeat(257)}`,
])
  test(`malformed memory identity is rejected (${malformed.length} bytes)`, () => {
    const f = fixture();
    f.sources[1].source_id = malformed;
    f.event.payload.sources[1].source_id = malformed;
    assert.throws(() => consume(f), /product_context_plan_invalid/u);
  });

for (const mutation of [
  "nonmemory-backslash",
  "descriptor-id",
  "descriptor-digest",
  "source-ref",
  "scope",
  "chunk-digest",
  "exclusion-list",
  "transformation",
  "promote-to-visible",
])
  test(`memory identity support preserves ${mutation} rejection`, () => {
    const f = fixture(),
      plan = f.evaluation.context_plan;
    if (mutation === "nonmemory-backslash") {
      f.sources[0].source_id = "user:task\\other";
      f.event.payload.sources[0].source_id = f.sources[0].source_id;
    }
    if (mutation === "descriptor-id")
      f.event.payload.sources[1].source_id = productMemorySourceId(
        "other",
        "fixture",
      );
    if (mutation === "descriptor-digest")
      f.event.payload.sources[1].content_digest = `sha256:${"b".repeat(64)}`;
    if (mutation === "source-ref") plan.chunks[1].source_ref = "memory:other:1";
    if (mutation === "scope") plan.scope_digest = `sha256:${"b".repeat(64)}`;
    if (mutation === "chunk-digest")
      plan.chunks[1].content_digest = `sha256:${"b".repeat(64)}`;
    if (mutation === "exclusion-list") plan.excluded_chunk_ids = [];
    if (mutation === "transformation")
      plan.transformations[0].output_digest = plan.chunks[1].content_digest;
    if (mutation === "promote-to-visible") {
      plan.chunks[1].transform_state = "preserved";
      plan.chunks[1].trust = "trusted";
      plan.chunks[1].fact_authority = "trusted_claim";
      plan.chunks[1].taints = [];
      plan.excluded_chunk_ids = [];
      plan.transformations = [];
    }
    resign(f);
    assert.throws(() => consume(f), /product_context_plan_invalid/u);
  });
