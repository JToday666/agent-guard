import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { createProductContextConsumer } from "../../packages/agentguard-openclaw-plugin/dist/runtime/product-context-plan.js";
import { restrictedDigest } from "../../packages/agentguard-openclaw-plugin/dist/runtime/canonical.js";

const fixture = JSON.parse(readFileSync(0, "utf8"));
let passed = 0;
function evaluate(input) {
  return createProductContextConsumer(input.expected)(
    input.event,
    input.evaluation,
    input.sources,
  );
}
function rehash(input) {
  const { plan_digest, ...projection } = input.evaluation.context_plan;
  input.evaluation.context_plan.plan_digest = restrictedDigest(projection);
}
try {
  const safe = evaluate(fixture);
  assert.equal(safe.messages.length, 2);
  assert.deepEqual(safe.messages[0], {
    role: "user",
    content: fixture.expected.taskSummary,
  });
  assert.match(safe.messages[1].content, /A &lt; B and B &gt; C &amp; C\./u);
  assert.equal(
    safe.messages[1].content.match(/<\/agentguard-context>/gu).length,
    1,
  );
  for (const index of [2, 3, 4])
    assert(!JSON.stringify(safe).includes(fixture.sources[index].content));
  assert(Object.isFrozen(safe) && Object.isFrozen(safe.messages[0]));
  passed++;
  const mutations = [
    (x) => {
      x.expected.scopeDigest = "sha256:" + "b".repeat(64);
    },
    (x) => {
      x.expected.taskSummary = "A different authenticated task";
    },
    (x) => {
      x.event.runtime = "langgraph";
    },
    (x) => {
      x.event.event_type = "model_input_prepared";
    },
    (x) => {
      x.evaluation.decision_authority.source = "current";
    },
    (x) => {
      x.evaluation.decision_authority.mode = "shadow";
    },
    (x) => {
      x.evaluation.decision_authority.legacy_floor_applied = true;
    },
    (x) => {
      x.evaluation.decision.decision = "ask";
    },
    (x) => {
      x.evaluation.context_plan.runtime = "langgraph";
    },
    (x) => {
      x.evaluation.context_plan.event_id = "evt:other";
    },
    (x) => {
      x.evaluation.context_plan.context_ref = "context:other";
    },
    (x) => {
      x.evaluation.context_plan.scope_digest = "sha256:" + "b".repeat(64);
    },
    (x) => {
      x.evaluation.context_plan.unknown_field = true;
    },
    (x) => {
      x.evaluation.context_plan.chunks.pop();
    },
    (x) => {
      x.evaluation.context_plan.chunks.reverse();
    },
    (x) => {
      x.evaluation.context_plan.chunks[1].content_digest =
        "sha256:" + "a".repeat(64);
    },
    (x) => {
      x.evaluation.context_plan.chunks[1].source_ref = "source:runtime:other";
    },
    (x) => {
      x.evaluation.context_plan.chunks[1].sequence.producer_binding_id =
        "runtime:langgraph";
    },
    (x) => {
      x.evaluation.context_plan.chunks[1].sequence.value = true;
    },
    (x) => {
      x.evaluation.context_plan.chunks[1].content_preview = "Injected preview";
    },
    (x) => {
      x.evaluation.context_plan.chunks[1].compartment = "authenticated_task";
    },
    (x) => {
      x.evaluation.context_plan.chunks[1].taints = [];
    },
    (x) => {
      // A rehashed plan may not hide an instruction taint behind a false flag.
      x.evaluation.context_plan.chunks[1].taints.push("EXTERNAL_INSTRUCTION");
    },
    (x) => {
      x.evaluation.context_plan.chunks[1].trust = "trusted";
    },
    (x) => {
      x.evaluation.context_plan.transformations.pop();
    },
    (x) => {
      x.evaluation.context_plan.transformations.push(
        x.evaluation.context_plan.transformations[0],
      );
    },
    (x) => {
      x.evaluation.context_plan.transformations[0].declassification_id =
        "declass:caller";
    },
    (x) => {
      x.evaluation.context_plan.transformations[0].output_digest = null;
    },
    (x) => {
      x.evaluation.context_plan.excluded_chunk_ids.pop();
    },
    (x) => {
      x.sources[0].role = x.event.payload.sources[0].role = "system";
    },
    (x) => {
      x.sources[1].content = "Edited after evaluate";
    },
    (x) => {
      x.event.payload.sources[1].summary = "Truncated preview";
    },
    (x) => {
      x.event.payload.sources[1].sequence_index = 0;
    },
    (x) => {
      x.evaluation.context_plan.chunks[2].transform_state = "preserved";
    },
    (x) => {
      const plan = x.evaluation.context_plan;
      const chunk = plan.chunks[2];
      Object.assign(chunk, {
        transform_state: "preserved",
        trust: "trusted",
        fact_authority: "trusted_claim",
        taints: [],
      });
      plan.excluded_chunk_ids = plan.excluded_chunk_ids.filter(
        (id) => id !== chunk.chunk_id,
      );
      plan.transformations = plan.transformations.filter(
        (item) => item.chunk_id !== chunk.chunk_id,
      );
    },
    (x) => {
      x.evaluation.context_plan.chunks[3].transform_state = "preserved";
    },
    (x) => {
      const plan = x.evaluation.context_plan;
      const chunk = plan.chunks[2];
      Object.assign(chunk, {
        transform_state: "annotated",
        trust: "untrusted",
        fact_authority: "untrusted_claim",
        taints: ["UNTRUSTED"],
      });
      plan.excluded_chunk_ids = plan.excluded_chunk_ids.filter(
        (id) => id !== chunk.chunk_id,
      );
      Object.assign(
        plan.transformations.find((item) => item.chunk_id === chunk.chunk_id),
        { action: "annotate", output_digest: chunk.content_digest },
      );
    },
    (x) => {
      x.evaluation.context_plan.chunks[4].transform_state = "preserved";
    },
  ];
  for (const mutate of mutations) {
    const input = structuredClone(fixture);
    mutate(input);
    rehash(input);
    assert.throws(() => evaluate(input), /product_context_plan_invalid/u);
    passed++;
  }
  const badHash = structuredClone(fixture);
  badHash.evaluation.context_plan.plan_digest = "sha256:" + "c".repeat(64);
  assert.throws(() => evaluate(badHash), /product_context_plan_invalid/u);
  passed++;
  const accessor = structuredClone(fixture);
  let reads = 0;
  Object.defineProperty(accessor.sources[0], "content", {
    get() {
      reads++;
      return "getter";
    },
  });
  assert.throws(() => evaluate(accessor), /product_context_plan_invalid/u);
  assert.equal(reads, 0);
  passed++;
  process.stdout.write(
    JSON.stringify({ passed, published_messages: safe.messages.length }),
  );
} catch {
  process.stderr.write("product_context_contract_probe_failed\n");
  process.exitCode = 1;
}
