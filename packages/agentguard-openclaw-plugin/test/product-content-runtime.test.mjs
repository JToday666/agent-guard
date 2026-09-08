// Synthetic authority and plan callbacks, real encrypted journal. No Provider qualification.
import assert from "node:assert/strict";
import test from "node:test";
import { mkdtemp, rm } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { createAgentToolResultMiddlewareRunner } from "openclaw/plugin-sdk/agent-harness";
import { snapshotNativeProductResult } from "../dist/mapping/product-events.js";
import { OpenClawProductContentRuntime } from "../dist/runtime/product-content-runtime.js";
import { OpenClawProductActionRuntime } from "../dist/runtime/product-action-runtime.js";
import { OpenClawProductEnvelopeStore } from "../dist/runtime/product-envelope-store.js";
import { OpenClawProductReceiptOutbox } from "../dist/runtime/product-receipt-outbox.js";
import { readOpenClawActivationAckHandle } from "../dist/runtime/activation-ack-handle.js";
import {
  bindEvaluationActivationAck,
  runtimeOutcomeToWire,
} from "../dist/runtime/product-authority-context.js";
import {
  restrictedCanonicalJson,
  restrictedDigest,
} from "../dist/runtime/canonical.js";
import {
  buildProductContentCheckpoint,
  buildProductContentReceipt,
} from "../dist/mapping/product-content-receipts.js";
import {
  buildProductContextEvent,
  normalizeProductModelOutput,
  productMemorySourceId,
} from "../dist/mapping/product-content-events.js";

const TOKEN = `hmac-sha256:${"a".repeat(64)}`;
const NS = {
  runtime: "openclaw",
  agentId: "main",
  principalId: "principal:content",
  runtimeBindingId: "binding:content",
};
const IDENTITY = {
  runtime_version: "2026.7.1-2",
  plugin_version: "0.1.0-rc.1",
  agent_id: NS.agentId,
  runtime_binding_id: NS.runtimeBindingId,
  profile_id: "agentguard-openclaw-v2-restricted",
  ...Object.fromEntries(
    [
      "activation_ref_digest",
      "capability_digest",
      "host_inventory_digest",
      "plugin_inventory_digest",
      "plugin_order_inventory_digest",
      "tool_inventory_digest",
    ].map((k, i) => [k, `sha256:${String(i + 1).repeat(64)}`]),
  ),
};
const BINDING = {
  agentId: "main",
  sessionKey: "agent:main:content",
  taskId: "task_content",
  userTask: "Read the isolated fixture",
  traceId: "trace_content",
  provider: "agentguard-acceptance",
  modelId: "controlled",
};
const TOOLS = [
  "read",
  "write",
  "edit",
  "exec",
  "process",
  "agentguard_memory_read",
  "agentguard_memory_write",
  "message",
].map((name) => ({
  name,
  description: name,
  parameters: { type: "object", properties: {} },
}));
const signal = () => new AbortController().signal;
function ack() {
  const now = Date.now();
  return readOpenClawActivationAckHandle(
    {
      schema_version: "1.0",
      runtime: "openclaw",
      ...IDENTITY,
      issued_at: new Date(now - 1000).toISOString(),
      expires_at: new Date(now + 119000).toISOString(),
      ack_token: TOKEN,
    },
    IDENTITY,
    { nowMs: now },
  );
}
function policy(event, handle, decision = "allow") {
  const value = {
    decision: {
      decision_id: `decision_${event.event_id}`,
      decision,
      risk_score: 10,
      severity: "low",
      reason: "synthetic",
    },
    approval: null,
    policy_audit_id: `policy_${event.event_id}`,
    decision_authority: {
      source: "v21",
      mode: "active",
      selection_basis: "profile_all",
      activation_ref_digest: IDENTITY.activation_ref_digest,
      legacy_floor_applied: false,
    },
    approval_release_directive: { mode: "not_applicable" },
  };
  bindEvaluationActivationAck(value, handle);
  return value;
}
function input(messages = [{ role: "user", content: BINDING.userTask }]) {
  return {
    ...BINDING,
    provider: BINDING.provider,
    modelId: BINDING.modelId,
    systemPrompt: "",
    messages,
    tools: TOOLS,
  };
}
function nativeInput(messages) {
  const { provider, modelId, systemPrompt, tools } = input();
  return {
    provider,
    modelId,
    systemPrompt,
    tools,
    messages: messages ?? input().messages,
  };
}
function output(call = false) {
  return {
    role: "assistant",
    content: call
      ? [
          {
            type: "toolCall",
            id: "call_read",
            name: "read",
            arguments: { path: "fixture.txt" },
          },
        ]
      : [{ type: "text", text: "Completed" }],
    stopReason: call ? "toolUse" : "stop",
    api: "openai-completions",
    provider: BINDING.provider,
    model: BINDING.modelId,
    usage: {
      input: 1,
      output: 1,
      totalTokens: 2,
      cost: { input: 0, output: 0, total: 0 },
    },
    timestamp: 1,
  };
}
function deferred() {
  let resolve;
  const promise = new Promise((r) => (resolve = r));
  return { promise, resolve };
}
async function fixture(t, options = {}) {
  const directory = await mkdtemp(join(tmpdir(), "ag-content-"));
  const sent = [],
    events = [],
    stores = [],
    boxes = [];
  const handle = ack();
  const open = async () => {
    const store = await OpenClawProductEnvelopeStore.open({
      directory: join(directory, "queue"),
      keyPath: join(directory, "keys", "key"),
      namespace: NS,
    });
    stores.push(store);
    const box = new OpenClawProductReceiptOutbox({
      store,
      sendReceipt: async (wire) => {
        sent.push(wire);
        return options.send
          ? options.send(JSON.parse(wire), wire)
          : {
              status: "recorded",
              auditId: JSON.parse(wire).audit_id,
              httpStatus: 200,
            };
      },
      retryBaseMs: 10,
      retryMaxMs: 20,
    });
    boxes.push(box);
    return box;
  };
  const outbox = await open();
  const client = {
    startProductSession: async () => handle,
    closeProductSession() {},
    snapshotProductAck: async () => {
      if (options.snapshot) await options.snapshot();
      return handle;
    },
    openProductDelivery: async () => outbox,
    closeProductDelivery: async () => outbox.close(),
    evaluateProductEvent: async (event) => {
      events.push(event);
      const evaluation = policy(
        event,
        handle,
        options.decision?.(event) ?? "allow",
      );
      if (options.evaluate) await options.evaluate(event, evaluation);
      return { evaluation, activationAck: handle };
    },
    waitForApproval: async () => ({ status: "pending" }),
    consumeProductExecutionLease: async () => {
      throw Error("not expected");
    },
  };
  let actions;
  const runtime = new OpenClawProductContentRuntime({
    client,
    binding: BINDING,
    tools: TOOLS,
    memoryNamespace: "/fixture/memory.sqlite",
    ensureStarted: async () => {},
    consumeContext: (event, _evaluation, sources) => {
      if (options.consume) return options.consume(event, sources);
      return {
        messages: sources
          .filter((s) => s.role === "user")
          .map((s) => ({ role: "user", content: s.content })),
        planId: "plan_content",
        planDigest: restrictedDigest(sources),
        contextRef: `context:${event.event_id}`,
        visibleSourceRefs: sources.map(
          (s, i) => `source:${s.source_type}:${event.event_id}:${i}`,
        ),
      };
    },
    verifyWirePayload: (prepared, payload) => {
      if (options.wire) options.wire(prepared, payload);
      else
        assert.deepEqual(
          JSON.parse(JSON.stringify(payload)),
          JSON.parse(JSON.stringify(prepared)),
        );
    },
  });
  actions = new OpenClawProductActionRuntime({
    client,
    observe: async () => ({}),
    profile: {
      agentId: "main",
      workspaceRoot: "/fixture",
      memoryNamespace: "/fixture/memory.sqlite",
      inboxUrl: "http://127.0.0.1:12345/inbox",
    },
    originProvider: runtime.originProvider.bind(runtime),
    resultCheckpoint: runtime.resultCheckpoint.bind(runtime),
  });
  await actions.start();
  t.after(async () => {
    runtime.close();
    await actions.close();
    for (const box of boxes) await box.close();
    await rm(directory, { recursive: true, force: true });
  });
  return {
    runtime,
    actions,
    outbox,
    open,
    stores,
    sent,
    events,
    client,
    handle,
  };
}
async function prepare(f) {
  const prepared = await f.runtime.prepareInput(nativeInput(), signal());
  f.runtime.verifyWirePayload(prepared, JSON.parse(JSON.stringify(prepared)));
  return {
    prepared,
    ticket: await f.runtime.beginModelCall(prepared, signal()),
  };
}

test("input/checkpoint and original model terminal retain their ACK; origin only after both receipts", async (t) => {
  const gate = deferred();
  let blocked = false;
  const f = await fixture(t, {
    send: async (receipt) => {
      if (receipt.stage === "native_model_terminal") {
        blocked = true;
        await gate.promise;
      }
      return { status: "recorded", auditId: receipt.audit_id, httpStatus: 200 };
    },
  });
  const { ticket } = await prepare(f);
  const done = f.runtime.finishModelCall(
    ticket,
    { status: "completed", message: output(true) },
    signal(),
  );
  while (!blocked) await new Promise((r) => setImmediate(r));
  assert.equal(f.sent.length, 3);
  const outputReceipt = f.sent
    .map((wire) => JSON.parse(wire))
    .find((receipt) => receipt.stage === "product_model_output_produced");
  assert.equal(outputReceipt.links.action_id, `act_${f.events[2].event_id}`);
  assert.equal(
    f.sent.every(
      (w) => JSON.parse(w).metadata.activation_ack.ack_token === TOKEN,
    ),
    true,
  );
  assert.equal(f.outbox.status().pendingCount, 1);
  gate.resolve();
  assert.deepEqual(
    JSON.parse(JSON.stringify((await done).message)),
    output(true),
  );
  const native = {
    agentId: "main",
    sessionKey: BINDING.sessionKey,
    runId: "run_actual",
    toolCallId: "call_read",
    toolName: "read",
    argumentsJson: '{"path":"fixture.txt"}',
  };
  const origin = await f.runtime.originProvider(native, signal());
  assert.equal(origin.runId, "run_actual");
  assert.equal(origin.modelOutputAuditId, `policy_${f.events[2].event_id}`);
  assert.equal(origin.modelSourceRef, `source:model:${f.events[2].event_id}`);
  assert.equal(
    f.sent
      .map((w) => JSON.parse(w))
      .every((r) => r.evidence.execution.invoked_at === null),
    true,
  );
});

for (const eventType of [
  "context_assembled",
  "model_input_prepared",
  "model_output_produced",
]) {
  test(`official ${eventType} deny never publishes native output`, async (t) => {
    const f = await fixture(t, {
      decision: (event) => (event.event_type === eventType ? "deny" : "allow"),
    });
    if (eventType === "model_output_produced") {
      const { ticket } = await prepare(f);
      await assert.rejects(
        f.runtime.finishModelCall(
          ticket,
          { status: "completed", message: output() },
          signal(),
        ),
        { code: "native_content_blocked" },
      );
      assert.equal(
        JSON.parse(f.sent.at(-1)).evidence.execution.status,
        "executed",
      );
    } else
      await assert.rejects(f.runtime.prepareInput(nativeInput(), signal()), {
        code: "native_content_blocked",
      });
    assert.equal(f.outbox.status().breakerOpen, true);
  });
}
for (const status of ["retryable", "permanent_rejected", "failed"]) {
  test(`unconfirmed output checkpoint ${status} retains actual model terminal and publishes nothing`, async (t) => {
    const f = await fixture(t, {
      send: async (receipt) =>
        receipt.stage === "product_model_output_produced"
          ? { status, httpStatus: status === "permanent_rejected" ? 422 : 503 }
          : { status: "recorded", auditId: receipt.audit_id, httpStatus: 200 },
    });
    const { ticket } = await prepare(f);
    await assert.rejects(
      f.runtime.finishModelCall(
        ticket,
        { status: "completed", message: output(true) },
        signal(),
      ),
    );
    assert.ok(
      f.sent.some((w) => {
        const r = JSON.parse(w);
        return (
          r.stage === "native_model_terminal" &&
          r.evidence.execution.status === "executed"
        );
      }),
    );
    assert.equal(f.outbox.status().breakerOpen, true);
    assert.ok(f.outbox.status().pendingCount >= 1);
  });
}
test("aborted postinvoke failure still writes historical terminal", async (t) => {
  const f = await fixture(t);
  const { ticket } = await prepare(f);
  const abort = new AbortController();
  abort.abort();
  await assert.rejects(
    f.runtime.finishModelCall(ticket, { status: "failed" }, abort.signal),
  );
  const receipt = JSON.parse(f.sent.at(-1));
  assert.equal(receipt.evidence.execution.status, "failed");
  assert.equal(receipt.evidence.execution.invoked_at, null);
});
test("overlapping prepare and copied tickets cannot grant another call", async (t) => {
  const f = await fixture(t);
  const { prepared, ticket } = await prepare(f);
  await assert.rejects(f.runtime.beginModelCall({ ...prepared }, signal()));
  await assert.rejects(
    f.runtime.finishModelCall(
      { ...ticket },
      { status: "completed", message: output() },
      signal(),
    ),
  );
  assert.equal(
    f.events.filter((e) => e.event_type === "model_output_produced").length,
    0,
  );
});
for (const change of ["task", "model", "tools", "history", "getter"]) {
  test(`unknown or changed native ${change} is rejected before policy/provider`, async (t) => {
    const f = await fixture(t);
    let raw = nativeInput();
    let called = 0;
    if (change === "task")
      raw.messages = [{ role: "user", content: "different" }];
    if (change === "model") raw.modelId = "different";
    if (change === "tools") raw.tools = TOOLS.slice(1);
    if (change === "history") raw.messages.push(output());
    if (change === "getter")
      Object.defineProperty(raw, "messages", {
        get() {
          called++;
          throw Error(TOKEN);
        },
      });
    await assert.rejects(f.runtime.prepareInput(raw, signal()));
    assert.equal(f.events.length, 0);
    assert.equal(called, 0);
  });
}
test("full output preserves thinking and rejects unknown/multiple call blocks", () => {
  const value = output();
  value.content.unshift({ type: "thinking", thinking: "complete reasoning" });
  assert.equal(
    normalizeProductModelOutput(value).projection.content[0].thinking,
    "complete reasoning",
  );
  const invalid = output();
  invalid.content.push({ type: "image", data: "hidden" });
  assert.throws(() => normalizeProductModelOutput(invalid));
  const multi = output(true);
  multi.content.push({ ...multi.content[0], id: "second" });
  assert.throws(() => normalizeProductModelOutput(multi));
});
test("native middleware shape returns only confirmed result before late after; next input uses evidence only", async (t) => {
  const f = await fixture(t);
  const { ticket } = await prepare(f);
  const approved = await f.runtime.finishModelCall(
    ticket,
    { status: "completed", message: output(true) },
    signal(),
  );
  const ctx = {
    agentId: "main",
    sessionKey: BINDING.sessionKey,
    runId: "run_actual",
    toolCallId: "call_read",
    toolName: "read",
  };
  const before = {
    toolName: "read",
    toolCallId: "call_read",
    runId: "run_actual",
    params: { path: "fixture.txt" },
  };
  assert.deepEqual(await f.actions.before(before, ctx), {
    params: { path: "fixture.txt" },
  });
  const result = {
    content: [{ type: "text", text: "fixture text" }],
    details: {},
  };
  const safe = await f.actions.observeToolResultMiddleware(
    {
      toolCallId: "call_read",
      toolName: "read",
      args: before.params,
      result,
      isError: false,
    },
    { runtime: "openclaw", harness: "openclaw" },
  );
  assert.deepEqual(
    JSON.parse(JSON.stringify(safe.result.content)),
    result.content,
  );
  assert.equal(f.sent.length, 5);
  assert.equal(f.events.at(-1).security_context.source_type, "tool_result");
  assert.equal(f.events.at(-1).security_context.source_trust, "untrusted");
  for (const event of f.events) {
    assert.equal(event.security_context.session_id, BINDING.sessionKey);
    assert.equal(event.security_context.session_key, BINDING.sessionKey);
    assert.equal(event.metadata.task_id, BINDING.taskId);
    assert.equal(event.trace_id, BINDING.traceId);
  }
  assert.equal(JSON.parse(f.sent[3]).stage, "native_tool_result_middleware");
  assert.equal(JSON.parse(f.sent[4]).stage, "product_tool_result_produced");
  await f.actions.after({ ...before, result }, ctx);
  assert.equal(f.sent.length, 5);
  const message = {
    role: "toolResult",
    toolCallId: "call_read",
    toolName: "read",
    ...safe.result,
    timestamp: 42,
  };
  const persisted = f.actions.resultForPersistence(
    { toolCallId: "call_read", toolName: "read", message },
    ctx,
  );
  assert.deepEqual(
    JSON.parse(JSON.stringify(persisted.message.content)),
    result.content,
  );
  // Actual Host normalizeMessagesForLlmBoundary strips this empty envelope.
  const replayMessage = { ...message };
  delete replayMessage.details;
  const next = await f.runtime.prepareInput(
    nativeInput([
      { role: "user", content: BINDING.userTask },
      approved.message,
      replayMessage,
    ]),
    signal(),
  );
  assert.equal(
    next.messages.some((m) => m.role === "assistant"),
    false,
  );
  assert.equal(next.messages[1].content.content[0].text, "fixture text");
  assert.equal(f.outbox.status().breakerOpen, false);
});
test("result checkpoint role survives restart without an action permit or terminal collision", async (t) => {
  const f = await fixture(t, { send: async () => ({ status: "retryable" }) });
  const event = buildProductContextEvent(BINDING, [
    {
      source_id: "user:task",
      source_type: "user",
      source_trust: "trusted",
      role: "user",
      content: BINDING.userTask,
    },
  ]);
  const evaluation = policy(event, f.handle);
  const checkpoint = buildProductContentCheckpoint(event, evaluation, true);
  assert.equal(
    (await f.outbox.submitCheckpoint(checkpoint)).status,
    "queued_durable",
  );
  assert.equal(
    (await f.outbox.submitCheckpoint(JSON.parse(JSON.stringify(checkpoint))))
      .status,
    "failed",
  );
  const pending = f.stores[0]
    .records()
    .map((r) => JSON.parse(r.payload))
    .find((r) => r.version === 2);
  assert.equal(pending.checkpointRole, "context_assembled");
  assert.equal(pending.type, "receipt");
  await f.outbox.close();
  const restarted = await f.open();
  assert.equal(restarted.status().unknownActionCount, 0);
  assert.equal(restarted.status().pendingCount, 1);
});

async function releasedRead(f) {
  const { ticket } = await prepare(f);
  await f.runtime.finishModelCall(
    ticket,
    { status: "completed", message: output(true) },
    signal(),
  );
  const context = {
    agentId: "main",
    sessionKey: BINDING.sessionKey,
    runId: "run_actual",
    toolCallId: "call_read",
    toolName: "read",
  };
  const event = {
    toolName: "read",
    toolCallId: "call_read",
    runId: "run_actual",
    params: { path: "fixture.txt" },
  };
  assert.deepEqual(await f.actions.before(event, context), {
    params: { path: "fixture.txt" },
  });
  return {
    context,
    event,
    result: {
      content: [{ type: "text", text: "private native text" }],
      details: {},
    },
  };
}
test("queued required result checkpoint releases no raw middleware content", async (t) => {
  const f = await fixture(t, {
    send: async (receipt) =>
      receipt.stage === "product_tool_result_produced"
        ? { status: "retryable" }
        : { status: "recorded", auditId: receipt.audit_id, httpStatus: 200 },
  });
  const call = await releasedRead(f);
  const result = await f.actions.observeToolResultMiddleware(
    {
      toolCallId: "call_read",
      toolName: "read",
      args: call.event.params,
      result: call.result,
    },
    { runtime: "openclaw" },
  );
  assert.equal(JSON.stringify(result).includes("private native text"), false);
  assert.equal(f.outbox.status().breakerOpen, true);
  assert.equal(f.outbox.status().pendingCount, 1);
  assert.equal(JSON.parse(f.sent[3]).evidence.execution.status, "executed");
});
test("close while result checkpoint is in flight cannot publish a late successful result", async (t) => {
  const gate = deferred();
  let waiting = false;
  const f = await fixture(t, {
    send: async (receipt) => {
      if (receipt.stage === "product_tool_result_produced") {
        waiting = true;
        await gate.promise;
      }
      return { status: "recorded", auditId: receipt.audit_id, httpStatus: 200 };
    },
  });
  const call = await releasedRead(f);
  const pending = f.actions.observeToolResultMiddleware(
    {
      toolCallId: "call_read",
      toolName: "read",
      args: call.event.params,
      result: call.result,
    },
    { runtime: "openclaw" },
  );
  while (!waiting) await new Promise((r) => setImmediate(r));
  f.runtime.close();
  gate.resolve();
  const result = await pending;
  assert.equal(JSON.stringify(result).includes("private native text"), false);
  assert.equal(f.outbox.status().breakerOpen, true);
});
for (const mismatch of ["args", "session", "after_error", "persist_content"]) {
  test(`native middleware ${mismatch} mismatch cannot publish or silently rebind`, async (t) => {
    const f = await fixture(t);
    const call = await releasedRead(f);
    const e = {
      toolCallId: "call_read",
      toolName: "read",
      args: call.event.params,
      result: call.result,
    };
    const ctx = { runtime: "openclaw" };
    if (mismatch === "args") e.args = { path: "other.txt" };
    if (mismatch === "session") ctx.sessionKey = "other";
    const safe = await f.actions.observeToolResultMiddleware(e, ctx);
    if (mismatch === "after_error")
      await f.actions.after(
        { ...call.event, result: call.result, error: "late mismatch" },
        call.context,
      );
    if (mismatch === "persist_content") {
      const message = {
        role: "toolResult",
        toolCallId: "call_read",
        toolName: "read",
        ...safe.result,
        timestamp: 42,
        content: [{ type: "text", text: "changed" }],
      };
      const persisted = f.actions.resultForPersistence(
        { toolCallId: "call_read", toolName: "read", message },
        call.context,
      );
      assert.equal(JSON.stringify(persisted).includes("changed"), false);
    }
    assert.equal(f.outbox.status().breakerOpen, true);
  });
}
test("finite native accounting decimals survive output/history without becoming security content", async (t) => {
  const f = await fixture(t);
  const { ticket } = await prepare(f);
  const message = output();
  message.usage.cost = { input: 0.000012, output: 0.000017, total: 0.000029 };
  const approved = await f.runtime.finishModelCall(
    ticket,
    { status: "completed", message },
    signal(),
  );
  assert.equal(approved.message.usage.cost.total, 0.000029);
  const next = await f.runtime.prepareInput(
    nativeInput([
      { role: "user", content: BINDING.userTask },
      approved.message,
    ]),
    signal(),
  );
  assert.equal(next.messages.length, 1);
  const context = f.events.at(-2);
  assert.equal(
    JSON.stringify(context.payload.sources).includes("0.000029"),
    false,
  );
});
for (const mutation of ["wrong_role", "missing_role", "downgrade", "version"]) {
  test(`encrypted checkpoint ${mutation} fails closed on recovery`, async (t) => {
    const f = await fixture(t, { send: async () => ({ status: "retryable" }) });
    const event = buildProductContextEvent(BINDING, [
      {
        source_id: "user:task",
        source_type: "user",
        source_trust: "trusted",
        role: "user",
        content: BINDING.userTask,
      },
    ]);
    await f.outbox.submitCheckpoint(
      buildProductContentCheckpoint(event, policy(event, f.handle), true),
    );
    const store = f.stores[0];
    const entry = store
      .records()
      .find((r) => JSON.parse(r.payload).version === 2);
    const data = JSON.parse(entry.payload);
    if (mutation === "wrong_role")
      data.checkpointRole = "model_output_produced";
    if (mutation === "missing_role") delete data.checkpointRole;
    if (mutation === "downgrade") {
      data.version = 1;
      delete data.checkpointRole;
    }
    if (mutation === "version") data.version = 3;
    store.replace(entry.recordId, restrictedCanonicalJson(data), {
      expectedRevision: entry.revision,
    });
    await f.outbox.close();
    await assert.rejects(f.open(), { code: "outbox_recovery_failed" });
  });
}
test("public historical wire cannot assign checkpoint semantics or expose a checkpoint token", async (t) => {
  const f = await fixture(t);
  const event = buildProductContextEvent(BINDING, [
    {
      source_id: "user:task",
      source_type: "user",
      source_trust: "trusted",
      role: "user",
      content: BINDING.userTask,
    },
  ]);
  const evaluation = policy(event, f.handle);
  const checkpoint = buildProductContentCheckpoint(event, evaluation, true);
  assert.equal(JSON.stringify(checkpoint).includes(TOKEN), false);
  const wire = restrictedCanonicalJson(
    runtimeOutcomeToWire(
      buildProductContentReceipt(event, evaluation, {
        accepted: true,
        status: "executed",
      }),
    ),
  );
  assert.equal((await f.outbox.submitHistoricalWire(wire)).status, "failed");
  assert.equal(f.sent.length, 0);
});

test("memory source uses the Core canonical slash escaping including non-ASCII namespaces", () => {
  assert.equal(
    productMemorySourceId("/隔离/memory.sqlite", "fixture"),
    String.raw`memory://\/隔离\/memory.sqlite/fixture`,
  );
  assert.equal(
    productMemorySourceId(String.raw`/a\b/memory.sqlite`, "key"),
    String.raw`memory://\/a\\b\/memory.sqlite/key`,
  );
});
test("another native boundary's durable breaker blocks model input immediately", async (t) => {
  const f = await fixture(t);
  await f.runtime.start();
  f.outbox.tripActionBarrier();
  await assert.rejects(f.runtime.prepareInput(nativeInput(), signal()));
  assert.equal(f.events.length, 0);
});

for (const failure of ["abort", "session_drift"]) {
  test(`late recorded result checkpoint with ${failure} cannot publish raw content`, async (t) => {
    const gate = deferred();
    let waiting = false,
      drift = false;
    const f = await fixture(t, {
      snapshot: async () => {
        if (drift) throw new Error("fixed drift");
      },
      send: async (receipt) => {
        if (receipt.stage === "product_tool_result_produced") {
          waiting = true;
          await gate.promise;
        }
        return {
          status: "recorded",
          auditId: receipt.audit_id,
          httpStatus: 200,
        };
      },
    });
    const call = await releasedRead(f);
    const pending = f.actions.observeToolResultMiddleware(
      {
        toolCallId: "call_read",
        toolName: "read",
        args: call.event.params,
        result: call.result,
      },
      { runtime: "openclaw" },
    );
    while (!waiting) await new Promise((r) => setImmediate(r));
    if (failure === "session_drift") drift = true;
    else void f.actions.close();
    gate.resolve();
    const result = await pending;
    assert.equal(JSON.stringify(result).includes("private native text"), false);
  });
}

for (const sessionKey of [undefined, "agent:main:other-task"]) {
  test(`missing or different Host session (${sessionKey ?? "missing"}) never creates an action event`, async (t) => {
    const f = await fixture(t);
    const { ticket } = await prepare(f);
    await f.runtime.finishModelCall(
      ticket,
      { status: "completed", message: output(true) },
      signal(),
    );
    const result = await f.actions.before(
      {
        toolName: "read",
        toolCallId: "call_read",
        runId: "run_actual",
        params: { path: "fixture.txt" },
      },
      {
        agentId: "main",
        sessionKey,
        toolName: "read",
        toolCallId: "call_read",
        runId: "run_actual",
      },
    );
    assert.equal(result.block, true);
    assert.equal(f.events.length, 3);
    assert.equal(
      f.events.some((event) => event.pre_execution && event.payload.tool),
      false,
    );
  });
}

for (const status of ["failed", "executed", "not_invoked"]) {
  test(`ALLOW parent projection survives runtime ${status} and isolation`, async (t) => {
    const f = await fixture(t);
    const event = {
      ...buildProductContextEvent(BINDING, [
        {
          source_id: "task",
          source_type: "user",
          source_trust: "trusted",
          role: "user",
          content: BINDING.userTask,
        },
      ]),
      case_id: "case:projection",
      is_malicious: false,
    };
    const evaluation = policy(event, f.handle);
    evaluation.decision.rule_hits = [{ rule_id: "policy:matched" }];
    const receipt = buildProductContentReceipt(event, evaluation, {
      accepted: false,
      status,
    });
    assert.equal(receipt.blocked, false);
    assert.deepEqual(receipt.rule_hits, ["policy:matched"]);
    assert.equal(receipt.case_id, event.case_id);
    assert.equal(receipt.is_malicious, false);
    assert.equal(receipt.evidence.intervention.type, "content_isolation");
    assert.equal(receipt.evidence.execution.status, status);
  });
}

test("actual Host tool argument text is verified and retained in native output and inspected content", () => {
  const native = output(true);
  native.content[0].partialArgs = '{ "path" : "fixture.txt" }';
  const result = normalizeProductModelOutput(native);
  assert.deepEqual(JSON.parse(JSON.stringify(result.message)), native);
  assert.deepEqual(result.projection.content, [
    {
      type: "tool_argument_text",
      call_id: "call_read",
      text: native.content[0].partialArgs,
    },
  ]);
  assert.deepEqual(
    { ...result.projection.tool_calls[0].args },
    {
      path: "fixture.txt",
    },
  );
});
for (const partialArgs of [
  '{"path":',
  '{"path":"other.txt"}',
  '{"path":"fixture.txt","path":"fixture.txt"}',
  '{"path":"fixture.txt","pa\\u0074h":"fixture.txt"}',
]) {
  test(`ambiguous or changed Host tool argument text is never omitted from validation (${partialArgs.length})`, () => {
    const native = output(true);
    native.content[0].partialArgs = partialArgs;
    assert.throws(() => normalizeProductModelOutput(native));
  });
}

test("actual public middleware runner preserves optional undefined result fields without losing content", async (t) => {
  const f = await fixture(t);
  const call = await releasedRead(f);
  let observed = false;
  const runner = createAgentToolResultMiddlewareRunner(
    { runtime: "openclaw" },
    [
      async (event, context) => {
        observed = true;
        assert.equal(Object.hasOwn(event.result, "details"), true);
        assert.equal(event.result.details, undefined);
        return f.actions.observeToolResultMiddleware(event, context);
      },
    ],
  );
  const result = await runner.applyToolResultMiddleware({
    toolCallId: "call_read",
    toolName: "read",
    args: call.event.params,
    cwd: "/workspace/fixture",
    isError: false,
    result: { content: call.result.content, details: undefined },
  });
  assert.equal(observed, true);
  assert.deepEqual(
    JSON.parse(JSON.stringify(result.content)),
    call.result.content,
  );
  assert.equal(f.events.at(-1).event_type, "tool_result_produced");
  assert.equal(f.sent.length, 5);
  await f.actions.after(
    {
      ...call.event,
      result: {
        content: result.content,
        details: result.details,
        terminate: undefined,
      },
    },
    call.context,
  );
  assert.equal(f.outbox.status().breakerOpen, false);
});

for (const invalid of ["nested", "content", "unknown", "getter"]) {
  test(`optional Host envelope handling does not omit invalid ${invalid} content`, () => {
    let getterCalls = 0;
    const value = { content: [{ type: "text", text: "complete" }] };
    if (invalid === "nested") value.details = { nested: undefined };
    if (invalid === "content") value.content = undefined;
    if (invalid === "unknown") value.extra = undefined;
    if (invalid === "getter")
      Object.defineProperty(value, "details", {
        enumerable: true,
        get() {
          getterCalls++;
          return undefined;
        },
      });
    assert.throws(() => snapshotNativeProductResult(value));
    assert.equal(getterCalls, 0);
  });
}

for (const mutation of [
  "host-strip",
  "details-exact",
  "details",
  "details-null",
  "details-empty",
  "content",
  "call-id",
  "tool-name",
  "isError",
]) {
  test(`Host result replay ${mutation} preserves confirmed evidence and exact native identity`, async (t) => {
    const f = await fixture(t);
    const call = await releasedRead(f);
    const result = await f.actions.observeToolResultMiddleware(
      {
        toolCallId: "call_read",
        toolName: "read",
        args: call.event.params,
        result: { ...call.result, details: { observed: "complete-detail" } },
      },
      { runtime: "openclaw", harness: "openclaw" },
    );
    assert.equal(result.result.isError, false);
    const originalMessage = {
      role: "toolResult",
      toolCallId: "call_read",
      toolName: "read",
      content: result.result.content,
      isError: false,
      timestamp: 0,
    };
    if (mutation === "details")
      originalMessage.details = { observed: "changed" };
    if (mutation === "details-exact")
      originalMessage.details = { observed: "complete-detail" };
    if (mutation === "details-null") originalMessage.details = null;
    if (mutation === "details-empty") originalMessage.details = {};
    if (mutation === "content")
      originalMessage.content = [{ type: "text", text: "changed" }];
    if (mutation === "call-id") originalMessage.toolCallId = "call-other";
    if (mutation === "tool-name") originalMessage.toolName = "write";
    if (mutation === "isError") originalMessage.isError = true;
    const pending = f.runtime.prepareInput(
      nativeInput([
        { role: "user", content: BINDING.userTask },
        output(true),
        originalMessage,
      ]),
      signal(),
    );
    if (["host-strip", "details-exact"].includes(mutation)) {
      const prepared = await pending;
      assert.equal(
        prepared.messages[1].content.details.observed,
        "complete-detail",
      );
      assert.equal(
        prepared.messages[1].content.content[0].text,
        "private native text",
      );
      assert.equal(f.outbox.status().breakerOpen, false);
      return;
    }
    await assert.rejects(pending);
    assert.equal(f.events.length, 5);
    assert.equal(f.outbox.status().breakerOpen, true);
  });
}
