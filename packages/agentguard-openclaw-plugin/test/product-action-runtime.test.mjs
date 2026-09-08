// B07 synthetic authority + real encrypted journal + actual pinned hook runner.
// These contracts do not claim a Provider-backed or public Product activation.
import assert from "node:assert/strict";
import test from "node:test";
import { mkdtemp, rm } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import {
  wrapToolWithBeforeToolCallHook,
  runAgentHarnessAfterToolCallHook,
  isToolResultError,
  sanitizeToolResult,
} from "openclaw/plugin-sdk/agent-harness";
import {
  createFixtureTools,
  createFixtureMemory,
} from "../../../tests/support/openclaw-product-runtime/index.mjs";
import {
  OpenClawProductActionRuntime,
  assertOpenClawProductExecutionAvailable,
} from "../dist/runtime/product-action-runtime.js";
import {
  readNativeProductAfter,
  snapshotProductJson,
} from "../dist/mapping/product-events.js";
import { restrictedDigest } from "../dist/runtime/canonical.js";
import { readOpenClawActivationAckHandle } from "../dist/runtime/activation-ack-handle.js";
import {
  bindEvaluationActivationAck,
  bindConsumptionActivationAck,
} from "../dist/runtime/product-authority-context.js";
import { OpenClawProductEnvelopeStore } from "../dist/runtime/product-envelope-store.js";
import { OpenClawProductReceiptOutbox } from "../dist/runtime/product-receipt-outbox.js";
import {
  registerBeforeToolCall,
  registerAfterToolCall,
  registerToolResultPersist,
} from "../dist/hooks/tool.js";
import { registerMessageSending } from "../dist/hooks/message.js";
import {
  getGlobalHookRunner,
  initializeGlobalHookRunner,
  resetGlobalHookRunner,
} from "openclaw/plugin-sdk/plugin-runtime";
const TOKEN_A = `hmac-sha256:${"a".repeat(64)}`,
  TOKEN_B = `hmac-sha256:${"b".repeat(64)}`;
const NS = {
  runtime: "openclaw",
  agentId: "main",
  principalId: "principal:actions",
  runtimeBindingId: "binding:actions",
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
    ].map((x, i) => [x, `sha256:${i + 1}`.padEnd(71, String(i + 1))]),
  ),
};
const ARGS = {
  read: { path: "fixture.txt" },
  write: { path: "fixture.txt", content: "sample" },
  edit: {
    path: "fixture.txt",
    edits: [{ oldText: "sample", newText: "changed" }],
  },
  exec: { command: "node marker.mjs" },
  process: { action: "list" },
  agentguard_memory_read: { key: "fixture" },
  agentguard_memory_write: { key: "fixture", value: "sample" },
  message: {
    action: "send",
    channel: "agentguard-fixture",
    target: "fixture-inbox",
    message: "sample",
  },
};
const PROFILE = {
  agentId: "main",
  workspaceRoot: "/workspace/fixture",
  memoryNamespace: "/workspace/fixture/memory.sqlite",
  inboxUrl: "http://127.0.0.1:45678/inbox",
};
function ack(token = TOKEN_A, now = Date.now()) {
  return readOpenClawActivationAckHandle(
    {
      schema_version: "1.0",
      runtime: "openclaw",
      ...IDENTITY,
      issued_at: new Date(now - 1000).toISOString(),
      expires_at: new Date(now + 119000).toISOString(),
      ack_token: token,
    },
    IDENTITY,
    { nowMs: now },
  );
}
function native(name = "read", suffix = "1") {
  const context = {
    agentId: "main",
    sessionKey: "agent:main:test",
    runId: `run_${suffix}`,
    toolCallId: `call_${suffix}`,
    toolName: name,
  };
  return {
    context,
    event: {
      toolName: name,
      runId: context.runId,
      toolCallId: context.toolCallId,
      params: structuredClone(ARGS[name]),
    },
  };
}
function origin(call) {
  return {
    modelOutputAuditId: `policy_model_${call.runId}`,
    modelSourceRef: `source:model:evt_${call.runId}`,
    callId: call.toolCallId,
    runId: call.runId,
    argumentsDigest: restrictedDigest(JSON.parse(call.argumentsJson)),
    taskId: "task_actions",
    userTask: "Exercise isolated tools",
    traceId: "trace_actions",
    visibleSourceRefs: [`source:model:evt_${call.runId}`],
  };
}
function evaluation(event, decision = "allow") {
  return {
    decision: {
      decision_id: `decision_${event.event_id}`,
      decision,
      risk_score: decision === "allow" ? 10 : 60,
      severity: decision === "allow" ? "low" : "medium",
      reason: "synthetic policy",
    },
    policy_audit_id: `policy_${event.event_id}`,
    approval:
      decision === "ask"
        ? { approval_id: "approval_actions", status: "pending" }
        : null,
    decision_authority: {
      source: "v21",
      mode: "active",
      selection_basis: "profile_all",
      activation_ref_digest: IDENTITY.activation_ref_digest,
      legacy_floor_applied: false,
    },
    approval_release_directive: {
      mode: decision === "ask" ? "restricted_allow_once" : "not_applicable",
    },
  };
}
async function fixture(t, options = {}) {
  const directory = await mkdtemp(join(tmpdir(), "ag-product-actions-"));
  const sent = [],
    events = [],
    consumes = [];
  const authorizations = [];
  const stores = [],
    outboxes = [];
  const open = async () => {
    const store = await OpenClawProductEnvelopeStore.open({
      directory: join(directory, "queue"),
      keyPath: join(directory, "keys", "key"),
      namespace: NS,
    });
    stores.push(store);
    const outbox = new OpenClawProductReceiptOutbox({
      store,
      sendReceipt: async (wire) => {
        sent.push(wire);
        return options.send
          ? options.send(wire)
          : {
              status: "recorded",
              auditId: JSON.parse(wire).audit_id,
              httpStatus: 200,
            };
      },
      retryBaseMs: 10,
      retryMaxMs: 20,
      drainIntervalMs: 1000,
    });
    outboxes.push(outbox);
    return outbox;
  };
  const outbox = await open();
  const evalAck = ack(),
    consumeAck = ack(TOKEN_B);
  let checkpoints = 0;
  const client = {
    startProductSession: async () => evalAck,
    closeProductSession() {},
    snapshotProductAck: async () =>
      options.snapshot ? options.snapshot() : consumeAck,
    openProductDelivery: async () => outbox,
    closeProductDelivery: async () => outbox.close(),
    evaluateProductEvent: async (event) => {
      events.push(event);
      const value = evaluation(event, options.decision);
      if (options.directive)
        value.approval_release_directive.mode = options.directive;
      bindEvaluationActivationAck(value, evalAck);
      if (options.evaluate) await options.evaluate(event, value);
      return { evaluation: value, activationAck: evalAck };
    },
    waitForApproval: async () =>
      options.approval ?? {
        status: "resolved",
        decision: "allow_once",
        resolution_source: "human",
      },
    consumeProductExecutionLease: async (value, request) => {
      consumes.push(request);
      bindConsumptionActivationAck(value, consumeAck);
      if (options.consume) return options.consume(value, request);
      return {
        leaseId: "lease_actions",
        consumptionId: "cons_actions",
        expiresAt: new Date(Date.now() + 60000).toISOString(),
      };
    },
  };
  const runtime = new OpenClawProductActionRuntime({
    client,
    observe: async () => ({}),
    profile: options.profile ?? PROFILE,
    originProvider: options.origin ?? (async (call) => origin(call)),
    resultCheckpoint: async (input) => {
      checkpoints++;
      if (options.checkpoint) return options.checkpoint(input);
      return {
        status: "recorded",
        message: {
          role: "toolResult",
          toolCallId: input.call.toolCallId,
          toolName: input.call.toolName,
          content: [{ type: "text", text: "safe result" }],
          isError: false,
          timestamp: Date.now(),
        },
      };
    },
    messageBridge: options.bridge ?? {
      authorize(p) {
        authorizations.push(p);
      },
      close() {},
    },
    ...options.runtimeOptions,
  });
  await runtime.start();
  t.after(async () => {
    await runtime.close();
    for (const box of outboxes) await box.close();
    await rm(directory, { recursive: true, force: true });
  });
  return {
    runtime,
    outbox,
    store: stores[0],
    sent,
    authorizations,
    events,
    consumes,
    evalAck,
    consumeAck,
    open,
    get checkpoints() {
      return checkpoints;
    },
  };
}
for (const name of Object.keys(ARGS))
  for (const decision of ["allow", "deny", "ask"])
    test(`${name} ${decision}: full native identity and honest gate/after receipt`, async (t) => {
      const f = await fixture(t, { decision });
      const { event, context } = native(name);
      const before = await f.runtime.before(event, context);
      assert.equal(f.events.length, 1);
      assert.equal(f.events[0].security_context.source_type, "model");
      assert.equal(f.events[0].security_context.source_trust, "unknown");
      if (decision === "deny") {
        assert.equal(before.block, true);
        await f.runtime.after({ ...event, error: "blocked by host" }, context);
        assert.equal(f.sent.length, 1);
        assert.equal(
          JSON.parse(f.sent[0]).evidence.execution.status,
          "not_invoked",
        );
        assert.equal(f.checkpoints, 0);
        return;
      }
      assert.deepEqual(before.params, event.params);
      const pre = f.sent.map(JSON.parse);
      assert.equal(pre.length, decision === "ask" ? 1 : 0);
      if (pre[0]) {
        assert.equal(pre[0].evidence.execution.status, "unknown");
        assert.equal(pre[0].metadata.activation_ack.ack_token, TOKEN_B);
        assert.equal(
          pre[0].evidence.enforcement.binding_check_status,
          "not_performed",
        );
      }
      if (name === "message")
        f.authorizations[0].onMessageDelivered(MESSAGE_ID);
      const result =
        name === "agentguard_memory_write"
          ? { content: [], details: { key: "fixture", written: true } }
          : name === "message"
            ? messageResult()
            : { content: [{ type: "text", text: "actual" }] };
      const delivered = await f.runtime.after({ ...event, result }, context);
      assert.equal(delivered?.status, "recorded");
      const terminal = JSON.parse(f.sent.at(-1));
      assert.equal(terminal.evidence.execution.status, "executed");
      assert.equal(terminal.evidence.execution.invoked_at, null);
      assert.equal(
        terminal.metadata.activation_ack.ack_token,
        decision === "ask" ? TOKEN_B : TOKEN_A,
      );
      assert.equal(
        terminal.evidence.execution.persisted,
        name === "agentguard_memory_write" ? true : null,
      );
      assert.equal(f.checkpoints, 1);
      assert.equal(
        f.runtime.resultForPersistence(
          { toolName: name, toolCallId: event.toolCallId, message: {} },
          context,
        ).message.content[0].text,
        "safe result",
      );
      assert.equal(f.outbox.status().pendingCount, 0);
    });
test("public composition is fixed closed without an enable override", () =>
  assert.throws(
    () => assertOpenClawProductExecutionAvailable(),
    /product_execution_unavailable/,
  ));
for (const field of ["runId", "toolCallId", "toolName"])
  test(`missing or contradictory native ${field} blocks before evaluate`, async (t) => {
    const f = await fixture(t);
    const { event, context } = native();
    delete event[field];
    assert.equal((await f.runtime.before(event, context)).block, true);
    assert.equal(f.events.length, 0);
    assert.equal(f.sent.length, 0);
  });
for (const variant of [
  "getter",
  "proxy",
  "cycle",
  "sparse",
  "extra",
  "path_escape",
])
  test(`immutable argument snapshot rejects ${variant} without executing input`, async (t) => {
    const f = await fixture(t);
    const { event, context } = native();
    let invoked = 0;
    if (variant === "getter")
      Object.defineProperty(event.params, "path", {
        get() {
          invoked++;
          return "fixture.txt";
        },
        enumerable: true,
      });
    if (variant === "proxy")
      event.params = new Proxy(event.params, {
        ownKeys() {
          invoked++;
          return ["path"];
        },
      });
    if (variant === "cycle") event.params.path = event.params;
    if (variant === "sparse") event.params.path = new Array(2);
    if (variant === "extra") event.params.config = "danger";
    if (variant === "path_escape") event.params.path = "../escape";
    assert.equal((await f.runtime.before(event, context)).block, true);
    assert.equal(f.events.length, 0);
    assert.equal(invoked, 0);
  });
test("argument drift during evaluate is denied with the original event ACK and zero release", async (t) => {
  const n = native();
  const f = await fixture(t, {
    evaluate: async () => {
      n.event.params.path = "changed.txt";
    },
  });
  assert.equal((await f.runtime.before(n.event, n.context)).block, true);
  assert.equal(f.sent.length, 1);
  assert.equal(JSON.parse(f.sent[0]).evidence.execution.status, "not_invoked");
  assert.equal(f.events[0].payload.arguments.path, "fixture.txt");
});
test("forbidden ASK does not consume or release", async (t) => {
  const f = await fixture(t, { decision: "ask", directive: "forbidden" }),
    n = native();
  assert.equal((await f.runtime.before(n.event, n.context)).block, true);
  assert.equal(f.consumes.length, 0);
  assert.equal(JSON.parse(f.sent[0]).evidence.execution.status, "not_invoked");
});
test("consume response lost retains evaluation ACK without invented lease correlation", async (t) => {
  const f = await fixture(t, {
      decision: "ask",
      consume: async () => {
        throw new Error(TOKEN_B);
      },
    }),
    n = native();
  assert.equal((await f.runtime.before(n.event, n.context)).block, true);
  const receipt = JSON.parse(f.sent[0]);
  assert.equal(receipt.metadata.activation_ack.ack_token, TOKEN_A);
  assert.equal(receipt.links.lease_id, undefined);
  assert.equal(receipt.evidence.enforcement.lease_consume_outcome, "unknown");
  assert.equal(JSON.stringify(receipt.evidence).includes(TOKEN_B), false);
});
test("unconfirmed approval release cannot return a permit", async (t) => {
  const f = await fixture(t, {
      decision: "ask",
      send: async () => ({ status: "retryable", httpStatus: 503 }),
    }),
    n = native();
  assert.equal((await f.runtime.before(n.event, n.context)).block, true);
  assert.equal(f.outbox.status().breakerOpen, true);
  assert.ok(f.outbox.status().pendingCount > 0);
});
for (const result of [false, 0, "", null, undefined])
  test(`actual falsy after ${String(result)} is executed, never not_invoked`, async (t) => {
    const f = await fixture(t),
      n = native();
    await f.runtime.before(n.event, n.context);
    const actual = { ...n.event, ...(result ? { result } : {}) };
    assert.equal(
      (await f.runtime.after(actual, n.context))?.status,
      "recorded",
    );
    assert.equal(
      JSON.parse(f.sent.at(-1)).evidence.execution.status,
      "executed",
    );
  });
test("actual failed after records a fixed failure once and no secret error text", async (t) => {
  const f = await fixture(t),
    n = native();
  await f.runtime.before(n.event, n.context);
  const actual = { ...n.event, error: TOKEN_A };
  await f.runtime.after(actual, n.context);
  await f.runtime.after(actual, n.context);
  assert.equal(f.sent.length, 1);
  const r = JSON.parse(f.sent[0]);
  assert.equal(r.evidence.execution.status, "failed");
  assert.equal(r.evidence.execution.error, "native_tool_failed");
});
test("missing after becomes unknown on run end; same-instance late after only supplements evidence", async (t) => {
  const f = await fixture(t),
    n = native();
  await f.runtime.before(n.event, n.context);
  f.runtime.onRunEnd(n.context.runId);
  assert.equal(f.outbox.status().unknownActionCount, 1);
  assert.equal(f.outbox.status().breakerOpen, true);
  await f.runtime.after({ ...n.event, result: { done: true } }, n.context);
  assert.equal(JSON.parse(f.sent.at(-1)).evidence.execution.status, "executed");
  assert.equal(f.checkpoints, 0);
  assert.equal(f.outbox.status().breakerOpen, true);
});
test("restart cannot reconstruct a ticket or reinvoke unknown action", async (t) => {
  const f = await fixture(t),
    n = native();
  await f.runtime.before(n.event, n.context);
  await f.runtime.close();
  const recovered = await f.open();
  assert.equal(recovered.status().unknownActionCount, 1);
  assert.throws(() => recovered.assertReady());
  assert.equal(f.sent.length, 0);
});
test("unconfirmed terminal or content checkpoint never exposes the raw Host result", async (t) => {
  const f = await fixture(t, {
      send: async () => ({ status: "retryable", httpStatus: 503 }),
    }),
    n = native();
  await f.runtime.before(n.event, n.context);
  await f.runtime.after({ ...n.event, result: { secret: TOKEN_A } }, n.context);
  assert.equal(f.checkpoints, 0);
  const message = f.runtime.resultForPersistence(
    {
      toolName: n.event.toolName,
      toolCallId: n.event.toolCallId,
      message: { content: TOKEN_A },
    },
    n.context,
  ).message;
  assert.equal(JSON.stringify(message).includes(TOKEN_A), false);
  assert.equal(f.outbox.status().breakerOpen, true);
});
test("blocked result checkpoint trips durable barrier after honest terminal was recorded", async (t) => {
  const f = await fixture(t, {
      checkpoint: async () => ({ status: "blocked" }),
    }),
    n = native();
  await f.runtime.before(n.event, n.context);
  await f.runtime.after({ ...n.event, result: { data: "actual" } }, n.context);
  assert.equal(JSON.parse(f.sent[0]).evidence.execution.status, "executed");
  assert.equal(f.outbox.status().breakerOpen, true);
  assert.match(
    f.runtime.resultForPersistence(
      {
        toolName: n.event.toolName,
        toolCallId: n.event.toolCallId,
        message: {},
      },
      n.context,
    ).message.content[0].text,
    /withheld/,
  );
});
test("duplicate native call and changed after never mint a second permit", async (t) => {
  const f = await fixture(t),
    n = native();
  await f.runtime.before(n.event, n.context);
  await f.runtime.after({ ...n.event, result: { value: 1 } }, n.context);
  assert.equal((await f.runtime.before(n.event, n.context)).block, true);
  await f.runtime.after({ ...n.event, result: { value: 2 } }, n.context);
  assert.equal(f.sent.length, 1);
  assert.equal(f.outbox.status().breakerOpen, true);
});
test("close during origin resolution cannot release a late action", async (t) => {
  let resolve;
  const pending = new Promise((r) => (resolve = r));
  const f = await fixture(t, {
      origin: async (call) => {
        await pending;
        return origin(call);
      },
    }),
    n = native();
  const before = f.runtime.before(n.event, n.context);
  await f.runtime.close();
  resolve();
  assert.equal((await before).block, true);
  assert.equal(f.events.length, 0);
});
test("message_sending only checks existing channel permit; missing native IDs do not become C3 proof", async (t) => {
  let permit;
  const f = await fixture(t, {
      bridge: {
        authorize(value) {
          permit = value;
        },
        close() {},
      },
    }),
    n = native("message");
  await f.runtime.before(n.event, n.context);
  assert.equal(permit.runId, n.context.runId);
  assert.equal(
    permit.argumentsJson,
    JSON.stringify(n.event.params, Object.keys(n.event.params).sort()),
  );
  assert.deepEqual(
    f.runtime.messageSending(
      { to: "fixture-inbox", content: "sample" },
      { channelId: "agentguard-fixture", accountId: "default" },
    ),
    { content: "sample" },
  );
  assert.equal(
    f.runtime.messageSending(
      { to: "other", content: "sample" },
      { channelId: "agentguard-fixture", accountId: "default" },
    ).cancel,
    true,
  );
  assert.throws(() => permit.assertCanSend());
});
test("actual pinned hook runner uses Product before/after/persistence handlers without legacy callbacks", async (t) => {
  const f = await fixture(t);
  const hooks = [];
  const hookContext = {
    api: {
      on(hookName, handler, options) {
        hooks.push({
          pluginId: "agentguard-security",
          hookName,
          handler,
          priority: options?.priority ?? 0,
        });
      },
    },
    config: {
      enabled: true,
      enforcementMode: "enforce",
      approvalWaitTimeoutMs: 1000,
    },
    makeClient() {
      throw new Error("legacy client must not be used");
    },
    productActions: f.runtime,
  };
  registerBeforeToolCall(hookContext);
  registerAfterToolCall(hookContext);
  registerToolResultPersist(hookContext);
  registerMessageSending(hookContext);
  resetGlobalHookRunner();
  initializeGlobalHookRunner({ hooks: [], plugins: [], typedHooks: hooks });
  t.after(() => resetGlobalHookRunner());
  const runner = getGlobalHookRunner(),
    n = native();
  assert.deepEqual(
    (await runner.runBeforeToolCall(n.event, n.context)).params,
    n.event.params,
  );
  await runner.runAfterToolCall(
    { ...n.event, result: { actual: true } },
    n.context,
  );
  assert.equal(f.sent.length, 1);
  const saved = runner.runToolResultPersist(
    {
      toolName: "read",
      toolCallId: n.event.toolCallId,
      message: { role: "toolResult", content: "raw" },
    },
    n.context,
  );
  assert.equal(saved.message.content[0].text, "safe result");
});
for (const decision of ["allow", "deny", "ask"])
  test(`actual pinned wrapper and SQLite tool ${decision}; SDK emits terminal shape with original IDs`, async (t) => {
    const root = await mkdtemp(join(tmpdir(), "ag-product-native-memory-"));
    t.after(() => rm(root, { recursive: true, force: true }));
    const f = await fixture(t, {
        decision,
        profile: {
          ...PROFILE,
          workspaceRoot: root,
          memoryNamespace: join(root, "memory.sqlite"),
        },
      }),
      n = native("agentguard_memory_write");
    const tools = createFixtureTools({
        acceptanceRoot: root,
        inboxUrl: PROFILE.inboxUrl,
      }),
      tool = tools.find((value) => value.name === n.event.toolName);
    let invocations = 0;
    const actualExecute = tool.execute;
    tool.execute = async (...args) => {
      invocations++;
      return actualExecute(...args);
    };
    const hooks = [];
    const ctx = {
      api: {
        on(hookName, handler, options) {
          hooks.push({
            pluginId: "agentguard-security",
            hookName,
            handler,
            priority: options?.priority ?? 0,
          });
        },
      },
      config: { enabled: true, enforcementMode: "enforce" },
      makeClient() {
        throw new Error("legacy transport");
      },
      productActions: f.runtime,
    };
    registerBeforeToolCall(ctx);
    registerAfterToolCall(ctx);
    resetGlobalHookRunner();
    initializeGlobalHookRunner({ hooks: [], plugins: [], typedHooks: hooks });
    t.after(() => resetGlobalHookRunner());
    const wrapped = wrapToolWithBeforeToolCallHook(
      tool,
      { ...n.context, config: {} },
      { emitDiagnostics: false },
    );
    const result = await wrapped.execute(n.event.toolCallId, n.event.params);
    assert.equal(invocations, decision === "deny" ? 0 : 1);
    // Drive the public emitter explicitly. This proves hook shape, not agent scheduling.
    await runAgentHarnessAfterToolCallHook({
      ...n.context,
      startArgs: n.event.params,
      result,
      startedAt: Date.now(),
    });
    assert.equal(f.events.length, 1);
    const r = JSON.parse(f.sent.at(-1));
    assert.equal(r.links.action_id, n.event.toolCallId);
    assert.equal(
      r.evidence.execution.status,
      decision === "deny" ? "not_invoked" : "executed",
    );
    assert.equal(r.evidence.execution.invoked_at, null);
    if (decision !== "deny") {
      assert.equal(
        createFixtureMemory(root).read({ key: "fixture" }).value,
        "sample",
      );
      assert.equal(r.evidence.execution.persisted, true);
    } else assert.equal(f.sent.length, 1);
  });
test("sparse/trailing-hole arrays are rejected in full result content, not silently shortened", () => {
  assert.throws(() => snapshotProductJson(new Array(2)));
  assert.throws(() => snapshotProductJson([1, ,]));
});
test("sync persistence rejects a different session even if the call ID was copied", async (t) => {
  const f = await fixture(t),
    n = native();
  await f.runtime.before(n.event, n.context);
  await f.runtime.after({ ...n.event, result: { done: true } }, n.context);
  const saved = f.runtime.resultForPersistence(
    { toolName: "read", toolCallId: n.event.toolCallId, message: {} },
    { ...n.context, sessionKey: "other" },
  );
  assert.match(saved.message.content[0].text, /withheld/);
  assert.equal(f.outbox.status().breakerOpen, true);
});
test("native optional undefined context fields do not become data provenance", async (t) => {
  const f = await fixture(t),
    n = native();
  await f.runtime.before(n.event, {
    ...n.context,
    getSessionExtension: () => undefined,
  });
  await f.runtime.after({ ...n.event, result: { done: true } }, n.context);
  const saved = f.runtime.resultForPersistence(
    {
      toolName: "read",
      toolCallId: n.event.toolCallId,
      message: {},
      isSynthetic: undefined,
    },
    n.context,
  );
  assert.equal(saved.message.content[0].text, "safe result");
});
for (const resolution_source of ["llm", "system", null])
  test(`restricted ASK resolution ${resolution_source} cannot release`, async (t) => {
    const f = await fixture(t, {
        decision: "ask",
        approval: {
          status: "resolved",
          decision: "allow_once",
          resolution_source,
        },
      }),
      n = native();
    assert.equal((await f.runtime.before(n.event, n.context)).block, true);
    assert.equal(f.consumes.length, 0);
    assert.equal(
      JSON.parse(f.sent[0]).evidence.execution.status,
      "not_invoked",
    );
  });
test("postconsume argument drift records not_invoked with the actual consume ACK and original lease", async (t) => {
  const n = native();
  const f = await fixture(t, {
    decision: "ask",
    consume: async () => {
      n.event.params.path = "changed.txt";
      return {
        leaseId: "lease_actions",
        consumptionId: "cons_actions",
        expiresAt: new Date(Date.now() + 60000).toISOString(),
      };
    },
  });
  assert.equal((await f.runtime.before(n.event, n.context)).block, true);
  const r = JSON.parse(f.sent[0]);
  assert.equal(r.links.lease_id, "lease_actions");
  assert.equal(r.metadata.activation_ack.ack_token, TOKEN_B);
  assert.equal(r.evidence.execution.status, "not_invoked");
  assert.deepEqual(r.evidence.enforcement.reason_codes, [
    "v21:restricted_allow_once",
    "v21:restricted_host_mismatch",
    "rte-05:lease_consumed",
  ]);
  assert.equal(f.outbox.status().unknownActionCount, 0);
});
test("required checkpoint accessors are never evaluated or exposed", async (t) => {
  let reads = 0;
  const f = await fixture(t, {
      checkpoint: async () =>
        Object.defineProperty({}, "status", {
          get() {
            reads++;
            return "recorded";
          },
          enumerable: true,
        }),
    }),
    n = native();
  await f.runtime.before(n.event, n.context);
  await f.runtime.after({ ...n.event, result: { done: true } }, n.context);
  assert.equal(reads, 0);
  assert.equal(f.outbox.status().breakerOpen, true);
});
test("Product configuration remains blocked even with disabled legacy enforcement and no coordinator", async () => {
  const hooks = new Map();
  let legacy = 0;
  const ctx = {
    api: {
      on(name, fn) {
        hooks.set(name, fn);
      },
    },
    config: {
      enabled: false,
      enforcementMode: "observe",
      officialProfileId: "agentguard-openclaw-v2-restricted",
    },
    makeClient() {
      legacy++;
      throw new Error("legacy must not run");
    },
  };
  registerBeforeToolCall(ctx);
  registerAfterToolCall(ctx);
  registerToolResultPersist(ctx);
  registerMessageSending(ctx);
  const n = native();
  assert.equal(
    (await hooks.get("before_tool_call")(n.event, n.context)).block,
    true,
  );
  assert.equal(
    (await hooks.get("message_sending")({ content: "private" }, {})).cancel,
    true,
  );
  await hooks.get("after_tool_call")(
    { ...n.event, result: { secret: "private" } },
    n.context,
  );
  assert.equal(
    JSON.stringify(
      hooks.get("tool_result_persist")({ message: { content: "private" } }, {}),
    ).includes("private"),
    false,
  );
  assert.equal(legacy, 0);
});
for (const [expiresAt, reason] of [
  [new Date(0).toISOString(), "rte-05:lease_expired"],
  ["invalid", "rte-05:lease_response_invalid"],
])
  test(`known consume ${reason} preserves correlation and truthful refusal code`, async (t) => {
    const f = await fixture(t, {
        decision: "ask",
        consume: async () => ({
          leaseId: "lease_actions",
          consumptionId: "cons_actions",
          expiresAt,
        }),
      }),
      n = native();
    assert.equal((await f.runtime.before(n.event, n.context)).block, true);
    const r = JSON.parse(f.sent[0]);
    assert.equal(r.metadata.activation_ack.ack_token, TOKEN_B);
    assert.equal(r.links.lease_id, "lease_actions");
    assert.ok(r.evidence.enforcement.reason_codes.includes(reason));
    assert.equal(r.evidence.execution.status, "not_invoked");
  });
test("known consumed lease after the approval budget records timed_out without losing its ACK", async (t) => {
  const now = Date.now();
  t.mock.timers.enable({ apis: ["Date"], now });
  const f = await fixture(t, {
      decision: "ask",
      consume: async () => {
        t.mock.timers.setTime(now + 30000);
        return {
          leaseId: "lease_actions",
          consumptionId: "cons_actions",
          expiresAt: new Date(now + 60000).toISOString(),
        };
      },
    }),
    n = native();
  assert.equal((await f.runtime.before(n.event, n.context)).block, true);
  const r = JSON.parse(f.sent[0]);
  assert.equal(r.evidence.enforcement.gate_state, "timed_out");
  assert.ok(
    r.evidence.enforcement.reason_codes.includes(
      "rte-05:lease_consume_timed_out",
    ),
  );
  assert.equal(r.metadata.activation_ack.ack_token, TOKEN_B);
});
for (const details of [
  { ok: false },
  { success: false },
  { status: "error" },
  { status: "timed_out" },
  { status: "forbidden" },
  { timedOut: true },
  { error: "fixed failure" },
  { exitCode: 7 },
])
  test(`Product after follows pinned structured failure contract ${Object.keys(details)[0]}`, () => {
    const result = { content: [], details };
    assert.equal(isToolResultError(result), true);
    assert.equal(readNativeProductAfter({ result }).failed, true);
  });
test("resolved tool result isError true produces failed terminal and cannot commit memory", async (t) => {
  const f = await fixture(t),
    n = native("agentguard_memory_write");
  await f.runtime.before(n.event, n.context);
  await f.runtime.after(
    {
      ...n.event,
      result: {
        isError: true,
        details: { key: "fixture", written: true },
        content: [],
      },
    },
    n.context,
  );
  const r = JSON.parse(f.sent[0]);
  assert.equal(r.evidence.execution.status, "failed");
  assert.equal(r.evidence.execution.persisted, null);
  assert.equal(r.evidence.execution.error, "native_tool_failed");
});
test("message permit expires with its original ACK even if a newer session ACK exists", async (t) => {
  const now = Date.now();
  t.mock.timers.enable({ apis: ["Date"], now });
  let permit;
  const f = await fixture(t, {
      snapshot: () => ack(TOKEN_B, Date.now()),
      bridge: {
        authorize(p) {
          permit = p;
        },
        close() {},
      },
    }),
    n = native("message");
  await f.runtime.before(n.event, n.context);
  t.mock.timers.setTime(now + 120000);
  assert.throws(() => permit.assertCanSend());
  await assert.rejects(() => permit.assertReadyToSend());
  assert.equal(f.sent.length, 0);
});
test("message dispatch awaits current session observation; drift blocks before network", async (t) => {
  let permit,
    observations = 0;
  const f = await fixture(t, {
      snapshot: () => {
        if (++observations > 1) throw new Error("manifest_changed");
        return ack(TOKEN_B);
      },
      bridge: {
        authorize(p) {
          permit = p;
        },
        close() {},
      },
    }),
    n = native("message");
  await f.runtime.before(n.event, n.context);
  await assert.rejects(
    () => permit.assertReadyToSend(),
    /native_send_unavailable/,
  );
  assert.equal(observations, 2);
  assert.equal(f.outbox.status().breakerOpen, true);
  assert.throws(() => permit.assertCanSend());
  assert.equal(f.sent.length, 0);
});
test("confirmed native memory write acknowledgement permits lifecycle receipt, while model result remains fenced", async (t) => {
  const f = await fixture(t, {
      checkpoint: async () => ({ status: "blocked" }),
    }),
    n = native("agentguard_memory_write");
  await f.runtime.before(n.event, n.context);
  await f.runtime.after(
    {
      ...n.event,
      result: { content: [], details: { key: "fixture", written: true } },
    },
    n.context,
  );
  const receipt = JSON.parse(f.sent[0]);
  assert.equal(receipt.evidence.result.disposition, "passed_through");
  assert.equal(receipt.evidence.execution.persisted, true);
  assert.equal(receipt.evidence.execution.tool_result_entered_context, null);
  assert.equal(f.outbox.status().breakerOpen, true);
  assert.equal(receipt.evidence.execution.status, "executed");
});

const MESSAGE_ID = "fixture:00000000-0000-4000-8000-000000000001";
function messageResult(messageId = MESSAGE_ID) {
  return {
    content: [{ type: "text", text: "sent" }],
    details: {
      channel: "agentguard-fixture",
      to: "fixture-inbox",
      via: "direct",
      mediaUrl: null,
      result: {
        channel: "agentguard-fixture",
        messageId,
        chatId: "fixture-inbox",
      },
      deliveryStatus: "sent",
      payloadOutcomes: [{ index: 0, status: "sent", resultCount: 1 }],
    },
  };
}
for (const variant of [
  "missing_delivery",
  "different_id",
  "missing_result",
  "other_target",
  "tool_error",
])
  test(`message ${variant} preserves unknown and never fabricates completion`, async (t) => {
    const f = await fixture(t),
      n = native("message");
    await f.runtime.before(n.event, n.context);
    if (variant !== "missing_delivery")
      f.authorizations[0].onMessageDelivered(MESSAGE_ID);
    const result = messageResult();
    if (variant === "different_id")
      result.details.result.messageId =
        "fixture:00000000-0000-4000-8000-000000000002";
    if (variant === "missing_result") delete result.details.result;
    if (variant === "other_target") result.details.to = "other";
    await f.runtime.after(
      {
        ...n.event,
        result: variant === "tool_error" ? undefined : result,
        ...(variant === "tool_error" ? { error: "channel_failure" } : {}),
      },
      n.context,
    );
    assert.equal(f.sent.length, 0);
    assert.equal(f.outbox.status().breakerOpen, true);
    assert.equal(f.outbox.status().unknownActionCount, 1);
    assert.equal((await f.runtime.before(n.event, n.context)).block, true);
  });
test("pinned sanitizeToolResult preserves actual message delivery identity for after correlation", async (t) => {
  const f = await fixture(t),
    n = native("message");
  await f.runtime.before(n.event, n.context);
  f.authorizations[0].onMessageDelivered(MESSAGE_ID);
  const result = sanitizeToolResult(messageResult());
  assert.equal(result.details.result.messageId, MESSAGE_ID);
  assert.equal(
    (await f.runtime.after({ ...n.event, result }, n.context))?.status,
    "recorded",
  );
  assert.equal(JSON.parse(f.sent[0]).evidence.execution.status, "executed");
});
