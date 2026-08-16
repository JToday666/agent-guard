// RTE-05 — OpenClaw strong approval binding conformance (CF-13..CF-17).
//
// These tests drive the real compiled hooks with a counting host boundary and
// prove consume -> approval release -> host invocation -> terminal. The pinned
// public host exposes no authoritative tool-start hook, so no start fact is
// synthesized by the plugin.
import assert from "node:assert/strict";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import {
  ExecutionLeaseConsumeError,
  GuardApiClient,
} from "../dist/guard-api-client.js";
import {
  registerAfterToolCall,
  registerBeforeToolCall,
} from "../dist/hooks/tool.js";
import { registerMessageSending } from "../dist/hooks/message.js";
import { buildRuntimeOutcomeAuditEvent } from "../dist/mapping/index.js";
import { buildRuntimeEnforcementCapability } from "../dist/runtime/heartbeat.js";
import { RuntimeOutcomeDelivery } from "../dist/runtime/outcome-delivery.js";
import { EvidenceDegradationTracker } from "../dist/runtime/state.js";

const FINGERPRINT = `hmac-sha256:${"a".repeat(64)}`;
const LEASE_TOKEN = `lease-v1:${"b".repeat(64)}`;
const BASE_CONFIG = {
  guardApiBaseUrl: "http://127.0.0.1:8088",
  adapterToken: "adapter-test-token",
  enforcementMode: "enforce",
  requestTimeoutMs: 50,
  approvalPollIntervalMs: 1,
  approvalTimeoutMs: 250,
  strongApprovalBindingEnabled: false,
  runtimeBindingId: "binding:openclaw:agent-rte05",
  diagnosticLogging: false,
  agentId: "agent-rte05",
};

function actionIdFor(event) {
  return event.event_type === "tool_call_proposed"
    ? event.payload.tool.call_id
    : `act_${event.event_id}`;
}

function askEvaluation(event, overrides = {}) {
  return {
    decision: {
      decision_id: overrides.decisionId ?? `dec_${event.event_id}`,
      decision: "ask",
      risk_score: 70,
      severity: "high",
      reason: "strong approval required",
      rule_hits: [],
    },
    approval: {
      approval_id: overrides.approvalId ?? `approval_${event.event_id}`,
      status: "pending",
      decision_options: ["allow_once", "deny"],
    },
    policy_audit_id: overrides.policyAuditId ?? `policy_${event.event_id}`,
    enforcement_binding: overrides.binding ?? {
      schema_version: "2.1",
      action_id: actionIdFor(event),
      authorization_fingerprint: FINGERPRINT,
      runtime_binding_id: "binding:openclaw:agent-rte05",
      requires_execution_lease: true,
    },
  };
}

function allowEvaluation(event) {
  return {
    decision: {
      decision_id: `dec_${event.event_id}`,
      decision: "allow",
      risk_score: 10,
      severity: "low",
      reason: "allowed",
      rule_hits: [],
    },
    approval: null,
    policy_audit_id: `policy_${event.event_id}`,
  };
}

function makeHarness(options = {}) {
  const handlers = {};
  const handlerOptions = {};
  const receipts = [];
  const order = [];
  const invocations = [];
  const toolCallState = new Map();
  const degradations = new EvidenceDegradationTracker();
  const client = {
    evaluate: async (event) => {
      order.push("evaluate");
      options.onEvaluate?.(event);
      return options.evaluate?.(event) ?? askEvaluation(event);
    },
    approvalDeadlineMs: () => Date.now() + 1_000,
    waitForApproval: async (approvalId) => {
      order.push("wait");
      return (
        (await options.waitForApproval?.(approvalId)) ?? {
          status: "resolved",
          decision: "allow_once",
          resolution_source: "human",
        }
      );
    },
    consumeExecutionLease: async (approvalId, binding) => {
      order.push("consume");
      return (
        (await options.consumeExecutionLease?.(approvalId, binding)) ?? {
          leaseId: "lease-rte05-001",
          consumptionId: "consume-rte05-001",
          expiresAt: new Date(Date.now() + 60_000).toISOString(),
        }
      );
    },
  };
  const context = {
    api: {
      on(name, handler, hookOptions = {}) {
        handlers[name] = handler;
        handlerOptions[name] = hookOptions;
      },
    },
    config: { ...BASE_CONFIG, ...(options.config ?? {}) },
    makeClient: () => options.client ?? client,
    outcomeDelivery: {
      submit(receipt) {
        receipts.push(receipt);
        return Promise.resolve();
      },
    },
    sessionState: new Map(),
    toolCallState,
    degradations,
  };
  return {
    client,
    context,
    degradations,
    handlers,
    handlerOptions,
    invocations,
    order,
    receipts,
    toolCallState,
  };
}

function registerToolHarness(harness) {
  registerBeforeToolCall(harness.context);
  registerAfterToolCall(harness.context);
}

async function runToolHost(harness, event, context) {
  const before = await harness.handlers.before_tool_call(event, context);
  if (before?.block === true) {
    return { blocked: true };
  }
  harness.order.push("invoke");
  harness.invocations.push(event.toolCallId);
  harness.invokedParams = before?.params ?? event.params;
  harness.handlers.after_tool_call(
    { ...event, result: { ok: true } },
    context,
  );
  return { blocked: false };
}

test("CF-13 exact human binding consumes before one tool invocation and correlates terminal IDs", async () => {
  let evaluatedEvent;
  const harness = makeHarness({
    onEvaluate(event) {
      evaluatedEvent = event;
    },
  });
  registerToolHarness(harness);
  const event = {
    toolName: "write_file",
    toolCallId: "call-cf13",
    runId: "run-cf13",
    params: {
      path: "/tmp/cf13.txt",
      content: "safe",
      task_id: "attacker-controlled-tool-argument",
    },
  };
  const context = {
    toolName: "write_file",
    toolCallId: "call-cf13",
    runId: "run-cf13",
    taskId: "task-host-trusted",
    agentId: "agent-rte05",
  };

  const result = await runToolHost(harness, event, context);
  assert.equal(result.blocked, false);
  assert.deepEqual(harness.order, ["evaluate", "wait", "consume", "invoke"]);
  assert.equal(harness.invocations.length, 1);
  assert.equal(evaluatedEvent.metadata.task_id, "task-host-trusted");

  assert.equal(harness.receipts.length, 2);
  const [release, terminal] = harness.receipts;
  assert.equal(release.metadata.outcome_kind, "approval_release");
  assert.equal(release.evidence.execution.status, "unknown");
  assert.equal(terminal.metadata.outcome_kind, "execution_completed");
  assert.equal(terminal.evidence.execution.status, "executed");
  for (const receipt of harness.receipts) {
    assert.equal(receipt.links.action_id, "call-cf13");
    assert.equal(receipt.links.lease_id, "lease-rte05-001");
    assert.equal(receipt.links.consumption_id, "consume-rte05-001");
    assert.deepEqual(receipt.evidence.enforcement, {
      gate_state: "approval_released",
      binding_check_status: "passed",
      lease_consume_outcome: "consumed",
      reason_codes: ["rte-05:binding_exact", "rte-05:lease_consumed"],
    });
  }

  const state = harness.toolCallState.get("call-cf13");
  assert.equal(state.leaseId, "lease-rte05-001");
  assert.equal(state.consumptionId, "consume-rte05-001");
  assert.equal("enforcement_binding" in state.evaluation, false);
  const serialized = JSON.stringify({
    state,
    receipts: harness.receipts,
  });
  assert.equal(serialized.includes(FINGERPRINT), false);
  assert.equal(serialized.includes(LEASE_TOKEN), false);
});

test("CF-14 mutation during approval wait fails binding before consume and invocation", async () => {
  const event = {
    toolName: "write_file",
    toolCallId: "call-cf14",
    runId: "run-cf14",
    params: { path: "/tmp/approved.txt", content: "approved" },
  };
  let consumes = 0;
  const harness = makeHarness({
    async waitForApproval() {
      event.params.path = "/tmp/swapped-after-evaluate.txt";
      return {
        status: "resolved",
        decision: "allow_once",
        resolution_source: "human",
      };
    },
    async consumeExecutionLease() {
      consumes += 1;
      throw new Error("must not consume a drifted action");
    },
  });
  registerToolHarness(harness);

  const result = await runToolHost(harness, event, {
    toolName: "write_file",
    toolCallId: "call-cf14",
    runId: "run-cf14",
    taskId: "task-cf14",
    agentId: "agent-rte05",
  });
  assert.equal(result.blocked, true);
  assert.equal(consumes, 0);
  assert.equal(harness.invocations.length, 0);
  assert.deepEqual(harness.order, ["evaluate", "wait"]);
  const receipt = harness.receipts.at(-1);
  assert.equal(receipt.metadata.outcome_kind, "pre_execution_deny");
  assert.equal(receipt.evidence.execution.status, "not_invoked");
  assert.equal(receipt.evidence.enforcement.gate_state, "binding_failed");
  assert.equal(receipt.evidence.enforcement.binding_check_status, "failed");
  assert.deepEqual(receipt.evidence.enforcement.reason_codes, [
    "rte-05:binding_mismatch",
  ]);
  assert.equal(
    harness.toolCallState.get("call-cf14").toolParams.path,
    "/tmp/approved.txt",
    "authoritative mapped event is a deep snapshot, not the mutated host object",
  );
});

test("CF-14 mutation during lease consume fails closed after consuming and before invocation", async () => {
  const event = {
    toolName: "write_file",
    toolCallId: "call-cf14-post-consume",
    runId: "run-cf14-post-consume",
    params: { path: "/tmp/approved.txt", nested: { content: "approved" } },
  };
  const harness = makeHarness({
    async consumeExecutionLease() {
      event.params.path = "/tmp/swapped-during-consume.txt";
      return {
        leaseId: "lease-post-consume",
        consumptionId: "consume-post-consume",
        expiresAt: new Date(Date.now() + 60_000).toISOString(),
      };
    },
  });
  registerToolHarness(harness);

  const result = await runToolHost(harness, event, {
    toolName: "write_file",
    toolCallId: "call-cf14-post-consume",
    runId: "run-cf14-post-consume",
    taskId: "task-cf14-post-consume",
    agentId: "agent-rte05",
  });

  assert.equal(result.blocked, true);
  assert.equal(harness.invocations.length, 0);
  assert.deepEqual(harness.order, ["evaluate", "wait", "consume"]);
  const receipt = harness.receipts.at(-1);
  assert.equal(receipt.links.lease_id, "lease-post-consume");
  assert.equal(receipt.links.consumption_id, "consume-post-consume");
  assert.deepEqual(receipt.evidence.enforcement, {
    gate_state: "binding_failed",
    binding_check_status: "failed",
    lease_consume_outcome: "consumed",
    reason_codes: ["rte-05:binding_mismatch", "rte-05:lease_consumed"],
  });
});

test("CF-14 strong tool release returns a deep approved params snapshot", async () => {
  const event = {
    toolName: "write_file",
    toolCallId: "call-cf14-approved-copy",
    runId: "run-cf14-approved-copy",
    params: { path: "/tmp/approved.txt", nested: { content: "approved" } },
  };
  const harness = makeHarness();
  registerBeforeToolCall(harness.context);

  const result = await harness.handlers.before_tool_call(event, {
    toolName: "write_file",
    toolCallId: "call-cf14-approved-copy",
    runId: "run-cf14-approved-copy",
    taskId: "task-cf14-approved-copy",
    agentId: "agent-rte05",
  });
  event.params.path = "/tmp/mutated-after-release.txt";
  event.params.nested.content = "mutated";

  assert.notEqual(result.params, event.params);
  assert.notEqual(result.params.nested, event.params.nested);
  assert.deepEqual(result.params, {
    path: "/tmp/approved.txt",
    nested: { content: "approved" },
  });
});

test("CF-14 full outbound message revalidation detects drift beyond the truncated preview", async () => {
  const prefix = "x".repeat(2_100);
  const event = {
    to: "security@example.test",
    content: `${prefix}:approved-tail`,
    threadId: "thread-cf14-message",
  };
  let consumes = 0;
  const harness = makeHarness({
    async waitForApproval() {
      event.content = `${prefix}:swapped-tail`;
      return {
        status: "resolved",
        decision: "allow_once",
        resolution_source: "human",
      };
    },
    async consumeExecutionLease() {
      consumes += 1;
      return {
        leaseId: "lease-never",
        consumptionId: "consume-never",
        expiresAt: new Date(Date.now() + 60_000).toISOString(),
      };
    },
  });
  registerMessageSending(harness.context);

  const result = await harness.handlers.message_sending(event, {
    channelId: "email",
    runId: "run-cf14-message",
    taskId: "task-cf14-message",
  });
  assert.equal(result.cancel, true);
  assert.equal(consumes, 0);
  assert.equal(harness.receipts.at(-1).evidence.execution.status, "not_invoked");
  assert.deepEqual(
    harness.receipts.at(-1).evidence.enforcement.reason_codes,
    ["rte-05:binding_mismatch"],
  );
});

test("CF-13 strong outbound message succeeds despite regenerated GuardEvent IDs", async () => {
  let sends = 0;
  const harness = makeHarness();
  registerMessageSending(harness.context);
  const event = {
    to: "security@example.test",
    content: "approved outbound message",
    threadId: "thread-cf13-message",
    replyToId: "message-parent",
  };
  const result = await harness.handlers.message_sending(event, {
    channelId: "email",
    runId: "run-cf13-message",
    taskId: "task-cf13-message",
  });
  if (result?.content === event.content) {
    sends += 1;
  }
  assert.equal(sends, 1);
  assert.deepEqual(harness.order, ["evaluate", "wait", "consume"]);
  assert.equal(harness.receipts.length, 1);
  assert.equal(harness.receipts[0].metadata.outcome_kind, "approval_release");
  assert.equal(
    harness.receipts[0].links.action_id,
    `act_${harness.receipts[0].links.event_id}`,
  );
  assert.equal(harness.receipts[0].links.lease_id, "lease-rte05-001");
});

test("CF-14 outbound metadata, attachments, and mediaUrls are in the exact snapshot", async () => {
  const cases = [
    {
      label: "metadata",
      mutate: (event) => {
        event.metadata.disposition = "secret";
      },
    },
    {
      label: "attachments",
      mutate: (event) => {
        event.attachments[0].path = "/tmp/secret.txt";
      },
    },
    {
      label: "mediaUrls",
      mutate: (event) => {
        event.mediaUrls[0] = "file:///tmp/secret.txt";
      },
    },
  ];

  for (const item of cases) {
    const event = {
      to: "security@example.test",
      content: "approved outbound message",
      metadata: { disposition: "attachment" },
      attachments: [{ path: "/tmp/approved.txt", name: "approved.txt" }],
      mediaUrls: ["file:///tmp/approved.txt"],
    };
    let consumes = 0;
    const harness = makeHarness({
      async waitForApproval() {
        item.mutate(event);
        return {
          status: "resolved",
          decision: "allow_once",
          resolution_source: "human",
        };
      },
      async consumeExecutionLease() {
        consumes += 1;
        throw new Error("mutated outbound input must not consume");
      },
    });
    registerMessageSending(harness.context);

    const result = await harness.handlers.message_sending(event, {
      channelId: "email",
      runId: `run-cf14-message-${item.label}`,
      taskId: `task-cf14-message-${item.label}`,
    });

    assert.equal(result.cancel, true, item.label);
    assert.equal(consumes, 0, item.label);
  }
});

test("strong enforcement hooks register at the last practical priority", () => {
  const harness = makeHarness();
  registerBeforeToolCall(harness.context);
  registerMessageSending(harness.context);

  assert.equal(
    harness.handlerOptions.before_tool_call.priority,
    Number.MIN_SAFE_INTEGER,
  );
  assert.equal(
    harness.handlerOptions.message_sending.priority,
    Number.MIN_SAFE_INTEGER,
  );
});

test("message_sending catches a stalled Guard API body locally and cancels", async () => {
  const realClient = new GuardApiClient({
    config: { ...BASE_CONFIG, requestTimeoutMs: 20, approvalTimeoutMs: 20 },
    fetchImpl: async () =>
      new Response(
        new ReadableStream({
          start(controller) {
            controller.enqueue(new TextEncoder().encode('{"decision":'));
          },
        }),
        { status: 200, headers: { "content-type": "application/json" } },
      ),
  });
  const harness = makeHarness({ client: realClient });
  registerMessageSending(harness.context);

  const outcome = await Promise.race([
    harness.handlers.message_sending(
      { to: "security@example.test", content: "must not escape" },
      { channelId: "email", runId: "run-stalled-message" },
    ),
    new Promise((resolve) => setTimeout(() => resolve("hung"), 200)),
  ]);

  assert.notEqual(outcome, "hung");
  assert.equal(outcome.cancel, true);
});

test("CF-15 consume retries identical bytes and returns no plaintext token", async () => {
  const requests = [];
  let calls = 0;
  const client = new GuardApiClient({
    config: BASE_CONFIG,
    fetchImpl: async (url, init) => {
      calls += 1;
      requests.push({ url, body: init.body });
      if (calls === 1) {
        return Response.json(
          { error: { code: "EXECUTION_LEASE_UNAVAILABLE" } },
          { status: 503 },
        );
      }
      return Response.json({
        lease_id: "lease.cf15",
        consumption_id: "consume.cf15",
        lease_token: LEASE_TOKEN,
        expires_at: new Date(Date.now() + 60_000).toISOString(),
      });
    },
  });
  const binding = {
    schema_version: "2.1",
    action_id: "call-cf15",
    authorization_fingerprint: FINGERPRINT,
    runtime_binding_id: "binding:cf15",
    requires_execution_lease: true,
  };

  const lease = await client.consumeExecutionLease(
    "approval-cf15",
    binding,
    Date.now() + 1_000,
  );
  assert.equal(calls, 2);
  assert.equal(requests[0].body, requests[1].body);
  assert.deepEqual(JSON.parse(requests[0].body), {
    action_id: "call-cf15",
    authorization_fingerprint: FINGERPRINT,
  });
  assert.deepEqual(Object.keys(lease).sort(), [
    "consumptionId",
    "expiresAt",
    "leaseId",
  ]);
  assert.equal(JSON.stringify(lease).includes(LEASE_TOKEN), false);
});

test("CF-15 consume rejects exact conflicts/expiry and malformed success without retry", async () => {
  const binding = {
    schema_version: "2.1",
    action_id: "call-cf15-errors",
    authorization_fingerprint: FINGERPRINT,
    runtime_binding_id: "binding:cf15-errors",
    requires_execution_lease: true,
  };
  const cases = [
    [409, "APPROVAL_NOT_CONSUMABLE", "approval_not_consumable"],
    [409, "APPROVAL_CONSUMPTION_CONFLICT", "consumption_conflict"],
    [409, "UNTRUSTED_FREE_TEXT", "rejected"],
    [410, "APPROVAL_EXPIRED", "approval_expired"],
    [410, "EXECUTION_LEASE_EXPIRED", "lease_expired"],
    [410, "UNTRUSTED_FREE_TEXT", "rejected"],
  ];
  for (const [status, code, expectedFailure] of cases) {
    let calls = 0;
    const client = new GuardApiClient({
      config: BASE_CONFIG,
      fetchImpl: async () => {
        calls += 1;
        return Response.json({ error: { code } }, { status });
      },
    });
    await assert.rejects(
      client.consumeExecutionLease(
        "approval-cf15-errors",
        binding,
        Date.now() + 1_000,
      ),
      (error) =>
        error instanceof ExecutionLeaseConsumeError &&
        error.failure === expectedFailure &&
        (code === "UNTRUSTED_FREE_TEXT" ? error.code === null : true),
    );
    assert.equal(calls, 1, `${status}/${code} must not retry`);
  }

  for (const malformed of [
    {
      lease_id: "lease cf15 invalid space",
      consumption_id: "consume.cf15",
      lease_token: LEASE_TOKEN,
      expires_at: new Date(Date.now() + 60_000).toISOString(),
    },
    {
      lease_id: "lease.cf15",
      consumption_id: "consume.cf15",
      lease_token: "not-a-frozen-lease-token",
      expires_at: new Date(Date.now() + 60_000).toISOString(),
    },
    {
      lease_id: "lease.cf15",
      consumption_id: "consume.cf15",
      lease_token: LEASE_TOKEN,
      expires_at: "2026-02-30T12:00:00Z",
    },
    {
      lease_id: "lease.cf15",
      consumption_id: "consume.cf15",
      lease_token: LEASE_TOKEN,
      expires_at: new Date(Date.now() + 60_000).toISOString(),
      extra: "forbidden",
    },
    {
      lease_id: `l${"x".repeat(160)}`,
      consumption_id: "consume.cf15",
      lease_token: LEASE_TOKEN,
      expires_at: new Date(Date.now() + 60_000).toISOString(),
    },
  ]) {
    const client = new GuardApiClient({
      config: BASE_CONFIG,
      fetchImpl: async () => Response.json(malformed),
    });
    await assert.rejects(
      client.consumeExecutionLease(
        "approval-cf15-malformed",
        binding,
        Date.now() + 1_000,
      ),
      (error) =>
        error instanceof ExecutionLeaseConsumeError &&
        error.failure === "invalid_response",
    );
  }
});

test("CF-15 conflict, expiry, and unavailable consume outcomes all keep invocation at zero", async () => {
  for (const [failure, reason, outcome] of [
    ["consumption_conflict", "rte-05:consumption_conflict", "rejected"],
    ["approval_expired", "rte-05:approval_expired", "expired"],
    ["lease_expired", "rte-05:lease_expired", "expired"],
    ["lease_unavailable", "rte-05:lease_unavailable", "unknown"],
  ]) {
    const harness = makeHarness({
      consumeExecutionLease: async () => {
        throw new ExecutionLeaseConsumeError(failure);
      },
    });
    registerToolHarness(harness);
    const result = await runToolHost(
      harness,
      {
        toolName: "shell",
        toolCallId: `call-${failure}`,
        runId: `run-${failure}`,
        params: { command: `echo ${failure}` },
      },
      {
        toolName: "shell",
        toolCallId: `call-${failure}`,
        runId: `run-${failure}`,
        taskId: `task-${failure}`,
        agentId: "agent-rte05",
      },
    );
    assert.equal(result.blocked, true, failure);
    assert.equal(harness.invocations.length, 0, failure);
    const receipt = harness.receipts.at(-1);
    assert.equal(receipt.evidence.execution.status, "not_invoked", failure);
    assert.equal(receipt.evidence.enforcement.lease_consume_outcome, outcome);
    assert.equal(receipt.evidence.enforcement.reason_codes.includes(reason), true);
  }
});

test("CF-15 transport diagnostics never echo fingerprint, lease token, or adapter token", async () => {
  const logs = [];
  const client = new GuardApiClient({
    config: { ...BASE_CONFIG, diagnosticLogging: true },
    fetchImpl: async () => {
      throw new Error(
        `transport echoed ${FINGERPRINT} ${LEASE_TOKEN} ${BASE_CONFIG.adapterToken}`,
      );
    },
  });
  const originalWarn = console.warn;
  console.warn = (...parts) => logs.push(parts.join(" "));
  try {
    await assert.rejects(
      client.consumeExecutionLease(
        "approval-cf15-secret-log",
        {
          schema_version: "2.1",
          action_id: "call-cf15-secret-log",
          authorization_fingerprint: FINGERPRINT,
          runtime_binding_id: BASE_CONFIG.runtimeBindingId,
          requires_execution_lease: true,
        },
        Date.now() + 1_000,
      ),
      (error) =>
        error instanceof ExecutionLeaseConsumeError &&
        error.failure === "lease_unavailable",
    );
  } finally {
    console.warn = originalWarn;
  }
  const rendered = logs.join("\n");
  assert.equal(rendered.includes(FINGERPRINT), false);
  assert.equal(rendered.includes(LEASE_TOKEN), false);
  assert.equal(rendered.includes(BASE_CONFIG.adapterToken), false);
  assert.match(rendered, /"error_type":"error"/);
});

test("CF-16 LLM allow_once is isolated and server binding overrides observe/default-off runtime", async () => {
  let consumes = 0;
  const harness = makeHarness({
    config: {
      enforcementMode: "observe",
      strongApprovalBindingEnabled: false,
    },
    waitForApproval: async () => ({
      status: "resolved",
      decision: "allow_once",
      resolution_source: "llm",
    }),
    consumeExecutionLease: async () => {
      consumes += 1;
      throw new Error("LLM resolution must never consume");
    },
  });
  registerToolHarness(harness);
  const result = await runToolHost(
    harness,
    {
      toolName: "shell",
      toolCallId: "call-cf16",
      runId: "run-cf16",
      params: { command: "echo isolated" },
    },
    {
      toolName: "shell",
      toolCallId: "call-cf16",
      runId: "run-cf16",
      taskId: "task-cf16",
      agentId: "agent-rte05",
    },
  );
  assert.equal(result.blocked, true);
  assert.equal(consumes, 0);
  assert.equal(harness.invocations.length, 0);
  assert.deepEqual(harness.receipts.at(-1).evidence.enforcement.reason_codes, [
    "rte-05:binding_exact",
    "rte-05:approval_not_human",
  ]);
});

test("CF-15 malformed approval wait is converted to a structured deny receipt", async () => {
  let consumes = 0;
  const harness = makeHarness({
    waitForApproval: async () => {
      throw new Error("malformed wait response");
    },
    consumeExecutionLease: async () => {
      consumes += 1;
      throw new Error("malformed wait must not consume");
    },
  });
  registerToolHarness(harness);
  const result = await runToolHost(
    harness,
    {
      toolName: "shell",
      toolCallId: "call-malformed-wait",
      runId: "run-malformed-wait",
      params: { command: "echo malformed" },
    },
    {
      toolName: "shell",
      toolCallId: "call-malformed-wait",
      runId: "run-malformed-wait",
      taskId: "task-malformed-wait",
      agentId: "agent-rte05",
    },
  );
  assert.equal(result.blocked, true);
  assert.equal(consumes, 0);
  assert.equal(harness.invocations.length, 0);
  assert.equal(harness.receipts.length, 1);
  assert.equal(harness.receipts[0].evidence.execution.status, "not_invoked");
  assert.deepEqual(harness.receipts[0].evidence.enforcement.reason_codes, [
    "rte-05:binding_exact",
    "rte-05:lease_response_invalid",
  ]);
});

test("CF-15 approval client rejects non-canonical wait status", async () => {
  const client = new GuardApiClient({
    config: BASE_CONFIG,
    fetchImpl: async () =>
      Response.json({
        status: "invented-status",
        decision: "allow_once",
        resolution_source: "human",
      }),
  });
  await assert.rejects(
    client.waitForApproval("approval-invalid-wait", Date.now() + 1_000),
    (error) =>
      error.name === "GuardApiError" &&
      error.message === "Guard API approval response is invalid",
  );
});

test("CF-16 malformed declared binding fails closed in observe mode", async () => {
  let waits = 0;
  const harness = makeHarness({
    config: { enforcementMode: "observe" },
    evaluate(event) {
      return askEvaluation(event, { binding: { invalid: true } });
    },
    waitForApproval: async () => {
      waits += 1;
      return { status: "resolved", decision: "allow_once", resolution_source: "human" };
    },
  });
  registerToolHarness(harness);
  const result = await runToolHost(
    harness,
    {
      toolName: "shell",
      toolCallId: "call-cf16-invalid",
      runId: "run-cf16-invalid",
      params: { command: "echo invalid" },
    },
    {
      toolName: "shell",
      toolCallId: "call-cf16-invalid",
      runId: "run-cf16-invalid",
      taskId: "task-cf16-invalid",
    },
  );
  assert.equal(result.blocked, true);
  assert.equal(waits, 0);
  assert.equal(harness.invocations.length, 0);
  assert.deepEqual(harness.receipts.at(-1).evidence.enforcement.reason_codes, [
    "rte-05:binding_invalid",
  ]);
});

test("CF-16 evaluation parser preserves only an invalid-binding signal, never its fingerprint", async () => {
  const client = new GuardApiClient({
    config: BASE_CONFIG,
    fetchImpl: async () =>
      Response.json({
        decision: {
          decision_id: "dec-malformed-binding",
          decision: "ask",
          risk_score: 70,
          severity: "high",
          reason: "malformed binding",
        },
        approval: {
          approval_id: "approval-malformed-binding",
          status: "pending",
          decision_options: ["allow_once", "deny"],
        },
        policy_audit_id: "policy-malformed-binding",
        enforcement_binding: {
          schema_version: "2.1",
          action_id: "call-malformed-binding",
          authorization_fingerprint: FINGERPRINT,
          runtime_binding_id: "invalid binding with spaces",
          requires_execution_lease: true,
        },
      }),
  });
  const parsed = await client.evaluate({ event_id: "evt-malformed-binding" });
  assert.deepEqual(parsed.enforcement_binding, { invalid: true });
  assert.equal(JSON.stringify(parsed).includes(FINGERPRINT), false);
});

test("CF-14 trusted runtime binding provisioning must exactly match before wait or consume", async () => {
  let waits = 0;
  let consumes = 0;
  const harness = makeHarness({
    config: { runtimeBindingId: "binding:openclaw:different-runtime" },
    waitForApproval: async () => {
      waits += 1;
      return { status: "resolved", decision: "allow_once", resolution_source: "human" };
    },
    consumeExecutionLease: async () => {
      consumes += 1;
      throw new Error("mismatched runtime binding must not consume");
    },
  });
  registerToolHarness(harness);
  const result = await runToolHost(
    harness,
    {
      toolName: "shell",
      toolCallId: "call-runtime-binding-mismatch",
      runId: "run-runtime-binding-mismatch",
      params: { command: "echo mismatch" },
    },
    {
      toolName: "shell",
      toolCallId: "call-runtime-binding-mismatch",
      runId: "run-runtime-binding-mismatch",
      taskId: "task-runtime-binding-mismatch",
    },
  );
  assert.equal(result.blocked, true);
  assert.equal(waits, 0);
  assert.equal(consumes, 0);
  assert.equal(harness.invocations.length, 0);
  assert.deepEqual(harness.receipts.at(-1).evidence.enforcement.reason_codes, [
    "rte-05:binding_mismatch",
  ]);
});

test("CF-17 strong tool binding without a native call ID fails before consumption", async () => {
  let waits = 0;
  let consumes = 0;
  const harness = makeHarness({
    waitForApproval: async () => {
      waits += 1;
      return { status: "resolved", decision: "allow_once", resolution_source: "human" };
    },
    consumeExecutionLease: async () => {
      consumes += 1;
      throw new Error("local fallback correlation must not consume");
    },
  });
  registerBeforeToolCall(harness.context);
  const result = await harness.handlers.before_tool_call(
    {
      toolName: "shell",
      runId: "run-local-fallback",
      params: { command: "echo no-native-id" },
    },
    {
      toolName: "shell",
      runId: "run-local-fallback",
      taskId: "task-local-fallback",
    },
  );
  assert.equal(result.block, true);
  assert.equal(waits, 0);
  assert.equal(consumes, 0);
  assert.equal(
    harness.degradations.snapshot().byReason
      .after_tool_call_local_fallback_correlation,
    1,
  );
  assert.deepEqual(harness.receipts.at(-1).evidence.enforcement.reason_codes, [
    "rte-05:binding_mismatch",
  ]);
});

test("CF-17 the 501st protected tool call is rejected without silent eviction and demotes C3", async () => {
  let consumes = 0;
  const harness = makeHarness({
    config: { strongApprovalBindingEnabled: true },
    evaluate(event) {
      return event.payload.tool.call_id === "call-capacity-501"
        ? askEvaluation(event)
        : allowEvaluation(event);
    },
    consumeExecutionLease: async () => {
      consumes += 1;
      throw new Error("capacity failure must precede consume");
    },
  });
  registerBeforeToolCall(harness.context);
  const context = {
    toolName: "long_running",
    runId: "run-cf17",
    taskId: "task-cf17",
    agentId: "agent-rte05",
  };

  for (let index = 1; index <= 500; index += 1) {
    const toolCallId = `call-capacity-${index}`;
    const result = await harness.handlers.before_tool_call(
      {
        toolName: "long_running",
        toolCallId,
        runId: "run-cf17",
        params: { index },
      },
      { ...context, toolCallId },
    );
    assert.equal(result, undefined);
  }
  assert.equal(harness.toolCallState.size, 500);
  assert.equal(harness.toolCallState.has("call-capacity-1"), true);

  const overflow = await harness.handlers.before_tool_call(
    {
      toolName: "long_running",
      toolCallId: "call-capacity-501",
      runId: "run-cf17",
      params: { index: 501 },
    },
    { ...context, toolCallId: "call-capacity-501" },
  );
  assert.equal(overflow.block, true);
  assert.equal(consumes, 0);
  assert.equal(harness.toolCallState.size, 500);
  assert.equal(harness.toolCallState.has("call-capacity-1"), true);
  assert.equal(harness.toolCallState.has("call-capacity-500"), true);
  assert.equal(harness.toolCallState.has("call-capacity-501"), false);
  assert.deepEqual(harness.receipts.at(-1).evidence.enforcement, {
    gate_state: "binding_failed",
    binding_check_status: "not_performed",
    lease_consume_outcome: "not_attempted",
    reason_codes: ["rte-05:correlation_capacity_exhausted"],
  });
  assert.equal(
    harness.degradations.snapshot().byReason.tool_call_state_capacity_exhausted,
    1,
  );
  const capability = buildRuntimeEnforcementCapability(harness.degradations, {
    activationEnabled: true,
    enforcementMode: "enforce",
    runtimeBindingId: "binding:openclaw:agent-rte05",
  });
  assert.equal(capability.profiles.C3_strong_approval_binding, false);
});

test("CF-17 a duplicate active native toolCallId fails closed without overwriting correlation state", async () => {
  let evaluations = 0;
  const harness = makeHarness({
    evaluate(event) {
      evaluations += 1;
      return allowEvaluation(event);
    },
  });
  registerBeforeToolCall(harness.context);
  const context = {
    toolName: "write_file",
    toolCallId: "call-duplicate-active",
    runId: "run-duplicate-active",
    taskId: "task-duplicate-active",
    agentId: "agent-rte05",
  };

  const first = await harness.handlers.before_tool_call(
    {
      toolName: "write_file",
      toolCallId: "call-duplicate-active",
      runId: "run-duplicate-active",
      params: { path: "/tmp/first.txt" },
    },
    context,
  );
  const original = harness.toolCallState.get("call-duplicate-active");
  const second = await harness.handlers.before_tool_call(
    {
      toolName: "write_file",
      toolCallId: "call-duplicate-active",
      runId: "run-duplicate-active",
      params: { path: "/tmp/replacement.txt" },
    },
    context,
  );

  assert.equal(first, undefined);
  assert.equal(second.block, true);
  assert.equal(evaluations, 1);
  assert.equal(harness.toolCallState.get("call-duplicate-active"), original);
  assert.equal(original.toolParams.path, "/tmp/first.txt");
  assert.equal(
    harness.degradations.snapshot().byReason
      .tool_call_state_duplicate_active_id,
    1,
  );
});

test("runtime evidence rejects free text, illegal enums, duplicates, and inconsistent lease links before spooling", async () => {
  const guardEvent = {
    schema_version: "0.3",
    event_id: "evt-rte05-validation",
    event_type: "tool_call_proposed",
    runtime: "openclaw",
    trace_id: "trace-rte05-validation",
    timestamp: new Date().toISOString(),
    pre_execution: true,
    security_context: {
      user_task: "validate receipt",
      source_type: "user",
      source_trust: "trusted",
      agent_id: "agent-rte05",
      current_step: "before_tool_call",
      context_sources: [],
      derived_paths: [],
      metadata: {},
    },
    payload: {
      tool: { name: "probe", category: "tool", call_id: "call-validation" },
      arguments: {},
      derived_resources: [],
    },
    metadata: {},
  };
  const evaluation = askEvaluation(guardEvent);
  const valid = buildRuntimeOutcomeAuditEvent(
    guardEvent,
    evaluation,
    "approval_release",
    {
      approval: {
        approvalId: evaluation.approval.approval_id,
        status: "allowed",
        decision: "allow_once",
      },
      lease: { leaseId: "lease.validation", consumptionId: "consume.validation" },
      enforcement: {
        gate_state: "approval_released",
        binding_check_status: "passed",
        lease_consume_outcome: "consumed",
        reason_codes: ["rte-05:binding_exact", "rte-05:lease_consumed"],
      },
    },
  );
  assert.throws(
    () =>
      buildRuntimeOutcomeAuditEvent(
        guardEvent,
        evaluation,
        "approval_release",
        {
          approval: {
            approvalId: evaluation.approval.approval_id,
            status: "allowed",
            decision: "allow_once",
          },
          lease: {
            leaseId: "lease.validation",
            consumptionId: "consume.validation",
          },
          enforcement: {
            gate_state: "approval_released",
            binding_check_status: "passed",
            lease_consume_outcome: "consumed",
            reason_codes: ["unbounded-free-text"],
          },
        },
      ),
    /canonical reason codes/,
  );
  const invalidReceipts = [];
  for (const mutate of [
    (receipt) => receipt.evidence.enforcement.reason_codes.push("free-text"),
    (receipt) => receipt.evidence.enforcement.reason_codes.push("rte-05:binding_exact"),
    (receipt) => { receipt.evidence.enforcement.gate_state = "invented"; },
    (receipt) => { delete receipt.links.lease_id; },
    (receipt) => { receipt.links.lease_id = `l${"x".repeat(160)}`; },
    (receipt) => {
      receipt.evidence.enforcement.gate_state = "binding_failed";
    },
  ]) {
    const candidate = structuredClone(valid);
    mutate(candidate);
    invalidReceipts.push(candidate);
  }

  let submitted = 0;
  const delivery = new RuntimeOutcomeDelivery({
    spoolDirectory: join(
      tmpdir(),
      `agentguard-rte05-invalid-${process.pid}-${Date.now()}`,
    ),
    config: BASE_CONFIG,
    makeClient: () => ({ submitRuntimeOutcome: async () => { submitted += 1; } }),
  });
  const originalError = console.error;
  console.error = () => undefined;
  try {
    for (const receipt of invalidReceipts) {
      await delivery.submit(
        receipt,
        { submitRuntimeOutcome: async () => { submitted += 1; } },
        "rte05-invalid",
      );
    }
  } finally {
    console.error = originalError;
  }
  assert.equal(submitted, 0);
});
