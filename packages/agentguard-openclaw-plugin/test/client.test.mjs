import assert from "node:assert/strict";
import test from "node:test";
import {
  OPENCLAW_REQUIRED_HOOK_COUNT,
  OPENCLAW_REQUIRED_HOOKS,
} from "../hook-contract.mjs";

import {
  GuardApiClient,
  buildPluginConfig,
  decisionToMessageResult,
  decisionToToolResult,
} from "../dist/guard-api-client.js";

const allowDecision = {
  decision: { decision: "allow", reason: "ok", safe_message: null },
  approval: null,
};
const denyDecision = {
  decision: { decision: "deny", reason: "blocked", safe_message: "no" },
  approval: null,
};
const askDecision = {
  decision: { decision: "ask", reason: "review", safe_message: "needs review" },
  approval: {
    approval_id: "app_001",
    status: "pending",
    decision_options: ["allow_once", "deny"],
  },
};

const BLOCKED_ACTION_GUIDANCE =
  "This action was blocked by AgentGuard and was NOT executed. Do not automatically retry the same blocked action. If the task cannot be completed without it, clearly tell the user that AgentGuard blocked the action.";
const APPROVAL_NOT_GRANTED_GUIDANCE =
  "This action required AgentGuard approval, but approval was not granted; the action was NOT executed. Do not automatically retry the same action. If the task cannot be completed without it, clearly tell the user that AgentGuard approval was not granted.";
const REVIEW_DENIED_GUIDANCE =
  "This action was denied by AgentGuard review and was NOT executed. Do not automatically retry the same denied action. If the task cannot be completed without it, clearly tell the user that AgentGuard review denied the action.";
const APPROVAL_EXPIRED_GUIDANCE =
  "AgentGuard approval timed out or expired before this action could run; the action was NOT executed. Do not automatically retry the same action. If the task cannot be completed without it, clearly tell the user that AgentGuard approval expired.";

function runtimeOutcomeReceipt(
  eventId = "evt_001",
  outcomeKind = "pre_execution_deny",
) {
  return {
    audit_id: `audit_outcome_${eventId}_${outcomeKind}`,
    schema_version: "0.4",
    record_type: "runtime_outcome",
    trace_id: "run_outcome",
    runtime: "openclaw",
    timestamp: "2026-08-09T00:00:00.000Z",
    stage: "before_tool_call",
    event_type: "runtime_outcome",
    summary: "denied",
    decision: "deny",
    risk_score: 90,
    severity: "high",
    blocked: true,
    resource_targets: [],
    rule_hits: [],
    reason: "deny",
    links: {
      event_id: eventId,
      decision_id: `decision_${eventId}`,
      policy_audit_id: `audit_policy_${eventId}`,
    },
    latency_ms: null,
    metadata: { agent_id: "main", outcome_kind: outcomeKind },
    evidence: {
      intervention: { type: "policy_deny", reason: "deny" },
      execution: {
        status: "not_invoked",
        receipt_recorded: true,
        invoked_at: null,
        completed_at: "2026-08-09T00:00:00.000Z",
        error: null,
        tool_result_entered_context: false,
        persisted: false,
      },
      side_effects: {
        measurement_status: "measured",
        count: 0,
        summary: "Tool was not invoked",
      },
      result: {
        disposition: "not_applicable",
        summary: null,
        sanitized: false,
      },
      approval: {
        approval_id: null,
        status: "not_required",
        decision: null,
        resolved_at: null,
      },
    },
  };
}

test("buildPluginConfig uses safe defaults with a resolved SecretRef token", () => {
  const config = buildPluginConfig({ adapterToken: "resolved-token" });

  assert.equal(config.guardApiBaseUrl, "http://127.0.0.1:8088");
  assert.equal(config.adapterToken, "resolved-token");
  assert.equal(config.enforcementMode, "enforce");
  assert.equal(config.requestTimeoutMs, 5000);
  assert.equal(config.approvalPollIntervalMs, 1000);
  assert.equal(config.approvalTimeoutMs, 25000);
  assert.equal(config.strongApprovalBindingEnabled, false);
  assert.equal(config.runtimeBindingId, "");
  assert.equal(config.diagnosticLogging, false);
  assert.equal(config.agentId, "main");
});

test("buildPluginConfig accepts the canonical public options", () => {
  const config = buildPluginConfig({
    adapterToken: "resolved-token",
    approvalTimeoutMs: 2500,
    strongApprovalBindingEnabled: true,
    runtimeBindingId: "binding:openclaw:main",
    diagnosticLogging: true,
    agentId: "openclaw-main",
    enforcementMode: "observe",
  });

  assert.equal(config.approvalTimeoutMs, 2500);
  assert.equal(config.strongApprovalBindingEnabled, true);
  assert.equal(config.runtimeBindingId, "binding:openclaw:main");
  assert.equal(config.diagnosticLogging, true);
  assert.equal(config.agentId, "openclaw-main");
  assert.equal(config.enforcementMode, "observe");
});

test("buildPluginConfig rejects an untrusted runtime binding identifier", () => {
  assert.throws(
    () =>
      buildPluginConfig({
        adapterToken: "resolved-token",
        runtimeBindingId: "binding id with spaces",
      }),
    /runtimeBindingId must be a 1-256 character trusted runtime identifier/,
  );
});

test("buildPluginConfig rejects a missing resolved SecretRef", () => {
  assert.throws(
    () => buildPluginConfig({}),
    /adapterToken must be configured through an OpenClaw SecretRef/,
  );
});

test("GuardApiClient sends bearer token without exposing it in errors", async () => {
  const requests = [];
  const client = new GuardApiClient({
    config: {
      guardApiBaseUrl: "https://guard.test",
      adapterToken: "secret-token",
      requestTimeoutMs: 1000,
      approvalPollIntervalMs: 10,
      approvalTimeoutMs: 10,
    },
    fetchImpl: async (url, init) => {
      requests.push({ url: String(url), init });
      return new Response(JSON.stringify(allowDecision), {
        status: 200,
        headers: { "content-type": "application/json" },
      });
    },
  });

  const result = await client.evaluate({ event_id: "evt_001" });

  assert.equal(result.decision.decision, "allow");
  assert.equal(requests[0].url, "https://guard.test/v1/guard/evaluate");
  assert.equal(requests[0].init.headers.Authorization, "Bearer secret-token");
});

test("GuardApiClient sends adapter heartbeat with capabilities and runtime identity", async () => {
  const requests = [];
  const client = new GuardApiClient({
    config: {
      guardApiBaseUrl: "https://guard.test",
      adapterToken: "secret-token",
      requestTimeoutMs: 1000,
      approvalPollIntervalMs: 10,
      approvalTimeoutMs: 10,
      diagnosticLogging: false,
      agentId: "openclaw-main",
    },
    fetchImpl: async (url, init) => {
      requests.push({
        url: String(url),
        init,
        body: JSON.parse(String(init.body)),
      });
      return new Response(
        JSON.stringify({ status: "loaded", loaded: true, runtime: "openclaw" }),
        {
          status: 200,
          headers: { "content-type": "application/json" },
        },
      );
    },
  });

  await client.submitHeartbeat({
    pluginVersion: "0.1.0-beta.1",
    runtimeVersion: "2026.6.6",
    hooks: ["before_tool_call", "message_sending"],
    capabilities: {
      event_types: ["tool_call_proposed", "message_send_proposed"],
    },
  });

  assert.equal(
    requests[0].url,
    "https://guard.test/v1/adapters/openclaw/heartbeat",
  );
  assert.equal(requests[0].init.headers.Authorization, "Bearer secret-token");
  assert.equal("runtime" in requests[0].body, false);
  assert.equal(requests[0].body.runtime_id, "openclaw");
  assert.equal(requests[0].body.agent_id, "openclaw-main");
  assert.equal(requests[0].body.plugin_version, "0.1.0-beta.1");
  assert.deepEqual(requests[0].body.hooks, [
    "before_tool_call",
    "message_sending",
  ]);
  assert.equal(requests[0].body.hook_count, 2);
  assert.equal(
    requests[0].body.expected_hook_count,
    OPENCLAW_REQUIRED_HOOK_COUNT,
  );
  assert.deepEqual(requests[0].body.fail_closed_stages, [
    "before_tool_call",
    "before_install",
    "before_agent_run",
    "before_agent_finalize",
    "tool_result_persist",
    "before_message_write",
  ]);
  assert.deepEqual(requests[0].body.capabilities.event_types, [
    "tool_call_proposed",
    "message_send_proposed",
  ]);
});

test("GuardApiClient falls back to the canonical hook contract for an empty heartbeat", async () => {
  const requests = [];
  const client = new GuardApiClient({
    config: {
      guardApiBaseUrl: "https://guard.test",
      adapterToken: "secret-token",
      requestTimeoutMs: 1000,
      approvalPollIntervalMs: 10,
      approvalTimeoutMs: 10,
    },
    fetchImpl: async (_url, init) => {
      requests.push(JSON.parse(String(init.body)));
      return new Response("{}", {
        status: 200,
        headers: { "content-type": "application/json" },
      });
    },
  });

  await client.submitHeartbeat({
    pluginVersion: "0.1.0-beta.1",
    hooks: [],
    capabilities: {},
  });

  assert.deepEqual(requests[0].hooks, [...OPENCLAW_REQUIRED_HOOKS]);
  assert.equal(requests[0].hook_count, OPENCLAW_REQUIRED_HOOK_COUNT);
  assert.equal(requests[0].expected_hook_count, OPENCLAW_REQUIRED_HOOK_COUNT);
});

test("GuardApiClient fail-closed errors do not include adapter token", async () => {
  const client = new GuardApiClient({
    config: {
      guardApiBaseUrl: "https://guard.test",
      adapterToken: "secret-token",
      requestTimeoutMs: 1000,
      approvalPollIntervalMs: 10,
      approvalTimeoutMs: 10,
    },
    fetchImpl: async () =>
      new Response("secret-token leaked by server", { status: 500 }),
  });

  await assert.rejects(
    () => client.evaluate({ event_id: "evt_001" }),
    (error) => {
      assert.equal(error.name, "GuardApiError");
      assert.equal(String(error.message).includes("secret-token"), false);
      return true;
    },
  );
});

test("decision adapters enforce allow deny ask and fail-closed results", async () => {
  assert.equal(await decisionToToolResult(allowDecision, {}), undefined);
  assert.deepEqual(await decisionToToolResult(denyDecision, {}), {
    block: true,
    blockReason: `no ${BLOCKED_ACTION_GUIDANCE}`,
  });

  assert.equal(await decisionToMessageResult(allowDecision, {}), undefined);
  assert.deepEqual(await decisionToMessageResult(denyDecision, {}), {
    cancel: true,
    cancelReason: `no ${BLOCKED_ACTION_GUIDANCE}`,
  });

  assert.equal(
    await decisionToToolResult(askDecision, {
      waitForApproval: async () => ({
        status: "resolved",
        decision: "allow_once",
      }),
    }),
    undefined,
  );
  assert.deepEqual(
    await decisionToMessageResult(askDecision, {
      waitForApproval: async () => ({ status: "resolved", decision: "deny" }),
    }),
    {
      cancel: true,
      cancelReason: `${REVIEW_DENIED_GUIDANCE} (approval_id=app_001)`,
    },
  );

  assert.deepEqual(
    await decisionToToolResult(askDecision, {
      waitForApproval: async () => ({ status: "pending", decision: null }),
    }),
    {
      block: true,
      blockReason: `${APPROVAL_NOT_GRANTED_GUIDANCE} (approval_id=app_001)`,
    },
  );

  assert.deepEqual(
    await decisionToToolResult(askDecision, {
      waitForApproval: async () => ({ status: "timeout", decision: "deny" }),
    }),
    {
      block: true,
      blockReason: `${APPROVAL_EXPIRED_GUIDANCE} (approval_id=app_001)`,
    },
  );

  assert.deepEqual(await decisionToMessageResult(askDecision, {}), {
    cancel: true,
    cancelReason: `${APPROVAL_NOT_GRANTED_GUIDANCE} (approval_id=app_001)`,
  });
});

test("GuardApiClient caps approval polling by the single approval timeout", async () => {
  let waitCalls = 0;
  const client = new GuardApiClient({
    config: {
      guardApiBaseUrl: "https://guard.test",
      adapterToken: "secret-token",
      requestTimeoutMs: 1000,
      approvalPollIntervalMs: 50,
      approvalTimeoutMs: 5,
      diagnosticLogging: false,
    },
    fetchImpl: async () => {
      waitCalls += 1;
      return new Response(
        JSON.stringify({ status: "pending", decision: null }),
        {
          status: 200,
          headers: { "content-type": "application/json" },
        },
      );
    },
  });

  const approval = await client.waitForApproval("app_budget");

  assert.equal(approval.status, "timeout");
  assert.equal(approval.decision, "deny");
  assert.equal(waitCalls, 1);
});

test("GuardApiClient total deadline covers a stalled successful response body", async () => {
  const encoder = new TextEncoder();
  const client = new GuardApiClient({
    config: {
      guardApiBaseUrl: "https://guard.test",
      adapterToken: "secret-token",
      requestTimeoutMs: 20,
      approvalPollIntervalMs: 1,
      approvalTimeoutMs: 20,
      diagnosticLogging: false,
    },
    fetchImpl: async () =>
      new Response(
        new ReadableStream({
          start(controller) {
            controller.enqueue(encoder.encode('{"decision":'));
          },
        }),
        { status: 200, headers: { "content-type": "application/json" } },
      ),
  });

  const outcome = await Promise.race([
    client.evaluate({ event_id: "evt_stalled_body" }).then(
      () => ({ kind: "resolved" }),
      (error) => ({ kind: "rejected", error }),
    ),
    new Promise((resolve) =>
      setTimeout(() => resolve({ kind: "hung" }), 200),
    ),
  ]);

  assert.equal(outcome.kind, "rejected");
  assert.equal(outcome.error.name, "GuardApiResponseError");
  assert.equal(outcome.error.failure, "timed_out");
});

test("GuardApiClient total deadline also covers stalled response headers", async () => {
  const client = new GuardApiClient({
    config: {
      guardApiBaseUrl: "https://guard.test",
      adapterToken: "secret-token",
      requestTimeoutMs: 20,
      approvalPollIntervalMs: 1,
      approvalTimeoutMs: 20,
      diagnosticLogging: false,
    },
    fetchImpl: async () => new Promise(() => undefined),
  });

  const outcome = await Promise.race([
    client.evaluate({ event_id: "evt_stalled_headers" }).then(
      () => ({ kind: "resolved" }),
      (error) => ({ kind: "rejected", error }),
    ),
    new Promise((resolve) =>
      setTimeout(() => resolve({ kind: "hung" }), 200),
    ),
  ]);

  assert.equal(outcome.kind, "rejected");
  assert.equal(outcome.error.name, "GuardApiResponseError");
  assert.equal(outcome.error.failure, "timed_out");
});

test("GuardApiClient rejects oversized and malformed JSON bodies with bounded classifications", async () => {
  const cases = [
    {
      body: JSON.stringify({ ...allowDecision, padding: "x".repeat(2_000_000) }),
      failure: "too_large",
    },
    { body: '{"decision":', failure: "malformed" },
  ];

  for (const item of cases) {
    const client = new GuardApiClient({
      config: {
        guardApiBaseUrl: "https://guard.test",
        adapterToken: "secret-token",
        requestTimeoutMs: 1000,
        approvalPollIntervalMs: 1,
        approvalTimeoutMs: 20,
        diagnosticLogging: false,
      },
      fetchImpl: async () =>
        new Response(item.body, {
          status: 200,
          headers: { "content-type": "application/json" },
        }),
    });

    await assert.rejects(
      client.evaluate({ event_id: `evt_${item.failure}` }),
      (error) =>
        error.name === "GuardApiResponseError" &&
        error.failure === item.failure,
    );
  }
});

test("GuardApiClient diagnostic logging redacts adapter token", async () => {
  const warnings = [];
  const originalWarn = console.warn;
  console.warn = (...args) => warnings.push(args.map(String).join(" "));
  const client = new GuardApiClient({
    config: {
      guardApiBaseUrl: "https://guard.test",
      adapterToken: "secret-token",
      requestTimeoutMs: 1000,
      approvalPollIntervalMs: 10,
      approvalTimeoutMs: 10,
      diagnosticLogging: true,
    },
    fetchImpl: async () => {
      throw new Error("secret-token leaked by transport");
    },
  });

  try {
    await assert.rejects(() => client.evaluate({ event_id: "evt_001" }));
  } finally {
    console.warn = originalWarn;
  }

  assert.equal(warnings.length > 0, true);
  assert.equal(warnings.join("\n").includes("secret-token"), false);
  assert.equal(warnings.join("\n").includes('"error_type":"error"'), true);
});

test("submitRuntimeOutcome posts to /v1/audit/events and surfaces created flags", async () => {
  const requests = [];
  const client = new GuardApiClient({
    config: {
      guardApiBaseUrl: "https://guard.test",
      adapterToken: "secret-token",
      requestTimeoutMs: 1000,
      approvalPollIntervalMs: 10,
      approvalTimeoutMs: 10,
    },
    fetchImpl: async (url, init) => {
      requests.push({ url: String(url), init });
      return new Response(
        JSON.stringify({
          ok: true,
          audit_id: "audit_outcome_evt_001_pre_execution_deny",
          created: true,
          idempotent_replay: false,
        }),
        { status: 200, headers: { "content-type": "application/json" } },
      );
    },
  });

  const result = await client.submitRuntimeOutcome(runtimeOutcomeReceipt());

  assert.equal(requests[0].url, "https://guard.test/v1/audit/events");
  assert.equal(requests[0].init.method, "POST");
  assert.equal(result.ok, true);
  assert.equal(result.created, true);
  assert.equal(result.idempotent_replay, false);
});

test("submitRuntimeOutcome treats 409 conflict as diagnostics without throwing", async () => {
  const client = new GuardApiClient({
    config: {
      guardApiBaseUrl: "https://guard.test",
      adapterToken: "secret-token",
      requestTimeoutMs: 1000,
      approvalPollIntervalMs: 10,
      approvalTimeoutMs: 10,
      diagnosticLogging: false,
    },
    fetchImpl: async () =>
      new Response(JSON.stringify({ error: "AUDIT_ID_CONFLICT" }), {
        status: 409,
        headers: { "content-type": "application/json" },
      }),
  });

  const result = await client.submitRuntimeOutcome(
    runtimeOutcomeReceipt("evt_conflict"),
  );

  assert.equal(result.ok, false);
  assert.equal(result.created, false);
  assert.equal(
    result.audit_id,
    "audit_outcome_evt_conflict_pre_execution_deny",
  );
});

test("submitRuntimeOutcome does not retry permanently invalid receipts", async () => {
  const client = new GuardApiClient({
    config: {
      guardApiBaseUrl: "https://guard.test",
      adapterToken: "secret-token",
      requestTimeoutMs: 1000,
      approvalPollIntervalMs: 10,
      approvalTimeoutMs: 10,
      diagnosticLogging: false,
    },
    fetchImpl: async () =>
      new Response(JSON.stringify({ error: "RUNTIME_OUTCOME_INVALID" }), {
        status: 422,
        headers: { "content-type": "application/json" },
      }),
  });

  const result = await client.submitRuntimeOutcome(
    runtimeOutcomeReceipt("evt_invalid"),
  );

  assert.equal(result.ok, false);
  assert.equal(result.created, false);
  assert.equal(result.audit_id, "audit_outcome_evt_invalid_pre_execution_deny");
});

test("submitRuntimeOutcome still rejects on server errors", async () => {
  const client = new GuardApiClient({
    config: {
      guardApiBaseUrl: "https://guard.test",
      adapterToken: "secret-token",
      requestTimeoutMs: 1000,
      approvalPollIntervalMs: 10,
      approvalTimeoutMs: 10,
      diagnosticLogging: false,
    },
    fetchImpl: async () =>
      new Response(JSON.stringify({ error: "boom" }), {
        status: 500,
        headers: { "content-type": "application/json" },
      }),
  });

  await assert.rejects(() =>
    client.submitRuntimeOutcome(runtimeOutcomeReceipt("evt_err")),
  );
});

test("decisionToToolResult reports outcome receipts for confirmed interventions", async () => {
  const denyOutcomes = [];
  await decisionToToolResult(denyDecision, {}, (outcome) =>
    denyOutcomes.push(outcome),
  );
  assert.equal(denyOutcomes.length, 1);
  assert.equal(denyOutcomes[0].kind, "pre_execution_deny");
  assert.equal(denyOutcomes[0].approval, null);

  const allowDecisionOutcome = [];
  assert.equal(
    await decisionToToolResult(allowDecision, {}, (outcome) =>
      allowDecisionOutcome.push(outcome),
    ),
    undefined,
  );
  assert.equal(allowDecisionOutcome.length, 0);

  const releaseOutcomes = [];
  await decisionToToolResult(
    askDecision,
    {
      waitForApproval: async () => ({
        status: "resolved",
        decision: "allow_once",
      }),
    },
    (outcome) => releaseOutcomes.push(outcome),
  );
  assert.equal(releaseOutcomes.length, 1);
  assert.equal(releaseOutcomes[0].kind, "approval_release");
  assert.equal(releaseOutcomes[0].approval.status, "allowed");
  assert.equal(releaseOutcomes[0].approval.approvalId, "app_001");

  const approvalDenyOutcomes = [];
  await decisionToToolResult(
    askDecision,
    { waitForApproval: async () => ({ status: "resolved", decision: "deny" }) },
    (outcome) => approvalDenyOutcomes.push(outcome),
  );
  assert.equal(approvalDenyOutcomes.length, 1);
  assert.equal(approvalDenyOutcomes[0].kind, "pre_execution_deny");
  assert.equal(approvalDenyOutcomes[0].approval.status, "denied");

  const timeoutOutcomes = [];
  await decisionToToolResult(
    askDecision,
    { waitForApproval: async () => ({ status: "timeout", decision: "deny" }) },
    (outcome) => timeoutOutcomes.push(outcome),
  );
  assert.equal(timeoutOutcomes.length, 1);
  assert.equal(timeoutOutcomes[0].kind, "pre_execution_deny");
  assert.equal(timeoutOutcomes[0].approval.status, "expired");
});

test("decisionToMessageResult reports cancel outcomes for message sends", async () => {
  const outcomes = [];
  await decisionToMessageResult(denyDecision, {}, (outcome) =>
    outcomes.push(outcome),
  );
  assert.equal(outcomes.length, 1);
  assert.equal(outcomes[0].kind, "pre_execution_deny");

  const allowOutcomes = [];
  assert.equal(
    await decisionToMessageResult(allowDecision, {}, (outcome) =>
      allowOutcomes.push(outcome),
    ),
    undefined,
  );
  assert.equal(allowOutcomes.length, 0);
});
