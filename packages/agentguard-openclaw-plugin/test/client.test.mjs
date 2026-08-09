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

test("buildPluginConfig uses safe defaults with a resolved SecretRef token", () => {
  const config = buildPluginConfig({ adapterToken: "resolved-token" });

  assert.equal(config.guardApiBaseUrl, "http://127.0.0.1:8088");
  assert.equal(config.adapterToken, "resolved-token");
  assert.equal(config.enforcementMode, "enforce");
  assert.equal(config.requestTimeoutMs, 5000);
  assert.equal(config.approvalPollIntervalMs, 1000);
  assert.equal(config.approvalTimeoutMs, 25000);
  assert.equal(config.diagnosticLogging, false);
  assert.equal(config.agentId, "main");
});

test("buildPluginConfig accepts the canonical public options", () => {
  const config = buildPluginConfig({
    adapterToken: "resolved-token",
    approvalTimeoutMs: 2500,
    diagnosticLogging: true,
    agentId: "openclaw-main",
    enforcementMode: "observe",
  });

  assert.equal(config.approvalTimeoutMs, 2500);
  assert.equal(config.diagnosticLogging, true);
  assert.equal(config.agentId, "openclaw-main");
  assert.equal(config.enforcementMode, "observe");
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
      guardApiBaseUrl: "http://guard.test",
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
  assert.equal(requests[0].url, "http://guard.test/v1/guard/evaluate");
  assert.equal(requests[0].init.headers.Authorization, "Bearer secret-token");
});

test("GuardApiClient sends adapter heartbeat with capabilities and runtime identity", async () => {
  const requests = [];
  const client = new GuardApiClient({
    config: {
      guardApiBaseUrl: "http://guard.test",
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
    "http://guard.test/v1/adapters/openclaw/heartbeat",
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
    "message_sending",
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
      guardApiBaseUrl: "http://guard.test",
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
      guardApiBaseUrl: "http://guard.test",
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
    blockReason: "no",
  });

  assert.equal(await decisionToMessageResult(allowDecision, {}), undefined);
  assert.deepEqual(await decisionToMessageResult(denyDecision, {}), {
    cancel: true,
    cancelReason: "no",
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
    { cancel: true, cancelReason: "needs review (approval_id=app_001)" },
  );

  assert.deepEqual(
    await decisionToToolResult(askDecision, {
      waitForApproval: async () => ({ status: "pending", decision: null }),
    }),
    { block: true, blockReason: "needs review (approval_id=app_001)" },
  );
});

test("GuardApiClient caps approval polling by the single approval timeout", async () => {
  let waitCalls = 0;
  const client = new GuardApiClient({
    config: {
      guardApiBaseUrl: "http://guard.test",
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

test("GuardApiClient diagnostic logging redacts adapter token", async () => {
  const warnings = [];
  const originalWarn = console.warn;
  console.warn = (...args) => warnings.push(args.map(String).join(" "));
  const client = new GuardApiClient({
    config: {
      guardApiBaseUrl: "http://guard.test",
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
  assert.equal(warnings.join("\n").includes("[redacted]"), true);
});

test("submitRuntimeOutcome posts to /v1/audit/events and surfaces created flags", async () => {
  const requests = [];
  const client = new GuardApiClient({
    config: {
      guardApiBaseUrl: "http://guard.test",
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

  const result = await client.submitRuntimeOutcome({
    audit_id: "audit_outcome_evt_001_pre_execution_deny",
    schema_version: "0.4",
    record_type: "runtime_outcome",
    trace_id: "run_outcome",
    runtime: "openclaw",
    stage: "before_tool_call",
    event_type: "runtime_outcome",
    summary: "denied",
    decision: "deny",
    risk_score: 90,
    severity: "high",
    blocked: true,
    reason: "deny",
    links: { event_id: "evt_001", policy_audit_id: "audit_policy_001" },
  });

  assert.equal(requests[0].url, "http://guard.test/v1/audit/events");
  assert.equal(requests[0].init.method, "POST");
  assert.equal(result.ok, true);
  assert.equal(result.created, true);
  assert.equal(result.idempotent_replay, false);
});

test("submitRuntimeOutcome treats 409 conflict as diagnostics without throwing", async () => {
  const client = new GuardApiClient({
    config: {
      guardApiBaseUrl: "http://guard.test",
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

  const result = await client.submitRuntimeOutcome({
    audit_id: "audit_outcome_conflict",
    schema_version: "0.4",
    record_type: "runtime_outcome",
    trace_id: "run_outcome",
    runtime: "openclaw",
    stage: "before_tool_call",
    event_type: "runtime_outcome",
    summary: "conflict",
    decision: "deny",
    risk_score: null,
    severity: null,
    blocked: true,
    reason: "conflict",
    links: {
      event_id: "evt_conflict",
      policy_audit_id: "audit_policy_conflict",
    },
  });

  assert.equal(result.ok, false);
  assert.equal(result.created, false);
  assert.equal(result.audit_id, "audit_outcome_conflict");
});

test("submitRuntimeOutcome still rejects on server errors", async () => {
  const client = new GuardApiClient({
    config: {
      guardApiBaseUrl: "http://guard.test",
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
    client.submitRuntimeOutcome({
      audit_id: "audit_outcome_err",
      schema_version: "0.4",
      record_type: "runtime_outcome",
      trace_id: "run_outcome",
      runtime: "openclaw",
      stage: "before_tool_call",
      event_type: "runtime_outcome",
      summary: "error",
      decision: "deny",
      risk_score: null,
      severity: null,
      blocked: true,
      reason: "error",
      links: { event_id: "evt_err", policy_audit_id: "audit_policy_err" },
    }),
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
