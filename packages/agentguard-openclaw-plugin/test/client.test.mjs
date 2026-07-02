import assert from "node:assert/strict";
import test from "node:test";

import {
  GuardApiClient,
  buildPluginConfig,
  decisionToMessageResult,
  decisionToToolResult,
} from "../dist/guard-api-client.js";

const allowDecision = { decision: { decision: "allow", reason: "ok", safe_message: null }, approval: null };
const denyDecision = { decision: { decision: "deny", reason: "blocked", safe_message: "no" }, approval: null };
const askDecision = {
  decision: { decision: "ask", reason: "review", safe_message: "needs review" },
  approval: { approval_id: "app_001", status: "pending", decision_options: ["allow_once", "deny"] },
};

test("buildPluginConfig uses safe defaults and env token fallback", () => {
  const config = buildPluginConfig({}, { AGENTGUARD_ADAPTER_TOKEN: "env-token" });

  assert.equal(config.guardApiBaseUrl, "http://127.0.0.1:8088");
  assert.equal(config.adapterToken, "env-token");
  assert.equal(config.requestTimeoutMs, 5000);
  assert.equal(config.approvalPollIntervalMs, 1000);
  assert.equal(config.approvalTimeoutMs, 120000);
  assert.equal(config.approvalWaitBudgetMs, 8000);
  assert.equal(config.diagnosticLogging, false);
});

test("buildPluginConfig accepts approval budget and diagnostic logging", () => {
  const config = buildPluginConfig(
    {
      approvalWaitBudgetMs: 2500,
      diagnosticLogging: true,
      runtimeId: "openclaw-gateway",
      agentId: "openclaw-main",
      enabledHooks: ["before_tool_call", "message_sending"],
      failClosedStages: ["before_tool_call"],
      redaction: { enabled: true, previewLimit: 1200 },
      heartbeatIntervalMs: 30000,
    },
    { AGENTGUARD_ADAPTER_TOKEN: "env-token" },
  );

  assert.equal(config.approvalWaitBudgetMs, 2500);
  assert.equal(config.diagnosticLogging, true);
  assert.equal(config.runtimeId, "openclaw-gateway");
  assert.equal(config.agentId, "openclaw-main");
  assert.deepEqual(config.enabledHooks, ["before_tool_call", "message_sending"]);
  assert.deepEqual(config.failClosedStages, ["before_tool_call"]);
  assert.deepEqual(config.redaction, { enabled: true, previewLimit: 1200 });
  assert.equal(config.heartbeatIntervalMs, 30000);
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
      approvalWaitBudgetMs: 10,
      diagnosticLogging: false,
      runtimeId: "openclaw-gateway",
      agentId: "openclaw-main",
      enabledHooks: ["before_tool_call"],
      failClosedStages: ["before_tool_call"],
      redaction: { enabled: true, previewLimit: 2000 },
      heartbeatIntervalMs: 60000,
    },
    fetchImpl: async (url, init) => {
      requests.push({ url: String(url), init, body: JSON.parse(String(init.body)) });
      return new Response(JSON.stringify({ status: "loaded", loaded: true, runtime: "openclaw" }), {
        status: 200,
        headers: { "content-type": "application/json" },
      });
    },
  });

  await client.submitHeartbeat({
    pluginVersion: "0.1.0",
    runtimeVersion: "2026.6.6",
    hooks: ["before_tool_call", "message_sending"],
    capabilities: { event_types: ["tool_call_proposed", "message_send_proposed"] },
  });

  assert.equal(requests[0].url, "http://guard.test/v1/adapters/openclaw/heartbeat");
  assert.equal(requests[0].init.headers.Authorization, "Bearer secret-token");
  assert.equal(requests[0].body.runtime, "openclaw");
  assert.equal(requests[0].body.runtime_id, "openclaw-gateway");
  assert.equal(requests[0].body.agent_id, "openclaw-main");
  assert.equal(requests[0].body.plugin_version, "0.1.0");
  assert.deepEqual(requests[0].body.hooks, ["before_tool_call", "message_sending"]);
  assert.deepEqual(requests[0].body.fail_closed_stages, ["before_tool_call"]);
  assert.deepEqual(requests[0].body.capabilities.event_types, [
    "tool_call_proposed",
    "message_send_proposed",
  ]);
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
    fetchImpl: async () => new Response("secret-token leaked by server", { status: 500 }),
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
  assert.equal((await decisionToToolResult(allowDecision, {})), undefined);
  assert.deepEqual(await decisionToToolResult(denyDecision, {}), {
    block: true,
    blockReason: "no",
  });

  assert.equal((await decisionToMessageResult(allowDecision, {})), undefined);
  assert.deepEqual(await decisionToMessageResult(denyDecision, {}), {
    cancel: true,
    cancelReason: "no",
  });

  assert.equal(
    await decisionToToolResult(askDecision, {
      waitForApproval: async () => ({ status: "resolved", decision: "allow_once" }),
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

test("GuardApiClient caps approval polling by per-hook budget", async () => {
  let waitCalls = 0;
  const client = new GuardApiClient({
    config: {
      guardApiBaseUrl: "http://guard.test",
      adapterToken: "secret-token",
      requestTimeoutMs: 1000,
      approvalPollIntervalMs: 50,
      approvalTimeoutMs: 120000,
      approvalWaitBudgetMs: 5,
      diagnosticLogging: false,
    },
    fetchImpl: async () => {
      waitCalls += 1;
      return new Response(JSON.stringify({ status: "pending", decision: null }), {
        status: 200,
        headers: { "content-type": "application/json" },
      });
    },
  });

  const approval = await client.waitForApproval("app_budget", 5);

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
      approvalWaitBudgetMs: 10,
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
