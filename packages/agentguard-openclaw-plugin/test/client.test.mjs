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
    { cancel: true, cancelReason: "needs review" },
  );

  assert.deepEqual(
    await decisionToToolResult(askDecision, {
      waitForApproval: async () => ({ status: "pending", decision: null }),
    }),
    { block: true, blockReason: "needs review" },
  );
});
