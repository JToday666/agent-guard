import assert from "node:assert/strict";
import test from "node:test";

test("plugin entry evaluates hooks with OpenClaw api.pluginConfig", async () => {
  const { default: plugin } = await import("../dist/index.js");
  const registered = [];
  const previousFetch = globalThis.fetch;
  const previousToken = process.env.AGENTGUARD_ADAPTER_TOKEN;
  delete process.env.AGENTGUARD_ADAPTER_TOKEN;

  try {
    plugin.register({
      pluginConfig: {
        guardApiBaseUrl: "http://guard.local",
        adapterToken: "plugin-token",
        requestTimeoutMs: 1000,
        approvalPollIntervalMs: 1,
        approvalTimeoutMs: 1,
      },
      on(name, handler, options) {
        registered.push({ name, handler, options });
      },
    });

    let authHeader = null;
    globalThis.fetch = async (_url, init) => {
      authHeader = init.headers.Authorization;
      return new Response(
        JSON.stringify({
          decision: { decision: "allow", reason: "ok" },
          approval: null,
        }),
        { status: 200, headers: { "Content-Type": "application/json" } },
      );
    };

    const beforeToolCall = registered.find((entry) => entry.name === "before_tool_call");
    assert.ok(beforeToolCall);

    const result = await beforeToolCall.handler(
      {
        toolName: "read_file",
        params: { path: "/tmp/e2e.txt" },
        toolCallId: "call_entry_test",
        runId: "run_entry_test",
      },
      { agentId: "main", sessionKey: "agent:main:entry-test" },
    );

    assert.equal(result, undefined);
    assert.equal(authHeader, "Bearer plugin-token");
  } finally {
    globalThis.fetch = previousFetch;
    if (previousToken === undefined) {
      delete process.env.AGENTGUARD_ADAPTER_TOKEN;
    } else {
      process.env.AGENTGUARD_ADAPTER_TOKEN = previousToken;
    }
  }
});
