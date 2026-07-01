import assert from "node:assert/strict";
import { createServer } from "node:http";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";

import { getToolPluginMetadata } from "openclaw/plugin-sdk/tool-plugin";

import entry, { BENCH_TOOL_NAMES, invokeBenchTool } from "../dist/index.js";

test("declares fixed AttackBench tools and fallback tool", () => {
  const metadata = getToolPluginMetadata(entry);
  assert.equal(metadata?.id, "agentguard-bench-tools");
  assert.deepEqual(
    metadata?.tools.map((tool) => tool.name),
    [...BENCH_TOOL_NAMES, "agentguard_bench_tool"],
  );
});

test("forwards a static tool call to the current benchmark tool server", async () => {
  const requests = [];
  const server = createServer((request, response) => {
    let body = "";
    request.on("data", (chunk) => {
      body += chunk;
    });
    request.on("end", () => {
      requests.push({
        method: request.method,
        url: request.url,
        body: JSON.parse(body || "{}"),
      });
      response.setHeader("Content-Type", "application/json");
      response.end(JSON.stringify({ ok: true, tool_name: "read_file", result: { body: "hello" } }));
    });
  });

  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  const address = server.address();
  const baseUrl = `http://127.0.0.1:${address.port}/tools`;
  const tempDir = await mkdtemp(path.join(tmpdir(), "agentguard-bench-tools-"));
  const runtimeConfigPath = path.join(tempDir, "runtime.json");
  await writeFile(
    runtimeConfigPath,
    JSON.stringify({
      toolInvocationBaseUrl: baseUrl,
      traceId: "trace_test",
      caseId: "BN-001",
    }),
    "utf8",
  );

  try {
    const result = await invokeBenchTool(
      "read_file",
      { path: "/docs/public.txt" },
      { runtimeConfigPath },
      { toolCallId: "call_test" },
    );

    assert.equal(result.ok, true);
    assert.equal(requests.length, 1);
    assert.equal(requests[0].method, "POST");
    assert.equal(requests[0].url, "/tools/read_file");
    assert.deepEqual(requests[0].body, {
      arguments: { path: "/docs/public.txt" },
      trace_id: "trace_test",
      call_id: "call_test",
    });
  } finally {
    server.close();
    await rm(tempDir, { recursive: true, force: true });
  }
});
