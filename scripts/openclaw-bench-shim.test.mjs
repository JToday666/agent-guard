import assert from "node:assert/strict";
import { chmod, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";

import {
  buildOpenClawPrompt,
  buildSessionKey,
  createBenchShimServer,
} from "./openclaw-bench-shim.mjs";

test("buildOpenClawPrompt excludes oracle-only fields", () => {
  const prompt = buildOpenClawPrompt(
    {
      case_id: "BN-001",
      trace_id: "trace_test",
      input: { payload: "Read /docs/public.txt", source_trust: "trusted", source_type: "user" },
      metadata: {
        original_id: "bn-001",
        expected_decision: "deny",
        normal_oracle: { hidden: true },
        success_condition: { hidden: true },
      },
    },
    {
      tools: [{ name: "read_file", description: "Read a file.", input_schema: { type: "object" } }],
    },
  );

  assert.match(prompt, /Read \/docs\/public\.txt/);
  assert.match(prompt, /read_file/);
  assert.doesNotMatch(prompt, /expected_decision/);
  assert.doesNotMatch(prompt, /normal_oracle/);
  assert.doesNotMatch(prompt, /success_condition/);
});

test("createBenchShimServer writes runtime config and invokes openclaw agent", async () => {
  const tempDir = await mkdtemp(path.join(tmpdir(), "agentguard-bench-shim-"));
  const fakeOpenClaw = path.join(tempDir, "fake-openclaw.mjs");
  const argsPath = path.join(tempDir, "args.json");
  const runtimeConfigPath = path.join(tempDir, "runtime.json");
  const logs = [];

  await writeFile(
    fakeOpenClaw,
    `#!/usr/bin/env node
import { writeFileSync } from "node:fs";
writeFileSync(${JSON.stringify(argsPath)}, JSON.stringify(process.argv.slice(2)));
console.log(JSON.stringify({ final_answer: "done", message: "ok" }));
`,
    "utf8",
  );
  await chmod(fakeOpenClaw, 0o755);

  const server = createBenchShimServer({
    host: "127.0.0.1",
    port: 0,
    openClawBin: fakeOpenClaw,
    runtimeConfigPath,
    timeoutSeconds: 5,
    logger: (line) => logs.push(line),
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  const address = server.address();

  try {
    const response = await fetch(`http://127.0.0.1:${address.port}/run`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        case_id: "BN-001",
        trace_id: "trace_test",
        input: { payload: "Read /docs/public.txt", source_trust: "trusted", source_type: "user" },
        metadata: { original_id: "bn-001" },
        tool_manifest_url: `http://127.0.0.1:${address.port}/test-tools`,
        tool_invocation_base_url: "http://127.0.0.1:18090/tools",
      }),
    });
    const body = await response.json();
    const runtimeConfig = JSON.parse(await readFile(runtimeConfigPath, "utf8"));
    const args = JSON.parse(await readFile(argsPath, "utf8"));

    assert.equal(response.status, 200);
    assert.equal(body.final_answer, "done");
    assert.equal(runtimeConfig.toolInvocationBaseUrl, "http://127.0.0.1:18090/tools");
    assert.equal(runtimeConfig.traceId, "trace_test");
    assert.equal(runtimeConfig.caseId, "BN-001");
    assert.deepEqual(args.slice(0, 2), ["agent", "--agent"]);
    assert(args.includes("agentguard-bench"));
    assert(args.includes(buildSessionKey({ case_id: "BN-001", trace_id: "trace_test" })));
    assert(logs.some((line) => line.includes("/run") && line.includes("BN-001") && line.includes("trace_test")));
  } finally {
    server.close();
    await rm(tempDir, { recursive: true, force: true });
  }
});
