// PR-RTE-04b — CF-08/CF-09 Tier 3 evidence binding (contract 05 §3, 06 §6).
//
// CF-08（stable action correlation）与 CF-09（blocked-call after-hook
// semantics）属真实运行时语义，由 PR-RTE-02 rev3 live 取证工件承载证据，
// 证据版本锁定 2026.7.1-2（rev5 pin bump）。当前自动 CI 只验证归档
// 工件与契约的机器化绑定，不会重跑真实 runtime、spike 探针或模型 turn；
// 这些必须由维护者通过隔离 smoke 脚本重新执行并归档。本文件保证工件
// 缺失或已记录语义退化时失败，但不能把历史工件扩大为当前平台实证。
import assert from "node:assert/strict";
import test from "node:test";
import { existsSync, readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const TEST_DIR = path.dirname(fileURLToPath(import.meta.url));
const LIVE_EVIDENCE_PATH = path.join(TEST_DIR, "fixtures", "rte02-live-evidence.json");
const LIVE_EVIDENCE_JSONL_PATH = path.join(
  TEST_DIR,
  "fixtures",
  "rte02-live-evidence.jsonl",
);
const REPO_ROOT = path.resolve(TEST_DIR, "..", "..", "..");
const CONTRACT_CASES_PATH = path.join(
  REPO_ROOT,
  "tests",
  "runtime_conformance",
  "contract_cases.json",
);
const MATRIX_PATH = path.join(
  REPO_ROOT,
  "tests",
  "runtime_conformance",
  "expected_capabilities.json",
);

function loadJson(filePath) {
  return JSON.parse(readFileSync(filePath, "utf8"));
}

function loadJsonl(filePath) {
  return readFileSync(filePath, "utf8")
    .split(/\r?\n/)
    .filter((line) => line.trim() !== "")
    .map((line) => JSON.parse(line));
}

function contractCase(caseId) {
  const found = loadJson(CONTRACT_CASES_PATH).cases.find(
    (item) => item.id === caseId,
  );
  assert.ok(found, `${caseId} must exist in the shared registry`);
  return found;
}

test("CF-08 live evidence: one stable toolCallId spans before/execute/after per scenario", () => {
  const spec = contractCase("CF-08");
  assert.equal(spec.tier, 3);
  assert.equal(spec.scope, "correlation");
  assert.ok(existsSync(LIVE_EVIDENCE_PATH));
  assert.ok(existsSync(LIVE_EVIDENCE_JSONL_PATH));

  const records = loadJsonl(LIVE_EVIDENCE_JSONL_PATH);
  const scenarioTools = [
    ...new Set(records.map((record) => record.toolName ?? record.tool)),
  ];
  assert.deepEqual(scenarioTools.sort(), [
    "rte_probe_deny",
    "rte_probe_fail",
    "rte_probe_ok",
  ]);

  for (const toolName of scenarioTools) {
    const scenarioRecords = records.filter(
      (record) => (record.toolName ?? record.tool) === toolName,
    );
    // before action_id == after action_id（CF-08 判据）。
    const hooked = scenarioRecords.filter(
      (record) =>
        record.kind === "before_tool_call" || record.kind === "after_tool_call",
    );
    assert.ok(hooked.length >= 2, `${toolName} must have before and after`);
    const ids = new Set(hooked.map((record) => record.toolCallId));
    assert.equal(ids.size, 1, `${toolName} must carry one toolCallId`);
    for (const record of hooked) {
      assert.equal(
        record.ctxToolCallId,
        record.toolCallId,
        `${toolName} ctx/event toolCallId must match`,
      );
    }
  }
});

test("CF-09 live evidence: blocked call has zero executions yet after hook fires (emission-on-blocked)", () => {
  const spec = contractCase("CF-09");
  assert.equal(spec.tier, 3);
  assert.ok(spec.expect.notes.includes("enforcement_violation"));

  const records = loadJsonl(LIVE_EVIDENCE_JSONL_PATH);
  const denyRecords = records.filter(
    (record) => (record.toolName ?? record.tool) === "rte_probe_deny",
  );

  // C1 事实：blocked 零执行。
  assert.ok(
    !denyRecords.some((record) => record.kind === "tool_executed"),
    "blocked call must have zero executions",
  );
  // pin 2026.7.1-2 语义：after hook 触发但不代表 invocation（error 形状）。
  const denyAfter = denyRecords.filter(
    (record) => record.kind === "after_tool_call",
  );
  assert.equal(denyAfter.length, 1);
  assert.equal(denyAfter[0].errorPresent, true);
  assert.equal(denyAfter[0].errorIsString, true);

  const evidence = loadJson(LIVE_EVIDENCE_PATH);
  assert.equal(evidence.runtime.openclaw_cli_version, "2026.7.1-2");
  const denyScenario = evidence.scenarios.find((item) => item.id === "S-deny");
  assert.ok(denyScenario);
  assert.ok(!denyScenario.observed_sequence.includes("tool_executed"));
  assert.ok(denyScenario.observed_sequence.includes("after_tool_call"));
});

test("matrix binds CF-08/CF-09 to this Tier 3 evidence chain", () => {
  const matrix = loadJson(MATRIX_PATH).runtimes.openclaw;
  for (const caseId of ["CF-08", "CF-09"]) {
    const entry = matrix[caseId];
    assert.equal(entry.status, "PASS", caseId);
    assert.ok(
      entry.evidence.endsWith("rte-conformance-tier3-evidence.test.mjs"),
      `${caseId} evidence must point at the Tier 3 binding test`,
    );
    assert.ok(existsSync(path.join(REPO_ROOT, entry.evidence)), caseId);
    // 证据链注明 live 取证工件，并明确当前 CI 不会把历史工件
    // 扩大为真实 runtime smoke 或本次平台验证。
    assert.ok(entry.note.includes("rte02-live-evidence.json"), caseId);
    assert.ok(entry.note.includes("当前 CI 不含真实 runtime smoke 矩阵"), caseId);
    assert.ok(entry.note.includes("scripts/openclaw-runtime-smoke.mjs"), caseId);
    assert.ok(
      entry.note.includes("手动复验"),
      `${caseId} note must keep runtime revalidation manual`,
    );
  }
});
