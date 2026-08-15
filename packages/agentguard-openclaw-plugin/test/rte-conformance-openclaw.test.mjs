// PR-RTE-04b — OpenClaw conformance profile (contract 05 §3, 06 §6).
//
// 固定决策 fake Guard API + 真实 plugin dist handlers，通过带 invocation
// 计数的 host harness 驱动（评审 P1：不再合成生命周期回调）：
//   before_tool_call handler → block:true 时 host 短路（零执行），
//   否则执行计数工具，随后按 pin 2026.7.1-2 已证语义发 after_tool_call。
// blocked 调用的 after 事件形状来自 rte02 live 取证（Q9 emission-on-blocked），
// 不是模拟语义。case ID 与共享注册表 tests/runtime_conformance/
// contract_cases.json 绑定；能力矩阵见 expected_capabilities.json。
import assert from "node:assert/strict";
import test from "node:test";
import { existsSync, readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import {
  registerAfterToolCall,
  registerBeforeToolCall,
  registerToolResultPersist,
} from "../dist/hooks/tool.js";
import { buildRuntimeOutcomeAuditEvent } from "../dist/mapping/index.js";
import { EvidenceDegradationTracker } from "../dist/runtime/state.js";

const REPO_ROOT = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  "..",
  "..",
  "..",
);
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

assert.ok(
  existsSync(CONTRACT_CASES_PATH),
  "shared conformance registry must exist at repo root",
);

function loadRegistry() {
  return JSON.parse(readFileSync(CONTRACT_CASES_PATH, "utf8"));
}

function loadMatrix() {
  return JSON.parse(readFileSync(MATRIX_PATH, "utf8"));
}

function contractCase(caseId) {
  const found = loadRegistry().cases.find((item) => item.id === caseId);
  assert.ok(found, `${caseId} must exist in the shared registry`);
  return found;
}

const BASE_CONFIG = {
  guardApiBaseUrl: "http://127.0.0.1:8088",
  adapterToken: "token",
  enforcementMode: "enforce",
  requestTimeoutMs: 5000,
  approvalPollIntervalMs: 10,
  approvalTimeoutMs: 50,
  diagnosticLogging: false,
  agentId: "agent_rte",
};

function makeHookContext(options = {}) {
  const handlers = {};
  const submitted = [];
  const toolCallState = new Map();
  const degradations = new EvidenceDegradationTracker();
  const invocations = [];
  const api = {
    on: (name, handler) => {
      handlers[name] = handler;
    },
  };
  const client = {
    evaluate:
      options.evaluate ??
      (async () => ({
        decision: {
          decision_id: "dec_cf",
          decision: options.decision ?? "allow",
          risk_score: 10,
          severity: "low",
          rule_hits: [],
          reason: "fixed conformance decision",
        },
        approval: options.approval ?? null,
        policy_audit_id: "audit_policy_cf",
      })),
    // 可改写：模拟晚到审批决议等时序变化（handlers 持有 client 引用）。
    waitForApproval: async () => {
      const response = options.waitResponse ?? {
        status: "resolved",
        decision: "allow_once",
      };
      return typeof response === "function" ? response() : response;
    },
  };
  const delivery = {
    submit: (receipt) => {
      submitted.push(receipt);
      return Promise.resolve();
    },
  };
  const context = {
    api,
    config: { ...BASE_CONFIG, ...(options.config ?? {}) },
    makeClient: () => client,
    outcomeDelivery: delivery,
    sessionState: new Map(),
    toolCallState,
    degradations,
  };
  return {
    handlers,
    submitted,
    toolCallState,
    degradations,
    invocations,
    context,
  };
}

function registerAll(context) {
  registerBeforeToolCall(context);
  registerAfterToolCall(context);
  registerToolResultPersist(context);
}

const TOOL_CTX = { toolName: "spike_probe", runId: "run-cf" };

/**
 * Host harness：按真实 host 执行链驱动插件 handlers（评审 P1）。
 * - before handler 返回 block:true → host 短路，invocation=0；pin
 *   2026.7.1-2 live 取证（Q9）证明 host observer 仍会对 blocked 项发
 *   after_tool_call（error 形状），此处按该已证形状发送，非模拟语义。
 * - 未阻断 → 执行计数工具一次，再按 behavior 发 after 事件。
 */
async function runHostToolCall(
  harness,
  { toolCallId, behavior = "ok", params = { mode: "cf" } },
) {
  const beforeEvent = {
    toolName: "spike_probe",
    params,
    toolCallId,
    runId: "run-cf",
  };
  const blockResult = await harness.handlers.before_tool_call(
    beforeEvent,
    TOOL_CTX,
  );
  if (blockResult && blockResult.block === true) {
    // Q9 emission-on-blocked（rte02 live 取证形状）。
    harness.handlers.after_tool_call(
      {
        toolName: "spike_probe",
        params,
        toolCallId,
        runId: "run-cf",
        result: { blocked: true },
        error: "Tool call blocked by plugin",
      },
      TOOL_CTX,
    );
    return { blocked: true };
  }
  // 计数执行：每次被接受的调用恰好一次。
  harness.invocations.push({ toolCallId, params, at: Date.now() });
  const afterFields = {};
  if (behavior === "throw") {
    afterFields.error = harness.throwWith ?? "spike tool failure";
  } else if (behavior === "falsy") {
    // falsy 成功：既无 result 也无 error（Q5）。
  } else {
    afterFields.result = { ok: true };
    afterFields.durationMs = 3;
  }
  harness.handlers.after_tool_call(
    {
      toolName: "spike_probe",
      params,
      toolCallId,
      runId: "run-cf",
      ...afterFields,
    },
    TOOL_CTX,
  );
  return { blocked: false };
}

async function flush() {
  await new Promise((resolve) => setImmediate(resolve));
}

test("CF-01 allow executes once per accepted call and closes a terminal fact", async () => {
  const spec = contractCase("CF-01");
  assert.equal(spec.expect.receipts[0].kind, "execution_completed");
  assert.equal(spec.expect.invocation_count, 1);
  const harness = makeHookContext({ decision: "allow" });
  registerAll(harness.context);

  const run = await runHostToolCall(harness, { toolCallId: "call-cf01" });
  assert.equal(run.blocked, false);
  assert.equal(harness.invocations.length, 1, "one accepted call -> one execution");

  assert.equal(harness.submitted.length, 1, "one terminal receipt per action");
  const receipt = harness.submitted[0];
  assert.equal(receipt.metadata.outcome_kind, "execution_completed");
  assert.equal(receipt.evidence.execution.status, "executed");
  assert.equal(receipt.links.action_id, "call-cf01");
  // Core 一致性：顶层 timestamp 与 completed_at 同源。
  assert.equal(receipt.timestamp, receipt.evidence.execution.completed_at);
  assert.equal(harness.toolCallState.get("call-cf01").gateState, "allowed");
  assert.equal(harness.toolCallState.get("call-cf01").terminalStatus, "executed");

  // 重放语义归属（registry note）：同 callId 再次通过 host 链属新 attempt，
  // 插件不做客户端重放抑制；同事件幂等去重由 evaluate 层承担（CF-10）。
  await runHostToolCall(harness, { toolCallId: "call-cf01" });
  assert.equal(harness.invocations.length, 2);
  assert.equal(harness.submitted.length, 2);
  assert.equal(harness.submitted[1].links.action_id, "call-cf01");
});

test("CF-02 deny returns block:true, never invokes, and blocked after-arrival derives nothing", async () => {
  const spec = contractCase("CF-02");
  assert.equal(spec.expect.receipts[0].kind, "pre_execution_deny");
  assert.equal(spec.expect.invocation_count, 0);
  const harness = makeHookContext({ decision: "deny" });
  registerAll(harness.context);

  const run = await runHostToolCall(harness, { toolCallId: "call-cf02" });

  // 真实阻断结果：host 必须拿到 block:true，工具零执行。
  assert.equal(run.blocked, true);
  assert.equal(harness.invocations.length, 0);
  // emission-on-blocked 的 after 到达不得派生 terminal fact（Q9）。
  assert.equal(harness.submitted.length, 1, "only the pre_execution_deny receipt");
  assert.equal(harness.submitted[0].metadata.outcome_kind, "pre_execution_deny");
  assert.equal(harness.submitted[0].evidence.execution.status, "not_invoked");
  assert.equal(harness.toolCallState.get("call-cf02").gateState, "blocked");
  assert.equal(harness.toolCallState.get("call-cf02").terminalStatus, undefined);
});

test("CF-03 ask + human deny stays not_invoked with block:true", async () => {
  const spec = contractCase("CF-03");
  assert.equal(spec.expect.invocation_count, 0);
  const harness = makeHookContext({
    decision: "ask",
    approval: { approval_id: "appr_cf03", status: "pending" },
    waitResponse: { status: "resolved", decision: "deny" },
  });
  registerAll(harness.context);

  const run = await runHostToolCall(harness, { toolCallId: "call-cf03" });

  assert.equal(run.blocked, true);
  assert.equal(harness.invocations.length, 0);
  assert.equal(harness.submitted.length, 1);
  assert.equal(harness.submitted[0].metadata.outcome_kind, "pre_execution_deny");
  assert.equal(harness.submitted[0].evidence.execution.status, "not_invoked");
  assert.equal(harness.submitted[0].evidence.approval.status, "denied");
  assert.equal(harness.toolCallState.get("call-cf03").gateState, "blocked");
});

test("CF-04 ask + allow_once releases once and closes terminal with approval evidence", async () => {
  const spec = contractCase("CF-04");
  const releaseSpec = spec.expect.receipts[0];
  assert.ok(releaseSpec.kind_any.includes("approval_release"));
  const harness = makeHookContext({
    decision: "ask",
    approval: { approval_id: "appr_cf04", status: "pending" },
    waitResponse: { status: "resolved", decision: "allow_once" },
  });
  registerAll(harness.context);

  const run = await runHostToolCall(harness, { toolCallId: "call-cf04" });

  assert.equal(run.blocked, false);
  assert.equal(harness.invocations.length, 1);
  assert.equal(harness.submitted.length, 2);
  assert.equal(harness.submitted[0].metadata.outcome_kind, "approval_release");
  assert.equal(harness.submitted[0].evidence.execution.status, "unknown");
  assert.equal(harness.submitted[1].metadata.outcome_kind, "execution_completed");
  assert.equal(harness.submitted[1].links.approval_id, "appr_cf04");
  assert.equal(harness.submitted[1].evidence.approval.decision, "allow_once");
  assert.equal(harness.toolCallState.get("call-cf04").gateState, "approval_released");
});

test("CF-05 wait timeout blocks and late approval does not resurrect", async () => {
  const spec = contractCase("CF-05");
  assert.equal(spec.expect.gate, "timed_out");
  // 状态化审批决议：首次 wait 超时，其后审批被晚到放行。
  let approvalResolutions = 0;
  const harness = makeHookContext({
    decision: "ask",
    approval: { approval_id: "appr_cf05", status: "pending" },
    waitResponse: () => {
      approvalResolutions += 1;
      return approvalResolutions === 1
        ? { status: "timeout", decision: "deny" }
        : { status: "resolved", decision: "allow_once" };
    },
  });
  registerAll(harness.context);

  const run = await runHostToolCall(harness, { toolCallId: "call-cf05" });
  assert.equal(run.blocked, true);
  assert.equal(harness.invocations.length, 0);
  assert.equal(harness.submitted.length, 1);
  assert.equal(harness.submitted[0].metadata.outcome_kind, "pre_execution_deny");
  assert.equal(harness.submitted[0].evidence.execution.status, "not_invoked");
  assert.equal(harness.submitted[0].evidence.approval.status, "expired");
  assert.equal(harness.toolCallState.get("call-cf05").gateState, "timed_out");
  const original = harness.submitted[0];

  // 晚到放行后同一动作再次提交：属新 attempt（同步重评估），
  // 旧 attempt 的 not_invoked 回执不得被改写或复活（评审 P1）。
  await runHostToolCall(harness, { toolCallId: "call-cf05" });

  assert.equal(harness.invocations.length, 1, "仅新 attempt 执行");
  assert.equal(harness.submitted[0], original, "原回执未被改写");
  assert.equal(original.evidence.execution.status, "not_invoked");
  assert.equal(original.evidence.approval.status, "expired");
  // 新终态回执是独立记录：audit_id 与原回执不同，不覆盖原 not_invoked 事实。
  const terminal = harness.submitted.find(
    (receipt) => receipt.metadata.outcome_kind === "execution_completed",
  );
  assert.ok(terminal, "新 attempt 正常关闭终态");
  assert.notEqual(terminal.audit_id, original.audit_id);
  assert.equal(
    harness.submitted.filter(
      (receipt) =>
        receipt.audit_id === original.audit_id &&
        receipt.evidence.execution.status === "executed",
    ).length,
    0,
    "late approval must not rewrite the timed-out attempt into executed",
  );
});

test("CF-06 evaluate unavailable fails closed with block:true and no policy receipt", async () => {
  const spec = contractCase("CF-06");
  assert.equal(spec.expect.receipts.length, 0);
  const harness = makeHookContext({
    evaluate: async () => {
      throw new Error("guard api unavailable");
    },
  });
  registerAll(harness.context);

  const run = await runHostToolCall(harness, { toolCallId: "call-cf06" });

  assert.equal(run.blocked, true, "fail-closed must surface as block:true");
  assert.equal(harness.invocations.length, 0);
  assert.equal(harness.submitted.length, 0, "no policy fact, no policy-link receipt");
  assert.equal(harness.toolCallState.get("call-cf06").gateState, "blocked");
});

test("CF-07 tool failure produces execution_failed with bounded error", async () => {
  const spec = contractCase("CF-07");
  assert.equal(spec.expect.receipts[0].kind, "execution_failed");
  const harness = makeHookContext({ decision: "allow" });
  harness.throwWith = "x".repeat(5000);
  registerAll(harness.context);

  const run = await runHostToolCall(harness, {
    toolCallId: "call-cf07",
    behavior: "throw",
  });

  assert.equal(run.blocked, false);
  assert.equal(harness.invocations.length, 1);
  assert.equal(harness.submitted.length, 1);
  assert.equal(harness.submitted[0].metadata.outcome_kind, "execution_failed");
  assert.equal(harness.submitted[0].evidence.execution.status, "failed");
  // bounded error 实测：超限 error 恰好截断到 2000（省略号计入上限）。
  assert.equal(harness.submitted[0].evidence.execution.error.length, 2000);
  assert.ok(harness.submitted[0].evidence.execution.error.endsWith("..."));

  // falsy 成功（Q5）：无 result 无 error 仍关闭为 completed。
  const falsyHarness = makeHookContext({ decision: "allow" });
  registerAll(falsyHarness.context);
  await runHostToolCall(falsyHarness, {
    toolCallId: "call-cf07-falsy",
    behavior: "falsy",
  });
  assert.equal(falsyHarness.invocations.length, 1);
  assert.equal(falsyHarness.submitted.length, 1);
  assert.equal(
    falsyHarness.submitted[0].metadata.outcome_kind,
    "execution_completed",
  );
});

test("CF-12 result quarantine closure: modified + fail-closed quarantined receipts driven through the hook", async () => {
  const spec = contractCase("CF-12");
  assert.equal(spec.expect.receipts[0].kind, "tool_result_quarantined");

  // 映射层：quarantined 回执构造（未驱动真实处置，矩阵因此 NOT_SUPPORTED）。
  const guardEvent = {
    event_id: "evt_cf12",
    schema_version: "0.4",
    record_type: "guard_event",
    event_type: "tool_call_proposed",
    trace_id: "trace_cf12",
    timestamp: "2026-08-15T00:00:00Z",
    pre_execution: true,
    security_context: {
      agent_id: "agent_rte",
      user_task: "cf12",
      source_type: "tool",
      source_trust: "untrusted",
      run_id: null,
      current_step: "tool_call",
      context_sources: [],
      derived_paths: [],
      metadata: {},
    },
    payload: {
      tool: { name: "fetch", category: "tool", kind: "web", call_id: "call-cf12" },
      arguments: {},
      derived_resources: [],
    },
    metadata: {},
  };
  const evaluation = {
    decision: {
      decision_id: "dec_cf12",
      decision: "allow",
      risk_score: 10,
      severity: "low",
      rule_hits: [],
      reason: "ok",
    },
    approval: null,
    policy_audit_id: "audit_policy_cf12",
  };
  const quarantined = buildRuntimeOutcomeAuditEvent(
    guardEvent,
    evaluation,
    "tool_result_quarantine",
    { resultDisposition: "quarantined", stage: "tool_result_persist" },
  );
  assert.equal(quarantined.metadata.outcome_kind, "tool_result_quarantined");
  assert.equal(quarantined.evidence.execution.status, "executed");
  assert.equal(quarantined.evidence.result.disposition, "quarantined");

  // hook 层已证明的子集：含凭据结果在持久化前被脱敏改写 → modified 回执。
  const harness = makeHookContext({ decision: "allow" });
  registerAll(harness.context);
  await runHostToolCall(harness, { toolCallId: "call-cf12" });
  harness.handlers.tool_result_persist(
    {
      toolName: "spike_probe",
      toolCallId: "call-cf12",
      runId: "run-cf",
      result: "provider key sk-liveAbcdef1234567890 leaked",
      message: "provider key sk-liveAbcdef1234567890 leaked",
    },
    { toolName: "spike_probe", toolCallId: "call-cf12", runId: "run-cf" },
  );
  await flush();

  const modified = harness.submitted.filter(
    (receipt) => receipt.metadata.outcome_kind === "tool_result_modified",
  );
  assert.equal(modified.length, 1);
  assert.equal(modified[0].evidence.execution.status, "executed");
  assert.equal(modified[0].evidence.result.disposition, "modified");
  assert.equal(modified[0].evidence.result.sanitized, true);

  // 真实隔离闭环（契约 03 §7.2，RTE-04 硬化）：fail-closed quarantine
  // 能关联原 action/policy 时，结果同步替换 + quarantined 回执必须同时成立。
  const closureHarness = makeHookContext({ decision: "allow" });
  registerAll(closureHarness.context);
  await runHostToolCall(closureHarness, { toolCallId: "call-cf12-closure" });
  // persist 阶段评估同步不可用 → fail-closed quarantine。
  closureHarness.context.makeClient().evaluate = () => {
    throw new Error("guard api unavailable");
  };
  const quarantinedResult = closureHarness.handlers.tool_result_persist(
    {
      toolName: "spike_probe",
      toolCallId: "call-cf12-closure",
      runId: "run-cf",
      result: "sensitive payload",
      message: "sensitive payload",
    },
    { toolName: "spike_probe", toolCallId: "call-cf12-closure", runId: "run-cf" },
  );
  // 结果被同步替换（隔离）。
  assert.ok(quarantinedResult);
  assert.ok(String(quarantinedResult.message).includes("quarantined"));
  await flush();
  const quarantinedReceipts = closureHarness.submitted.filter(
    (receipt) => receipt.metadata.outcome_kind === "tool_result_quarantined",
  );
  assert.equal(quarantinedReceipts.length, 1);
  assert.equal(quarantinedReceipts[0].evidence.execution.status, "executed");
  assert.equal(quarantinedReceipts[0].evidence.result.disposition, "quarantined");
  assert.equal(quarantinedReceipts[0].links.action_id, "call-cf12-closure");

  // 无关联时仅诊断，不伪造 policy link。
  const unlinkedHarness = makeHookContext({ decision: "allow" });
  registerAll(unlinkedHarness.context);
  unlinkedHarness.context.makeClient().evaluate = () => {
    throw new Error("guard api unavailable");
  };
  const unlinkedResult = unlinkedHarness.handlers.tool_result_persist(
    {
      toolName: "spike_probe",
      toolCallId: "call-cf12-unlinked",
      runId: "run-cf",
      result: "x",
      message: "x",
    },
    { toolName: "spike_probe", toolCallId: "call-cf12-unlinked", runId: "run-cf" },
  );
  assert.ok(unlinkedResult);
  assert.ok(String(unlinkedResult.message).includes("quarantined"));
  assert.equal(unlinkedHarness.submitted.length, 0, "无关联不伪造回执");

  // 矩阵口径：真实隔离闭环已证明，openclaw CF-12 声明 PASS。
  const entry = loadMatrix().runtimes.openclaw["CF-12"];
  assert.equal(entry.status, "PASS");
  assert.ok(String(entry.note).length > 0);
});

test("CF-10/CF-11 stay NOT_SUPPORTED for the openclaw profile (delegated to Guard API)", () => {
  const matrix = loadMatrix().runtimes.openclaw;
  for (const caseId of ["CF-10", "CF-11"]) {
    const spec = contractCase(caseId);
    assert.equal(spec.scope, "idempotency");
    assert.equal(matrix[caseId].status, "NOT_SUPPORTED", caseId);
    assert.ok(
      String(matrix[caseId].note).length > 0,
      `${caseId} NOT_SUPPORTED requires a reason note`,
    );
  }
});
