// PR-RTE-04b — OpenClaw conformance profile (contract 05 §3, 06 §6).
//
// 固定决策 fake Guard API + 真实 plugin dist handlers，逐 CF case 断言
// gate/回执语义。case ID 与共享注册表 tests/runtime_conformance/
// contract_cases.json 绑定；能力矩阵见 expected_capabilities.json。
// Q9/Q5 spike 安全约束在 RTE-03 用例中另有回归，本文件只按 CF 口径复证。
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
    waitForApproval: async () =>
      options.waitResponse ?? { status: "resolved", decision: "allow_once" },
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
  return { handlers, submitted, toolCallState, degradations, context };
}

function registerAll(context) {
  registerBeforeToolCall(context);
  registerAfterToolCall(context);
  registerToolResultPersist(context);
}

const TOOL_CTX = { toolName: "spike_probe", runId: "run-cf" };
const beforeEvent = (toolCallId) => ({
  toolName: "spike_probe",
  params: { mode: "cf" },
  toolCallId,
  runId: "run-cf",
});
const afterEvent = (toolCallId, fields = {}) => ({
  toolName: "spike_probe",
  params: { mode: "cf" },
  toolCallId,
  runId: "run-cf",
  ...fields,
});

async function flush() {
  await new Promise((resolve) => setImmediate(resolve));
}

test("CF-01 allow executes once and closes a terminal fact", async () => {
  const spec = contractCase("CF-01");
  assert.equal(spec.expect.receipts[0].kind, "execution_completed");
  const { handlers, submitted, toolCallState, context } = makeHookContext({
    decision: "allow",
  });
  registerAll(context);

  await handlers.before_tool_call(beforeEvent("call-cf01"), TOOL_CTX);
  handlers.after_tool_call(
    afterEvent("call-cf01", { result: { ok: true } }),
    TOOL_CTX,
  );

  assert.equal(submitted.length, 1, "one terminal receipt for one action");
  const receipt = submitted[0];
  assert.equal(receipt.metadata.outcome_kind, "execution_completed");
  assert.equal(receipt.evidence.execution.status, "executed");
  assert.equal(receipt.links.action_id, "call-cf01");
  // Core 一致性：顶层 timestamp 与 completed_at 同源。
  assert.equal(receipt.timestamp, receipt.evidence.execution.completed_at);
  assert.equal(toolCallState.get("call-cf01").gateState, "allowed");
  assert.equal(toolCallState.get("call-cf01").terminalStatus, "executed");
});

test("CF-02 deny is not invoked and blocked after-arrival derives nothing", async () => {
  const spec = contractCase("CF-02");
  assert.equal(spec.expect.receipts[0].kind, "pre_execution_deny");
  assert.equal(spec.expect.invocation_count, 0);
  const { handlers, submitted, toolCallState, context } = makeHookContext({
    decision: "deny",
  });
  registerAll(context);

  await handlers.before_tool_call(beforeEvent("call-cf02"), TOOL_CTX);
  // pin 2026.7.1-2 已证明 blocked 也会发 after hook（error 形状）。
  handlers.after_tool_call(
    afterEvent("call-cf02", { error: "Tool call blocked by plugin" }),
    TOOL_CTX,
  );

  assert.equal(submitted.length, 1, "only the pre_execution_deny receipt");
  assert.equal(submitted[0].metadata.outcome_kind, "pre_execution_deny");
  assert.equal(submitted[0].evidence.execution.status, "not_invoked");
  assert.equal(toolCallState.get("call-cf02").gateState, "blocked");
  assert.equal(toolCallState.get("call-cf02").terminalStatus, undefined);
});

test("CF-03 ask + human deny stays not_invoked", async () => {
  const spec = contractCase("CF-03");
  assert.equal(spec.expect.invocation_count, 0);
  const { handlers, submitted, toolCallState, context } = makeHookContext({
    decision: "ask",
    approval: { approval_id: "appr_cf03", status: "pending" },
    waitResponse: { status: "resolved", decision: "deny" },
  });
  registerAll(context);

  await handlers.before_tool_call(beforeEvent("call-cf03"), TOOL_CTX);

  assert.equal(submitted.length, 1);
  assert.equal(submitted[0].metadata.outcome_kind, "pre_execution_deny");
  assert.equal(submitted[0].evidence.execution.status, "not_invoked");
  assert.equal(submitted[0].evidence.approval.status, "denied");
  assert.equal(toolCallState.get("call-cf03").gateState, "blocked");
});

test("CF-04 ask + allow_once releases once and closes terminal with approval evidence", async () => {
  const spec = contractCase("CF-04");
  const releaseSpec = spec.expect.receipts[0];
  assert.ok(releaseSpec.kind_any.includes("approval_release"));
  const { handlers, submitted, toolCallState, context } = makeHookContext({
    decision: "ask",
    approval: { approval_id: "appr_cf04", status: "pending" },
    waitResponse: { status: "resolved", decision: "allow_once" },
  });
  registerAll(context);

  await handlers.before_tool_call(beforeEvent("call-cf04"), TOOL_CTX);
  handlers.after_tool_call(
    afterEvent("call-cf04", { result: { ok: true } }),
    TOOL_CTX,
  );

  assert.equal(submitted.length, 2);
  assert.equal(submitted[0].metadata.outcome_kind, "approval_release");
  assert.equal(submitted[0].evidence.execution.status, "unknown");
  assert.equal(submitted[1].metadata.outcome_kind, "execution_completed");
  assert.equal(submitted[1].links.approval_id, "appr_cf04");
  assert.equal(submitted[1].evidence.approval.decision, "allow_once");
  assert.equal(toolCallState.get("call-cf04").gateState, "approval_released");
});

test("CF-05 wait timeout blocks and late approval does not resurrect", async () => {
  const spec = contractCase("CF-05");
  assert.equal(spec.expect.gate, "timed_out");
  const { handlers, submitted, toolCallState, context } = makeHookContext({
    decision: "ask",
    approval: { approval_id: "appr_cf05", status: "pending" },
    waitResponse: { status: "timeout", decision: "deny" },
  });
  registerAll(context);

  await handlers.before_tool_call(beforeEvent("call-cf05"), TOOL_CTX);
  assert.equal(submitted.length, 1);
  assert.equal(submitted[0].metadata.outcome_kind, "pre_execution_deny");
  assert.equal(submitted[0].evidence.execution.status, "not_invoked");
  assert.equal(submitted[0].evidence.approval.status, "expired");
  assert.equal(toolCallState.get("call-cf05").gateState, "timed_out");

  // 晚到审批/after 观察都不得复活已终结 attempt。
  handlers.after_tool_call(
    afterEvent("call-cf05", { result: { ok: true } }),
    TOOL_CTX,
  );
  assert.equal(submitted.length, 1, "no terminal fact for timed_out gate");
  assert.equal(toolCallState.get("call-cf05").terminalStatus, undefined);
});

test("CF-06 evaluate unavailable fails closed without policy receipt", async () => {
  const spec = contractCase("CF-06");
  assert.equal(spec.expect.receipts.length, 0);
  const { handlers, submitted, toolCallState, context } = makeHookContext({
    evaluate: async () => {
      throw new Error("guard api unavailable");
    },
  });
  registerAll(context);

  const result = await handlers.before_tool_call(
    beforeEvent("call-cf06"),
    TOOL_CTX,
  );

  assert.equal(result.block, true);
  assert.equal(submitted.length, 0, "no policy fact, no policy-link receipt");
  assert.equal(toolCallState.get("call-cf06").gateState, "blocked");
});

test("CF-07 tool failure produces execution_failed with bounded error", async () => {
  const spec = contractCase("CF-07");
  assert.equal(spec.expect.receipts[0].kind, "execution_failed");
  const { handlers, submitted, context } = makeHookContext({ decision: "allow" });
  registerAll(context);

  await handlers.before_tool_call(beforeEvent("call-cf07"), TOOL_CTX);
  handlers.after_tool_call(
    afterEvent("call-cf07", { error: "x".repeat(5000) }),
    TOOL_CTX,
  );

  assert.equal(submitted.length, 1);
  assert.equal(submitted[0].metadata.outcome_kind, "execution_failed");
  assert.equal(submitted[0].evidence.execution.status, "failed");
  // bounded error：省略号计入 2000 上限（契约 02 §9）。
  assert.equal(submitted[0].evidence.execution.error.length, 2000);
  assert.ok(submitted[0].evidence.execution.error.endsWith("..."));
});

test("CF-12 result quarantine keeps executed with quarantined/modified dispositions", async () => {
  const spec = contractCase("CF-12");
  assert.equal(spec.expect.receipts[0].kind, "tool_result_quarantined");

  // 映射层：隔离回执 executed + disposition=quarantined。
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

  // hook 层：含凭据的结果在持久化前被脱敏改写 → modified 回执。
  const { handlers, submitted, context } = makeHookContext({ decision: "allow" });
  registerAll(context);
  await handlers.before_tool_call(beforeEvent("call-cf12"), TOOL_CTX);
  handlers.tool_result_persist(
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

  const modified = submitted.filter(
    (receipt) => receipt.metadata.outcome_kind === "tool_result_modified",
  );
  assert.equal(modified.length, 1);
  assert.equal(modified[0].evidence.execution.status, "executed");
  assert.equal(modified[0].evidence.result.disposition, "modified");
  assert.equal(modified[0].evidence.result.sanitized, true);
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
