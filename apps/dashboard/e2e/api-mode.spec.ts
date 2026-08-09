import { expect, test, type Page } from "@playwright/test";

import { OPENCLAW_REQUIRED_HOOK_COUNT } from "../../../packages/agentguard-openclaw-plugin/hook-contract.mjs";
import { expectPrimaryRoutesLayout } from "./support/dashboard-layout";

const guardedServerErrorMessage = "核心服务暂时无法完成请求，请稍后重试。";
const guardedNotFoundMessage = "请求的资源不存在或已失效。";

const eventDto = {
  audit_id: "audit_api_001",
  schema_version: "0.3",
  trace_id: "trace_api_001",
  case_id: "PI-API-001",
  runtime: "langgraph",
  timestamp: "2026-06-28T08:00:00Z",
  stage: "before_tool_call",
  event_type: "tool_call_proposed",
  attack_type: "indirect_prompt_injection",
  is_malicious: true,
  summary: "Agent attempted to call send_email('exfil@example.invalid')",
  decision: "ask",
  risk_score: 64,
  severity: "medium",
  blocked: true,
  resource_targets: ["exfil@example.invalid"],
  rule_hits: ["P005_external_send", "P004_task_mismatch"],
  reason: "发送目标不在当前任务允许范围内，需要人工确认",
  links: {
    action_id: "action_api_001",
    decision_id: "decision_api_001",
    event_id: "evt_api_001",
  },
  latency_ms: 4,
  record_type: "policy_evaluation",
  integrity: {
    sequence: 1,
    prev_hash: null,
    event_hash: "hash_api",
    canonicalization: "json:v1",
  },
  metadata: {
    action_name: "send_email",
    channel: "email",
    recipient: "exfil@example.invalid",
    user_task: "整理客户反馈摘要",
  },
};

const metricsDto = {
  event_count: 1,
  allow_count: 0,
  deny_count: 0,
  ask_count: 1,
  blocked_count: 1,
  block_rate: 1,
  fpr: null,
  fnr: 0,
  average_latency_ms: 4,
};

async function installApiRoutes(
  page: Page,
  options: {
    approvals?: Record<string, unknown>[];
    authenticated?: boolean;
    dropApprovalAfterResolveFailure?: boolean;
    evaluation?: Record<string, unknown>;
    events?: Record<string, unknown>[];
    failConfigAudit?: boolean;
    health?: { database?: string; status: string };
    healthStatus?: number;
    provenance?: Record<string, unknown>;
    provenanceFailuresBeforeSuccess?: number;
    provenanceSnapshots?: Array<{
      etag: string;
      graph: Record<string, unknown>;
    }>;
    resolveApprovalStatus?: number;
    traceSnapshots?: Array<{
      approvals: Record<string, unknown>[];
      etag: string;
      events: Record<string, unknown>[];
    }>;
    traceStatus?: number;
  } = {},
) {
  const authenticated = options.authenticated ?? true;
  let provenanceFailuresRemaining = options.provenanceFailuresBeforeSuccess ?? 0;
  let provenanceSnapshotIndex = 0;
  let resolutionAttempted = false;
  let traceSnapshotIndex = 0;
  const traceConditionalHeaders: Array<string | null> = [];
  const provenanceConditionalHeaders: Array<string | null> = [];
  const traceEtag = '"trace-api-v1"';
  const provenanceEtag = '"provenance-api-v1"';

  await page.route("**/api/health?check_db=true", (route) =>
    route.fulfill({
      status: options.healthStatus ?? 200,
      json: options.health ?? { status: "ok", database: "ok" },
    }),
  );

  await page.route("**/api/v1/**", (route) => {
    const url = new URL(route.request().url());
    const path = url.pathname.replace("/api/v1", "");

    if (path === "/auth/browser/me") {
      if (!authenticated) {
        return route.fulfill({
          status: 401,
          json: { error: { code: "SESSION_EXPIRED" } },
        });
      }
      return route.fulfill({
        json: {
          authenticated: true,
          csrf_token: "csrf_api_mode",
          expires_at: "2026-06-28T09:00:00Z",
        },
      });
    }

    if (!authenticated) {
      return route.fulfill({
        status: 401,
        json: { error: { code: "SESSION_EXPIRED" } },
      });
    }

    if (path === "/audit/events") {
      return route.fulfill({ json: options.events ?? [eventDto] });
    }
    if (path === "/approvals/pending") {
      return route.fulfill({
        json:
          resolutionAttempted && options.dropApprovalAfterResolveFailure
            ? []
            : (options.approvals ?? []),
      });
    }
    if (path.startsWith("/approvals/") && path.endsWith("/resolve")) {
      resolutionAttempted = true;
      return route.fulfill({
        status: options.resolveApprovalStatus ?? 200,
        json:
          options.resolveApprovalStatus && options.resolveApprovalStatus >= 400
            ? { error: { code: "INTERNAL_ERROR" } }
            : {
                approval_id: path.split("/")[2],
                status: "resolved",
                decision: "deny",
              },
      });
    }
    if (path === "/policies/current") {
      return route.fulfill({
        json: { bundle_id: "default", version: "api-smoke" },
      });
    }
    if (path === "/policies/history") {
      return route.fulfill({
        json: [
          {
            revision: 7,
            updated_at: "2026-06-28T08:00:00Z",
            updated_by: "guard-api",
            bundle_id: "default",
            version: "api-smoke",
          },
        ],
      });
    }
    if (path === "/audit/integrity") {
      return route.fulfill({
        json: {
          valid: true,
          event_count: 1,
          head_hash: "hash_api",
          first_broken_audit_id: null,
        },
      });
    }
    if (path === "/evaluations/latest") {
      if (options.evaluation) {
        return route.fulfill({ json: options.evaluation });
      }
      return route.fulfill({
        status: 404,
        json: { error: { code: "EVALUATION_NOT_FOUND" } },
      });
    }
    if (path === "/config-audit/findings") {
      if (options.failConfigAudit) {
        return route.fulfill({
          status: 503,
          contentType: "text/plain",
          body: "配置审计接口暂不可用",
        });
      }
      return route.fulfill({ json: [] });
    }
    if (path === "/adapters/openclaw/status") {
      return route.fulfill({
        json: {
          status: "unknown",
          loaded: false,
          hook_count: null,
          expected_hook_count: OPENCLAW_REQUIRED_HOOK_COUNT,
          last_verified_at: null,
          error: null,
          source: null,
        },
      });
    }
    if (path === "/traces/trace_api_001") {
      traceConditionalHeaders.push(route.request().headers()["if-none-match"] ?? null);
      if (options.traceStatus) {
        return route.fulfill({
          status: options.traceStatus,
          json: { error: { code: "TRACE_NOT_FOUND" } },
        });
      }
      const snapshot =
        options.traceSnapshots?.[Math.min(traceSnapshotIndex, options.traceSnapshots.length - 1)];
      const activeTraceEtag = snapshot?.etag ?? traceEtag;
      if (options.traceSnapshots && traceSnapshotIndex < options.traceSnapshots.length - 1) {
        traceSnapshotIndex += 1;
      }
      if (route.request().headers()["if-none-match"] === activeTraceEtag) {
        return route.fulfill({ status: 304, headers: { ETag: activeTraceEtag } });
      }
      const traceEvents = snapshot?.events ?? options.events ?? [eventDto];
      return route.fulfill({
        headers: { ETag: activeTraceEtag },
        json: {
          trace_id: "trace_api_001",
          audit_events: traceEvents,
          approvals: snapshot?.approvals ?? options.approvals ?? [],
          metrics: metricsDto,
          audit_window: {
            limit: 500,
            returned_count: traceEvents.length,
            has_more: false,
          },
        },
      });
    }
    if (path === "/traces/trace_api_001/provenance") {
      provenanceConditionalHeaders.push(route.request().headers()["if-none-match"] ?? null);
      if (provenanceFailuresRemaining > 0) {
        provenanceFailuresRemaining -= 1;
        return route.fulfill({
          status: 503,
          contentType: "text/plain",
          body: "溯源关系接口暂不可用",
        });
      }
      const snapshot =
        options.provenanceSnapshots?.[
          Math.min(provenanceSnapshotIndex, options.provenanceSnapshots.length - 1)
        ];
      const activeProvenanceEtag = snapshot?.etag ?? provenanceEtag;
      if (
        options.provenanceSnapshots &&
        provenanceSnapshotIndex < options.provenanceSnapshots.length - 1
      ) {
        provenanceSnapshotIndex += 1;
      }
      const provenanceGraph = snapshot?.graph ?? options.provenance;
      if (provenanceGraph) {
        if (route.request().headers()["if-none-match"] === activeProvenanceEtag) {
          return route.fulfill({
            status: 304,
            headers: { ETag: activeProvenanceEtag },
          });
        }
        return route.fulfill({
          headers: { ETag: activeProvenanceEtag },
          json: provenanceGraph,
        });
      }
      if (route.request().headers()["if-none-match"] === activeProvenanceEtag) {
        return route.fulfill({ status: 304, headers: { ETag: activeProvenanceEtag } });
      }
      return route.fulfill({
        headers: { ETag: activeProvenanceEtag },
        json: {
          trace_id: "trace_api_001",
          nodes: [
            {
              node_id: "action:action_api_001",
              trace_id: "trace_api_001",
              kind: "action",
              ref_id: "action_api_001",
              label: "send_email",
              timestamp: "2026-06-28T08:00:00Z",
              metadata: { event_id: "audit_api_001", phase: "tool_policy" },
            },
            {
              node_id: "event:evt_api_001",
              trace_id: "trace_api_001",
              kind: "event",
              ref_id: "evt_api_001",
              label: "tool_call_proposed",
              timestamp: "2026-06-28T08:00:00Z",
              metadata: { runtime: "langgraph" },
            },
            {
              node_id: "decision:decision_api_001",
              trace_id: "trace_api_001",
              kind: "decision",
              ref_id: "decision_api_001",
              label: "ask",
              timestamp: "",
              metadata: { severity: "medium", risk_score: 64 },
            },
            {
              node_id: "audit:audit_api_001",
              trace_id: "trace_api_001",
              kind: "audit",
              ref_id: "audit_api_001",
              label: "tool_call_proposed",
              timestamp: "2026-06-28T08:00:00Z",
              metadata: { runtime: "langgraph", stage: "before_tool_call" },
            },
          ],
          edges: [
            {
              edge_id: "edge:action_api_001:decision_api_001",
              trace_id: "trace_api_001",
              source_node_id: "action:action_api_001",
              target_node_id: "decision:decision_api_001",
              relation: "evaluated_to",
              timestamp: "",
              metadata: { relation_type: "policy" },
            },
            {
              edge_id: "edge:evt_api_001:decision_api_001",
              trace_id: "trace_api_001",
              source_node_id: "event:evt_api_001",
              target_node_id: "decision:decision_api_001",
              relation: "evaluated_to",
              timestamp: "",
              metadata: {},
            },
            {
              edge_id: "edge:decision_api_001:audit_api_001",
              trace_id: "trace_api_001",
              source_node_id: "decision:decision_api_001",
              target_node_id: "audit:audit_api_001",
              relation: "recorded_as",
              timestamp: "2026-06-28T08:00:00Z",
              metadata: {},
            },
          ],
        },
      });
    }

    return route.fulfill({
      status: 404,
      json: { error: { code: "NOT_FOUND" } },
    });
  });

  return { provenanceConditionalHeaders, traceConditionalHeaders };
}

function uncertainApproval() {
  return {
    approval_id: "approval_uncertain",
    trace_id: "trace_api_001",
    tool_call_id: "call_uncertain",
    requesting_principal_id: "agent_api",
    runtime: "langgraph",
    agent_id: "agent_api",
    status: "pending",
    decision_options: ["allow_once", "deny"],
    decision: null,
    tool: "send_email",
    resource: "external@example.invalid",
    reason: "外部发送需要人工确认",
    risk_score: 64,
    severity: "medium",
    created_at: "2026-06-28T08:00:00Z",
    expires_at: "2099-06-28T08:05:00Z",
    resolved_at: null,
  };
}

function runtimeApproval(status: "pending" | "resolved", decision: "allow_once" | null) {
  return {
    ...uncertainApproval(),
    approval_id: "approval_runtime",
    action_id: "action_api_001",
    action_name: "send_email",
    tool_call_id: "action_api_001",
    status,
    decision,
    resolved_at: status === "resolved" ? "2026-06-28T08:00:02Z" : null,
  };
}

test("API mode preserves primary layouts across supported desktop workspaces", async ({ page }) => {
  await installApiRoutes(page, {
    evaluation: {
      run_id: "eval_api_layout",
      run_at: "2026-06-28T00:00:00+00:00",
      dataset_id: "api-layout",
      dataset_version: "v1",
      cases: [],
    },
  });
  await expectPrimaryRoutesLayout(page, "trace_api_001");
});

test("API mode conditionally refreshes a running action until its terminal receipt", async ({
  page,
}) => {
  const startEvent = {
    ...eventDto,
    audit_id: "audit_start_api_001",
    blocked: null,
    decision: null,
    event_type: "tool_call_started",
    evidence: {},
    integrity: {
      ...eventDto.integrity,
      sequence: 2,
      prev_hash: "hash_api",
      event_hash: "hash_start_api",
    },
    links: {
      action_id: "action_api_001",
      event_id: "evt_api_001",
      parent_audit_id: "audit_api_001",
    },
    reason: "工具调用已经开始",
    record_type: "runtime_observation",
    risk_score: null,
    severity: null,
    stage: "tool_call_started",
    summary: "工具调用已经开始",
    timestamp: "2026-06-28T08:00:02Z",
  };
  const outcomeEvent = {
    ...eventDto,
    audit_id: "audit_outcome_api_001",
    blocked: null,
    decision: null,
    event_type: "tool_call_completed",
    evidence: {
      execution: {
        completed_at: "2026-06-28T08:00:03Z",
        receipt_recorded: true,
        status: "executed",
      },
    },
    integrity: {
      ...eventDto.integrity,
      sequence: 3,
      prev_hash: "hash_start_api",
      event_hash: "hash_outcome_api",
    },
    links: {
      action_id: "action_api_001",
      approval_id: "approval_runtime",
      event_id: "evt_api_001",
      parent_audit_id: "audit_start_api_001",
      policy_audit_id: "audit_api_001",
    },
    reason: "工具执行完成",
    record_type: "runtime_outcome",
    risk_score: null,
    severity: null,
    stage: "after_tool_call",
    summary: "工具执行完成",
    timestamp: "2026-06-28T08:00:03Z",
  };
  const completedEvent = {
    ...eventDto,
    audit_id: "audit_trace_completed_api_001",
    blocked: null,
    decision: null,
    event_type: "trace_completed",
    evidence: {},
    integrity: {
      ...eventDto.integrity,
      sequence: 4,
      prev_hash: "hash_outcome_api",
      event_hash: "hash_trace_completed_api",
    },
    links: { event_id: "trace_api_001" },
    reason: "本次运行已经结束",
    record_type: "runtime_observation",
    risk_score: null,
    severity: null,
    stage: "trace_completed",
    summary: "本次运行已经结束",
    timestamp: "2026-06-28T08:00:04Z",
  };
  const requests = await installApiRoutes(page, {
    traceSnapshots: [
      {
        approvals: [runtimeApproval("pending", null)],
        etag: '"trace-runtime-v1"',
        events: [eventDto],
      },
      {
        approvals: [runtimeApproval("resolved", "allow_once")],
        etag: '"trace-runtime-v2"',
        events: [eventDto, startEvent],
      },
      {
        approvals: [runtimeApproval("resolved", "allow_once")],
        etag: '"trace-runtime-v3"',
        events: [eventDto, startEvent, outcomeEvent, completedEvent],
      },
    ],
  });

  await page.goto("/evidence/trace_api_001");
  const action = page.locator(".execution-node").filter({ hasText: "发送邮件" });
  await expect(action).toContainText("等待审批");
  await expect(action).toContainText("正在执行", { timeout: 4_500 });
  await expect(action).toContainText("已执行", { timeout: 5_000 });
  await expect(page.locator(".execution-trace__state-line")).toContainText("运行已结束");
  await expect(page.locator(".execution-trace__connection")).toContainText("运行结果已确认");
  expect(requests.traceConditionalHeaders).toContain('"trace-runtime-v1"');
  expect(requests.traceConditionalHeaders).toContain('"trace-runtime-v2"');
});

test("API mode appends a new execution node without moving existing graph positions", async ({
  page,
}) => {
  const secondAction = {
    ...eventDto,
    audit_id: "audit_api_002",
    blocked: false,
    decision: "allow",
    event_type: "tool_call_proposed",
    integrity: {
      ...eventDto.integrity,
      event_hash: "hash_api_002",
      prev_hash: "hash_api",
      sequence: 2,
    },
    links: {
      action_id: "action_api_002",
      decision_id: "decision_api_002",
      event_id: "evt_api_002",
    },
    metadata: {
      action_name: "read_file",
      path: "/workspace/report.txt",
      user_task: "整理客户反馈摘要",
    },
    reason: "文件读取符合当前任务范围",
    resource_targets: ["/workspace/report.txt"],
    risk_score: 18,
    rule_hits: [],
    severity: "low",
    summary: "Agent requested a second action",
    timestamp: "2026-06-28T08:00:01Z",
  };
  await installApiRoutes(page, {
    traceSnapshots: [
      { approvals: [], etag: '"trace-append-v1"', events: [eventDto] },
      { approvals: [], etag: '"trace-append-v2"', events: [eventDto, secondAction] },
    ],
  });

  await page.goto("/evidence/trace_api_001");
  const firstNode = page.locator(".execution-node").filter({ hasText: "发送邮件" });
  await expect(firstNode).toBeVisible();
  const firstPosition = await firstNode.evaluate(
    (element) => element.parentElement?.getAttribute("style") ?? "",
  );
  const scrollY = await page.evaluate(() => window.scrollY);

  await expect(page.locator(".execution-node")).toHaveCount(2, { timeout: 4_500 });
  await expect(page.locator(".execution-node").filter({ hasText: "读取文件" })).toBeVisible();
  await expect(page.locator(".execution-trace__updates")).toContainText("1 个新增或更新步骤");
  expect(
    await firstNode.evaluate((element) => element.parentElement?.getAttribute("style") ?? ""),
  ).toBe(firstPosition);
  expect(await page.evaluate(() => window.scrollY)).toBe(scrollY);
});

test("API mode renders every supported guard stage once and groups one tool lifecycle", async ({
  page,
}) => {
  const policyEvent = (
    index: number,
    eventType: string,
    actionName: string,
    actionId?: string,
  ) => ({
    ...eventDto,
    audit_id: `audit_matrix_${index}`,
    blocked: false,
    decision: "allow",
    event_type: eventType,
    integrity: {
      canonicalization: "json:v1",
      event_hash: `hash_matrix_${index}`,
      prev_hash: index === 1 ? null : `hash_matrix_${index - 1}`,
      sequence: index,
    },
    links: {
      ...(actionId ? { action_id: actionId } : {}),
      decision_id: `decision_matrix_${index}`,
      event_id: `event_matrix_${index}`,
    },
    metadata: { action_name: actionName, user_task: "整理运行记录" },
    reason: "安全检查通过",
    risk_score: 0,
    severity: "low",
    stage: eventType,
    summary: `${eventType} recorded`,
    timestamp: `2026-06-28T08:00:${String(index).padStart(2, "0")}Z`,
  });
  const events = [
    policyEvent(1, "context_assembled", "context_assembled"),
    policyEvent(2, "model_input_prepared", "model_input_prepared"),
    policyEvent(3, "tool_call_proposed", "read_file", "call_matrix_read"),
    policyEvent(4, "tool_result_produced", "read_file", "call_matrix_read"),
    policyEvent(5, "model_output_produced", "model_output_produced", "event_matrix_5"),
    policyEvent(6, "memory_write_proposed", "memory_write", "event_matrix_6"),
    policyEvent(7, "message_send_proposed", "send_message", "event_matrix_7"),
    {
      ...eventDto,
      audit_id: "audit_matrix_terminal",
      blocked: null,
      decision: null,
      event_type: "trace_completed",
      integrity: {
        canonicalization: "json:v1",
        event_hash: "hash_matrix_terminal",
        prev_hash: "hash_matrix_7",
        sequence: 8,
      },
      links: { event_id: "trace_api_001" },
      reason: "本次运行已经结束",
      record_type: "runtime_observation",
      risk_score: null,
      severity: null,
      stage: "trace_completed",
      summary: "本次运行已经结束",
      timestamp: "2026-06-28T08:00:08Z",
    },
  ];
  await installApiRoutes(page, { events });

  await page.goto("/evidence/trace_api_001");
  const steps = page.locator(".execution-node");
  await expect(steps).toHaveCount(6);
  await expect(steps).toContainText([
    "检查输入上下文",
    "检查模型输入",
    "读取文件",
    "检查模型输出",
    "写入记忆",
    "发送消息",
  ]);

  let visibleStepEventCount = 0;
  for (let index = 0; index < (await steps.count()); index += 1) {
    await steps.nth(index).focus();
    await page.keyboard.press("Enter");
    visibleStepEventCount += await page.locator(".execution-inspector__events li").count();
  }
  expect(visibleStepEventCount).toBe(7);
  await steps.filter({ hasText: "读取文件" }).focus();
  await page.keyboard.press("Enter");
  await expect(page.locator(".execution-inspector__events li")).toHaveCount(2);
  await expect(page.locator(".execution-lane")).toHaveCount(2);
  await expect(page.locator(".execution-lane")).toContainText(["智能体处理", "受控动作"]);

  await page.getByRole("searchbox", { name: "搜索运行步骤" }).fill("写入记忆");
  await expect(page.locator(".execution-node")).toHaveCount(6);
  await expect(page.locator(".execution-flow-node--matched")).toHaveCount(1);
  await expect(page.locator(".execution-flow-node--dimmed")).toHaveCount(5);
});

test("API mode keeps a large execution trace navigable without rendering every offscreen node", async ({
  page,
}) => {
  const events = Array.from({ length: 85 }, (_, offset) => {
    const index = offset + 1;
    return {
      ...eventDto,
      audit_id: `audit_large_${index}`,
      blocked: false,
      decision: "allow",
      integrity: {
        canonicalization: "json:v1",
        event_hash: `hash_large_${index}`,
        prev_hash: index === 1 ? null : `hash_large_${index - 1}`,
        sequence: index,
      },
      links: {
        action_id: `action_large_${index}`,
        decision_id: `decision_large_${index}`,
        event_id: `event_large_${index}`,
      },
      metadata: {
        action_name: "read_file",
        path: `/workspace/report-${index}.txt`,
        user_task: "检查批量文件",
      },
      reason: "文件读取符合当前任务范围",
      resource_targets: [`/workspace/report-${index}.txt`],
      risk_score: 8,
      rule_hits: [],
      severity: "low",
      summary: `Agent requested file ${index}`,
      timestamp: `2026-06-28T08:${String(Math.floor(offset / 60)).padStart(2, "0")}:${String(offset % 60).padStart(2, "0")}Z`,
    };
  });
  await installApiRoutes(page, { events });

  await page.goto("/evidence/trace_api_001");
  const graph = page.locator(".execution-flow");
  await expect(graph).toContainText("大轨迹已定位当前步骤");
  await expect(graph.locator(".vue-flow__minimap")).toBeVisible();
  await expect(graph.locator('[data-action-id="action_large_85"]')).toBeVisible();
  const renderedNodeCount = await graph.locator(".execution-node").count();
  expect(renderedNodeCount).toBeGreaterThan(0);
  expect(renderedNodeCount).toBeLessThan(85);
  expect(
    await page.evaluate(
      () => document.documentElement.scrollWidth <= document.documentElement.clientWidth,
    ),
  ).toBe(true);
});

test("API mode keeps independent validators for trace and provenance snapshots", async ({
  page,
}) => {
  const requests = await installApiRoutes(page);
  await page.goto("/evidence/trace_api_001");

  await expect
    .poll(() => requests.traceConditionalHeaders, { timeout: 4_500 })
    .toContain('"trace-api-v1"');
  await page.getByRole("tab", { name: "溯源关系" }).click();
  await expect(page.locator(".provenance-flow")).toBeVisible();
  await page.getByRole("button", { name: "更新溯源关系" }).click();
  await expect.poll(() => requests.provenanceConditionalHeaders).toContain('"provenance-api-v1"');
  await expect(page.locator(".prov-node--action")).toContainText("send_email");
});

test("provenance updates preserve filters, collapsed stages and the selected node anchor", async ({
  page,
}) => {
  const nodes = [
    {
      node_id: "action:action_api_001",
      trace_id: "trace_api_001",
      kind: "action",
      ref_id: "action_api_001",
      label: "send_email",
      timestamp: "2026-06-28T08:00:00Z",
      metadata: { critical: true, phase: "tool_policy", status: "pending" },
    },
    {
      node_id: "decision:decision_api_001",
      trace_id: "trace_api_001",
      kind: "decision",
      ref_id: "decision_api_001",
      label: "ask",
      timestamp: "2026-06-28T08:00:00Z",
      metadata: { critical: true, phase: "tool_policy" },
    },
    {
      node_id: "audit:audit_api_001",
      trace_id: "trace_api_001",
      kind: "audit",
      ref_id: "audit_api_001",
      label: "tool_call_proposed",
      timestamp: "2026-06-28T08:00:00Z",
      metadata: { critical: true, phase: "outcome_audit" },
    },
  ];
  const edges = [
    {
      edge_id: "edge:action_api_001:decision_api_001",
      trace_id: "trace_api_001",
      source_node_id: "action:action_api_001",
      target_node_id: "decision:decision_api_001",
      relation: "evaluated_to",
      timestamp: "2026-06-28T08:00:00Z",
      metadata: { relation_type: "policy" },
    },
    {
      edge_id: "edge:decision_api_001:audit_api_001",
      trace_id: "trace_api_001",
      source_node_id: "decision:decision_api_001",
      target_node_id: "audit:audit_api_001",
      relation: "recorded_as",
      timestamp: "2026-06-28T08:00:00Z",
      metadata: { relation_type: "audit" },
    },
  ];
  await installApiRoutes(page, {
    provenanceSnapshots: [
      {
        etag: '"provenance-anchor-v1"',
        graph: { trace_id: "trace_api_001", nodes, edges },
      },
      {
        etag: '"provenance-anchor-v2"',
        graph: {
          trace_id: "trace_api_001",
          nodes: [
            {
              ...nodes[0],
              metadata: { critical: true, phase: "tool_policy", status: "executed" },
            },
            ...nodes.slice(1),
            {
              ...nodes[0],
              node_id: "action:action_api_002",
              ref_id: "action_api_002",
              label: "read_file",
              timestamp: "2026-06-28T08:00:02Z",
            },
          ],
          edges: [
            ...edges,
            {
              ...edges[0],
              edge_id: "edge:action_api_002:decision_api_001",
              source_node_id: "action:action_api_002",
            },
          ],
        },
      },
    ],
  });

  await page.goto("/evidence/trace_api_001");
  await page.getByRole("tab", { name: "溯源关系" }).click();
  const graph = page.locator(".provenance-workbench");
  await graph.locator(".prov-node--action").click();
  await expect(graph.locator(".prov-node--selected")).toContainText("待审批");
  const kindFilter = graph.getByRole("combobox", { name: "节点类型筛选" });
  await kindFilter.selectOption("action");
  const inputPhase = graph.locator(".provenance-phases button").filter({ hasText: "输入与信任" });
  await inputPhase.click();
  await expect(inputPhase).toHaveAttribute("aria-pressed", "false");

  const selected = graph.locator(".prov-node--selected");
  const selectedCenter = () =>
    selected.evaluate((element) => {
      const rect = element.getBoundingClientRect();
      const canvasRect = element.closest(".provenance-canvas")?.getBoundingClientRect();
      if (!canvasRect) throw new Error("Provenance canvas is missing");
      return {
        x: rect.x + rect.width / 2 - canvasRect.x,
        y: rect.y + rect.height / 2 - canvasRect.y,
      };
    });
  await expect
    .poll(async () => {
      const first = await selectedCenter();
      await page.waitForTimeout(50);
      const second = await selectedCenter();
      return Math.abs(second.x - first.x) + Math.abs(second.y - first.y);
    })
    .toBeLessThanOrEqual(0.5);
  const before = await selectedCenter();
  await page.getByRole("button", { name: "更新溯源关系" }).click();
  await expect(graph.locator(".prov-node--action")).toHaveCount(2);
  await expect
    .poll(async () => {
      const first = await selectedCenter();
      await page.waitForTimeout(50);
      const second = await selectedCenter();
      return Math.abs(second.x - first.x) + Math.abs(second.y - first.y);
    })
    .toBeLessThanOrEqual(0.5);

  await expect(kindFilter).toHaveValue("action");
  await expect(inputPhase).toHaveAttribute("aria-pressed", "false");
  await expect(selected).toContainText("send_email");
  await expect(selected).toContainText("已执行");
  const after = await selectedCenter();
  expect(Math.abs(after.x - before.x)).toBeLessThanOrEqual(2);
  expect(Math.abs(after.y - before.y)).toBeLessThanOrEqual(2);
});

test("API mode renders authenticated dashboard and tolerates partial endpoint failure", async ({
  page,
}) => {
  const runtimeErrors: string[] = [];
  page.on("pageerror", (error) => runtimeErrors.push(error.message));

  await installApiRoutes(page, { failConfigAudit: true });
  const auditRequestPromise = page.waitForRequest((request) =>
    request.url().includes("/api/v1/audit/events?"),
  );
  await page.goto("/overview");
  const auditHeaders = (await auditRequestPromise).headers();

  await expect(page.getByRole("heading", { name: "安全总览" })).toBeVisible();
  expect(auditHeaders.accept).toBe("application/json");
  expect(auditHeaders["content-type"]).toBeUndefined();
  await expect(page.locator("body")).not.toContainText(/P\d{3}/);
  const deniedMetric = page.locator(".metric-strip__item").filter({ hasText: "拒绝" });
  await expect(deniedMetric.locator("dd")).toHaveText("0");
  await expect(deniedMetric.getByRole("link")).toHaveAttribute(
    "href",
    "/investigations?decision=deny",
  );
  const approvalMetric = page.locator(".metric-strip__item").filter({ hasText: "需审批" });
  await expect(approvalMetric.locator("dd")).toHaveText("1");
  await expect(approvalMetric).toContainText("审批触发率 100.0%");
  await expect(approvalMetric.getByRole("link")).toHaveAttribute(
    "href",
    "/investigations?decision=ask",
  );
  await expect(page.locator("body")).not.toContainText("Guard 决策随当前审计窗口变化");

  await page.goto("/evidence/trace_api_001");
  await expect(page.locator(".evidence-hero")).toContainText("策略决定：需审批");
  await expect(page.locator(".evidence-hero")).not.toContainText(/P\d{3}/);
  await page.locator(".evidence-context > summary").click();
  await expect(page.locator(".evidence-facts")).toContainText("当前返回事件均带完整性元数据");
  await expect(page.locator(".execution-node")).toContainText("发送邮件");
  await page.getByRole("tab", { name: "溯源关系" }).click();
  await expect(page.locator(".prov-node--decision")).toContainText("需审批");
  await expect(page.locator(".prov-node--decision")).toContainText("风险 64");
  await page.locator(".prov-node--decision").click();
  await expect(
    page.locator(".provenance-flow").getByText("判定", { exact: true }).first(),
  ).toBeVisible();
  await page.locator(".provenance-workbench").getByRole("button", { name: "适配" }).click();
  await page.locator(".prov-node--audit").click();
  await expect(page).toHaveURL(/event_id=audit_api_001/);
  await page.getByRole("button", { name: "查看关联事件" }).click();
  await expect(page.getByRole("dialog")).toContainText("send_email");

  await page.goto("/system");
  await expect(page.getByRole("heading", { name: "系统状态" })).toBeVisible();
  await expect(page.locator(".system-page")).toContainText(guardedServerErrorMessage);
  await expect(page.locator(".system-page")).not.toContainText("配置审计接口暂不可用");
  await expect(page.locator("body")).not.toContainText(/P\d{3}/);
  expect(runtimeErrors).toEqual([]);
});

test("API mode never falls back to fixture evidence after a trace failure", async ({ page }) => {
  await installApiRoutes(page, { events: [], traceStatus: 404 });
  await page.goto("/evidence/trace_api_001");

  await expect(page.getByRole("alert")).toContainText(guardedNotFoundMessage);
  await expect(page.locator("body")).not.toContainText("trace_001");
  await expect(page.locator("body")).not.toContainText("/private/token.txt");
  await expect(page.locator("body")).not.toContainText("总结邮件内容");
  await expect(page.locator(".evidence-hero")).toHaveCount(0);
});

test("provenance workbench controls a graph larger than 24 nodes", async ({ page }) => {
  const nodes = Array.from({ length: 26 }, (_, index) => ({
    node_id: `node:${index}`,
    trace_id: "trace_api_001",
    kind: ["task", "source", "context", "model_intent", "action", "resource", "rule", "policy"][
      index % 8
    ],
    ref_id: `ref_${index}`,
    label: `证据节点 ${index}`,
    timestamp: `2026-06-28T08:${String(index).padStart(2, "0")}:00Z`,
    metadata: {
      critical: index < 8,
      phase: ["input_trust", "context_intent", "tool_policy", "outcome_audit"][index % 4],
      summary: `第 ${index} 个证据分支`,
    },
  }));
  const edges = Array.from({ length: 25 }, (_, index) => ({
    edge_id: `edge:${index}`,
    trace_id: "trace_api_001",
    source_node_id: `node:${index}`,
    target_node_id: `node:${index + 1}`,
    relation: index % 2 ? "derived_from" : "evaluated_to",
    timestamp: "",
    metadata: {
      relation_type: index % 2 ? "causal" : "detection",
    },
  }));
  await installApiRoutes(page, {
    provenance: {
      edges,
      nodes,
      trace_id: "trace_api_001",
    },
  });
  await page.goto("/evidence/trace_api_001");
  await page.getByRole("tab", { name: "溯源关系" }).click();

  const graph = page.locator(".provenance-workbench");
  await expect(graph).toContainText("已收拢 18 个旁支或阶段节点");
  await expect(graph.locator(".vue-flow__minimap")).toBeVisible();
  await graph.getByRole("button", { name: "展开旁支" }).click();
  await expect(graph.locator(".vue-flow__node")).toHaveCount(26);

  await graph.getByRole("button", { name: "全屏" }).click();
  await expect(graph).toHaveClass(/provenance-workbench--fullscreen/);
  await page.keyboard.press("Escape");
  await expect(graph).not.toHaveClass(/provenance-workbench--fullscreen/);

  const search = graph.getByRole("searchbox", { name: "搜索溯源节点" });
  await search.fill("证据节点 25");
  await search.press("Enter");
  await expect(page).toHaveURL(/node_id=node%3A25|node_id=node:25/);
  await expect(graph.locator(".prov-node--selected")).toContainText("证据节点 25");
});

test("API mode retries provenance independently after a canonical endpoint failure", async ({
  page,
}) => {
  await installApiRoutes(page, { provenanceFailuresBeforeSuccess: 1 });
  await page.goto("/evidence/trace_api_001");
  await page.getByRole("tab", { name: "溯源关系" }).click();

  await expect(page.getByText(guardedServerErrorMessage)).toBeVisible();
  await expect(page.locator(".trace-provenance")).not.toContainText("溯源关系接口暂不可用");
  await page.getByRole("button", { name: "重新加载溯源关系" }).click();

  await expect(page.locator(".provenance-flow")).toBeVisible();
  await expect(page.getByText(guardedServerErrorMessage)).toHaveCount(0);
});

test("API mode renders degraded database health without marking the API offline", async ({
  page,
}) => {
  await installApiRoutes(page, {
    health: { status: "degraded", database: "error" },
    healthStatus: 503,
  });
  await page.goto("/system");

  const apiRow = page.locator(".status-ledger__rows article").filter({ hasText: "Guard API" });
  const databaseRow = page
    .locator(".status-ledger__rows article")
    .filter({ hasText: "PostgreSQL" });
  await expect(apiRow).toContainText("正常");
  await expect(databaseRow).toContainText("异常");
});

test("API mode keeps an uncertain approval available when reconciliation still returns it", async ({
  page,
}) => {
  await installApiRoutes(page, {
    approvals: [uncertainApproval()],
    resolveApprovalStatus: 503,
  });
  await page.goto("/approvals/approval_uncertain");
  await page.getByRole("button", { name: "拒绝授权" }).click();
  await page.getByRole("button", { name: "确认拒绝授权" }).click();

  await expect(
    page.getByText("审批提交结果未确认，已尝试刷新待审批队列，请以当前状态为准。"),
  ).toBeVisible();
  await expect(page.getByRole("dialog", { name: "确认拒绝本次授权？" })).toBeVisible();
  await expect(page.getByRole("button", { name: "确认拒绝授权", exact: true })).toBeEnabled();
  await expect(page.getByRole("button", { name: "拒绝授权", exact: true })).toBeEnabled();
  await expect(page).toHaveURL(/\/approvals\/approval_uncertain$/);
});

test("API mode leaves a removed uncertain approval without inferring its outcome", async ({
  page,
}) => {
  await installApiRoutes(page, {
    approvals: [uncertainApproval()],
    dropApprovalAfterResolveFailure: true,
    resolveApprovalStatus: 503,
  });
  await page.goto("/approvals/approval_uncertain");
  await page.getByRole("button", { name: "拒绝授权" }).click();
  await page.getByRole("button", { name: "确认拒绝授权" }).click();

  await expect(
    page.getByText("审批提交结果未确认，已尝试刷新待审批队列，请以当前状态为准。"),
  ).toBeVisible();
  await expect(page.getByText("审批队列已清空")).toBeVisible();
  await expect(page).toHaveURL(/\/approvals$/);
  await expect(page.getByText(/已拒绝|已允许/)).toHaveCount(0);
});

test("API mode disables an approval when its expiry passes without another poll", async ({
  page,
}) => {
  const now = new Date("2026-06-28T08:00:00Z");
  await page.clock.install({ time: now });
  await installApiRoutes(page, {
    approvals: [
      {
        approval_id: "approval_expiring",
        trace_id: "trace_api_001",
        tool_call_id: "call_expiring",
        requesting_principal_id: "agent_api",
        runtime: "langgraph",
        agent_id: "agent_api",
        status: "pending",
        decision_options: ["allow_once", "deny"],
        decision: null,
        tool: "send_email",
        resource: "external@example.invalid",
        reason: "外部发送需要人工确认",
        risk_score: 64,
        severity: "medium",
        created_at: new Date(now.getTime() - 60_000).toISOString(),
        expires_at: new Date(now.getTime() + 60_000).toISOString(),
        resolved_at: null,
      },
    ],
  });
  await page.goto("/approvals");

  const denyButton = page.getByRole("button", { name: "拒绝授权" });
  await expect(denyButton).toBeEnabled();
  await expect(page.locator(".approval-queue time")).toContainText("分钟后过期");
  await page.clock.fastForward(61_000);
  await expect(page.getByText("审批已过期，不能继续处理")).toBeVisible();
  await expect(page.locator(".approval-queue time")).toHaveText("已过期");
  await expect(denyButton).toBeDisabled();
});

test("API mode queues new events while the investigation list is scrolled", async ({ page }) => {
  const events = Array.from({ length: 30 }, (_, index) => ({
    ...eventDto,
    audit_id: `audit_api_${String(index + 1).padStart(3, "0")}`,
    timestamp: new Date(Date.parse(eventDto.timestamp) - index * 60_000).toISOString(),
  }));
  await installApiRoutes(page, { events });
  await page.goto("/investigations");
  await expect(page.locator(".event-table tbody tr")).toHaveCount(20);

  await page.evaluate(() => window.scrollTo(0, document.documentElement.scrollHeight));
  await expect.poll(() => page.evaluate(() => window.scrollY)).toBeGreaterThan(40);

  events.push({
    ...eventDto,
    audit_id: "audit_api_new",
    timestamp: "2026-06-28T09:00:00Z",
    summary: "Agent requested a newly arrived action",
    resource_targets: ["new-target.example.invalid"],
    metadata: {
      ...eventDto.metadata,
      action_name: "new_event_tool",
      recipient: "new-target.example.invalid",
    },
  });
  await page.evaluate(() => document.dispatchEvent(new Event("visibilitychange")));

  await expect(page.getByText("有 1 条新事件")).toBeVisible();
  await expect(page.locator(".event-table tbody")).not.toContainText("new_event_tool");
  await page.getByRole("button", { name: "查看新事件" }).click();
  await expect(page.locator(".event-table tbody tr").first()).toContainText("new_event_tool");
  await expect.poll(() => page.evaluate(() => window.scrollY)).toBeLessThanOrEqual(1);
});

test("API mode shows a session error instead of a blank dashboard", async ({ page }) => {
  await installApiRoutes(page, { authenticated: false });
  await page.goto("/overview");

  await expect(page.getByRole("alert")).toContainText("无法建立安全会话");
  await expect(page.getByRole("alert")).toContainText("当前会话已过期");
});

test("API polling requests only common data and the active page domain", async ({ page }) => {
  const requestedPaths: string[] = [];
  page.on("request", (request) => {
    const url = new URL(request.url());
    if (url.pathname.startsWith("/api/")) requestedPaths.push(url.pathname);
  });
  await installApiRoutes(page);

  await page.goto("/overview");
  await expect(page.getByRole("heading", { name: "安全总览" })).toBeVisible();
  await expect(page.locator(".metric-strip")).toContainText("审计记录");
  await expect(page.locator(".freshness--ready").first()).toBeVisible();

  const overviewPaths = [...requestedPaths];
  expect(overviewPaths).toContain("/api/v1/audit/events");
  expect(overviewPaths).not.toContain("/api/v1/metrics/eval");
  expect(overviewPaths).not.toContain("/api/v1/policies/current");
  expect(overviewPaths).not.toContain("/api/v1/config-audit/findings");
  expect(overviewPaths).not.toContain("/api/v1/adapters/openclaw/status");

  requestedPaths.length = 0;
  await page.getByRole("link", { name: "安全评测" }).click();
  await expect(page.getByRole("heading", { name: "安全评测" })).toBeVisible();
  await expect.poll(() => requestedPaths.includes("/api/v1/evaluations/latest")).toBe(true);

  expect(requestedPaths).not.toContain("/api/v1/audit/events");
  expect(requestedPaths).not.toContain("/api/v1/metrics/eval");
  expect(requestedPaths).not.toContain("/api/v1/policies/current");

  requestedPaths.length = 0;
  await page.getByRole("link", { name: "系统状态" }).click();
  await expect(page.getByRole("heading", { name: "系统状态" })).toBeVisible();
  await expect.poll(() => requestedPaths.includes("/api/v1/policies/current")).toBe(true);

  expect(requestedPaths).toContain("/api/v1/policies/history");
  expect(requestedPaths).toContain("/api/v1/config-audit/findings");
  expect(requestedPaths).toContain("/api/v1/adapters/openclaw/status");
  expect(requestedPaths).not.toContain("/api/v1/audit/events");
});

test("manual refresh bypasses the shared-resource freshness window", async ({ page }) => {
  const requestedPaths: string[] = [];
  page.on("request", (request) => {
    const url = new URL(request.url());
    if (url.pathname.startsWith("/api/")) requestedPaths.push(url.pathname);
  });
  await installApiRoutes(page);
  await page.goto("/overview");
  await expect(page.locator(".freshness--ready").first()).toBeVisible();

  requestedPaths.length = 0;
  await page.getByRole("button", { name: "刷新数据" }).click();
  await expect.poll(() => requestedPaths.includes("/api/v1/audit/events")).toBe(true);
  expect(requestedPaths).not.toContain("/api/v1/metrics/eval");
});
