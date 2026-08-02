import { expect, test, type Page } from "@playwright/test";

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
  links: { event_id: "evt_api_001" },
  latency_ms: 4,
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
    events?: Array<typeof eventDto>;
    failConfigAudit?: boolean;
    provenance?: Record<string, unknown>;
    provenanceFailuresBeforeSuccess?: number;
    traceStatus?: number;
  } = {},
) {
  const authenticated = options.authenticated ?? true;
  let provenanceFailuresRemaining = options.provenanceFailuresBeforeSuccess ?? 0;

  await page.route("**/api/health?check_db=true", (route) =>
    route.fulfill({ json: { status: "ok", database: "ok" } }),
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
    if (path === "/metrics/eval") return route.fulfill({ json: metricsDto });
    if (path === "/approvals/pending") {
      return route.fulfill({ json: options.approvals ?? [] });
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
          expected_hook_count: 16,
          last_verified_at: null,
          error: null,
          source: null,
        },
      });
    }
    if (path === "/traces/trace_api_001") {
      if (options.traceStatus) {
        return route.fulfill({
          status: options.traceStatus,
          json: { error: { code: "TRACE_NOT_FOUND" } },
        });
      }
      return route.fulfill({
        json: {
          trace_id: "trace_api_001",
          audit_events: options.events ?? [eventDto],
          approvals: [],
          metrics: metricsDto,
        },
      });
    }
    if (path === "/traces/trace_api_001/provenance") {
      if (provenanceFailuresRemaining > 0) {
        provenanceFailuresRemaining -= 1;
        return route.fulfill({
          status: 503,
          contentType: "text/plain",
          body: "溯源关系接口暂不可用",
        });
      }
      if (options.provenance) {
        return route.fulfill({ json: options.provenance });
      }
      return route.fulfill({
        json: {
          trace_id: "trace_api_001",
          nodes: [
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
}

test("API mode renders authenticated dashboard and tolerates partial endpoint failure", async ({
  page,
}) => {
  const runtimeErrors: string[] = [];
  page.on("pageerror", (error) => runtimeErrors.push(error.message));

  await installApiRoutes(page, { failConfigAudit: true });
  await page.goto("/overview");

  await expect(page.getByRole("heading", { name: "安全总览" })).toBeVisible();
  await expect(page.locator("body")).not.toContainText(/P\d{3}/);
  const deniedMetric = page.locator(".metric-strip__item").filter({ hasText: "拒绝" });
  await expect(deniedMetric.locator("dd")).toHaveText("0");
  await expect(deniedMetric.getByRole("link")).toHaveAttribute(
    "href",
    "/investigations?decision=deny",
  );

  await page.goto("/evidence/trace_api_001");
  await expect(page.locator(".evidence-hero")).toContainText("策略决定：需审批");
  await expect(page.locator(".evidence-hero")).not.toContainText(/P\d{3}/);
  await expect(page.locator(".evidence-facts")).toContainText("当前返回事件均带完整性元数据");
  await expect(page.locator(".prov-node--decision")).toContainText("需审批");
  await expect(page.locator(".prov-node--decision")).toContainText("风险 64");
  await page.locator(".prov-node--decision").click();
  await expect(page.locator(".provenance-flow").getByText("判定", { exact: true })).toBeVisible();
  await page.locator(".prov-node--audit").click();
  await expect(page).toHaveURL(/event_id=audit_api_001/);
  await page.getByRole("button", { name: "查看关联原始审计" }).click();
  await expect(page.getByRole("dialog")).toContainText("send_email");

  await page.goto("/system");
  await expect(page.getByRole("heading", { name: "系统状态" })).toBeVisible();
  await expect(page.locator(".system-page")).toContainText("配置审计接口暂不可用");
  await expect(page.locator("body")).not.toContainText(/P\d{3}/);
  expect(runtimeErrors).toEqual([]);
});

test("API mode never falls back to fixture evidence after a trace failure", async ({ page }) => {
  await installApiRoutes(page, { events: [], traceStatus: 404 });
  await page.goto("/evidence/trace_api_001");

  await expect(page.getByRole("alert")).toContainText("请求失败 (404)");
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
  await expect(page).toHaveURL(/prov_node=node:25/);
  await expect(graph.locator(".prov-node--selected")).toContainText("证据节点 25");
});

test("API mode retries provenance independently after a canonical endpoint failure", async ({
  page,
}) => {
  await installApiRoutes(page, { provenanceFailuresBeforeSuccess: 1 });
  await page.goto("/evidence/trace_api_001");

  await expect(page.getByText("溯源关系接口暂不可用")).toBeVisible();
  await page.getByRole("button", { name: "重新加载溯源关系" }).click();

  await expect(page.locator(".provenance-flow")).toBeVisible();
  await expect(page.getByText("溯源关系接口暂不可用")).toHaveCount(0);
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
        approval_nonce: "nonce_expiring",
      },
    ],
  });
  await page.goto("/approvals");

  const denyButton = page.getByRole("button", { name: "拒绝并阻断" });
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

  const mainPanel = page.locator(".investigations-page__main");
  await mainPanel.evaluate((element) => {
    element.scrollTop = element.scrollHeight;
  });
  await expect.poll(() => mainPanel.evaluate((element) => element.scrollTop)).toBeGreaterThan(40);

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
  await expect.poll(() => mainPanel.evaluate((element) => element.scrollTop)).toBe(0);
});

test("API mode shows a session error instead of a blank dashboard", async ({ page }) => {
  await installApiRoutes(page, { authenticated: false });
  await page.goto("/overview");

  await expect(page.getByRole("alert")).toContainText("无法建立监督端会话");
  await expect(page.getByRole("alert")).toContainText("监督端会话已过期");
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
  await expect(page.locator(".metric-strip")).toContainText("审计事件");
  await expect(page.locator(".freshness--ready").first()).toBeVisible();

  const overviewPaths = [...requestedPaths];
  expect(overviewPaths).toContain("/api/v1/audit/events");
  expect(overviewPaths).toContain("/api/v1/metrics/eval");
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
  expect(requestedPaths).toContain("/api/v1/metrics/eval");
});
