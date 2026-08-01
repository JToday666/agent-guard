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
  reason: "发送目标不在当前任务允许范围内，需要人工确认",
  latency_ms: 4,
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
  options: { authenticated?: boolean; failConfigAudit?: boolean } = {},
) {
  const authenticated = options.authenticated ?? true;

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

    if (path === "/audit/events") return route.fulfill({ json: [eventDto] });
    if (path === "/metrics/eval") return route.fulfill({ json: metricsDto });
    if (path === "/approvals/pending") return route.fulfill({ json: [] });
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
      return route.fulfill({
        json: {
          trace_id: "trace_api_001",
          audit_events: [eventDto],
          approvals: [],
          metrics: metricsDto,
        },
      });
    }
    if (path === "/traces/trace_api_001/provenance") {
      return route.fulfill({
        json: {
          trace_id: "trace_api_001",
          nodes: [
            {
              node_id: "trace_api_001:task",
              trace_id: "trace_api_001",
              kind: "audit",
              ref_id: "trace_api_001",
              label: "整理客户反馈摘要",
              timestamp: "2026-06-28T08:00:00Z",
              metadata: { lane: "任务与资源", source: "api" },
            },
            {
              node_id: "trace_api_001:event",
              trace_id: "trace_api_001",
              kind: "event",
              ref_id: "audit_api_001",
              label: "send_email / ex***@example.invalid",
              timestamp: "2026-06-28T08:00:00Z",
              metadata: {
                lane: "Agent 行为",
                decision: "ask",
                riskScore: "64",
                source: "api",
              },
            },
          ],
          edges: [
            {
              edge_id: "edge_api_001",
              trace_id: "trace_api_001",
              source_node_id: "trace_api_001:task",
              target_node_id: "trace_api_001:event",
              relation: "触发行为",
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

  await page.goto("/evidence/trace_api_001");
  await expect(page.locator(".trace-conclusion")).toContainText("等待人工审批");
  await expect(page.locator(".trace-conclusion")).not.toContainText(/P\d{3}/);

  await page.goto("/system");
  await expect(page.getByRole("heading", { name: "系统状态" })).toBeVisible();
  await expect(page.locator(".system-page")).toContainText("配置审计接口暂不可用");
  await expect(page.locator("body")).not.toContainText(/P\d{3}/);
  expect(runtimeErrors).toEqual([]);
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
  await page.goto("/evaluation");
  await expect(page.getByRole("heading", { name: "安全评测" })).toBeVisible();
  await expect.poll(() => requestedPaths.includes("/api/v1/evaluations/latest")).toBe(true);

  expect(requestedPaths).toContain("/api/v1/audit/events");
  expect(requestedPaths).toContain("/api/v1/metrics/eval");
  expect(requestedPaths).not.toContain("/api/v1/policies/current");

  requestedPaths.length = 0;
  await page.goto("/system");
  await expect(page.getByRole("heading", { name: "系统状态" })).toBeVisible();
  await expect.poll(() => requestedPaths.includes("/api/v1/policies/current")).toBe(true);

  expect(requestedPaths).toContain("/api/v1/policies/history");
  expect(requestedPaths).toContain("/api/v1/config-audit/findings");
  expect(requestedPaths).toContain("/api/v1/adapters/openclaw/status");
  expect(requestedPaths).not.toContain("/api/v1/audit/events");
});
