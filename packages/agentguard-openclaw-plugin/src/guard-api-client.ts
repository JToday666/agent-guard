import type {
  AgentGuardPluginConfig,
  AdapterHeartbeatInput,
  AuditEvent,
  ApprovalWaitResponse,
  ConfigAuditEvent,
  ConfigAuditResult,
  GuardEvaluationResponse,
  GuardEvent,
  MessageHookResult,
  OpenClawPluginConfigInput,
  ToolHookResult,
} from "./types.js";

type FetchLike = typeof fetch;

type ClientParams = {
  config: AgentGuardPluginConfig;
  fetchImpl?: FetchLike;
};

type ApprovalWaiter = {
  waitForApproval?: (approvalId: string) => Promise<ApprovalWaitResponse>;
};

const DEFAULT_CONFIG: AgentGuardPluginConfig = {
  guardApiBaseUrl: "http://127.0.0.1:8088",
  adapterToken: "",
  enforcementMode: "enforce",
  requestTimeoutMs: 5000,
  approvalPollIntervalMs: 1000,
  approvalTimeoutMs: 120000,
  approvalWaitBudgetMs: 25000,
  diagnosticLogging: false,
  runtimeId: "openclaw",
  agentId: "main",
  enabledHooks: [
    "before_tool_call",
    "message_sending",
    "before_install",
    "before_prompt_build",
    "llm_input",
    "llm_output",
    "tool_result_persist",
    "message_received",
    "before_message_write",
    "before_agent_finalize",
    "gateway_start",
    "gateway_stop",
    "session_start",
    "session_end",
    "before_compaction",
    "after_compaction",
    "subagent_spawned",
    "subagent_ended",
    "model_call_started",
    "model_call_ended",
    "cron_changed",
    "resolve_exec_env",
  ],
  failClosedStages: ["before_tool_call", "message_sending", "before_install"],
  redaction: { enabled: true, previewLimit: 2000 },
  heartbeatIntervalMs: 60000,
};

export class GuardApiError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "GuardApiError";
  }
}

export class GuardApiClient {
  private readonly config: AgentGuardPluginConfig;
  private readonly fetchImpl: FetchLike;

  constructor(params: ClientParams) {
    this.config = params.config;
    this.fetchImpl = params.fetchImpl ?? fetch;
  }

  async evaluate(event: GuardEvent | Record<string, unknown>): Promise<GuardEvaluationResponse> {
    if (!this.config.adapterToken) {
      throw new GuardApiError("AgentGuard adapter token is not configured");
    }

    const response = await this.request("/v1/guard/evaluate", {
      method: "POST",
      body: JSON.stringify(event),
    });
    return (await response.json()) as GuardEvaluationResponse;
  }

  async evaluateConfigAudit(event: ConfigAuditEvent): Promise<ConfigAuditResult> {
    if (!this.config.adapterToken) {
      throw new GuardApiError("AgentGuard adapter token is not configured");
    }

    const response = await this.request("/v1/config-audit/evaluate", {
      method: "POST",
      body: JSON.stringify(event),
    });
    return (await response.json()) as ConfigAuditResult;
  }

  async submitRuntimeObservation(event: AuditEvent): Promise<{ ok: boolean; audit_id: string }> {
    if (!this.config.adapterToken) {
      throw new GuardApiError("AgentGuard adapter token is not configured");
    }

    const response = await this.request("/v1/audit/events", {
      method: "POST",
      body: JSON.stringify(event),
    });
    return (await response.json()) as { ok: boolean; audit_id: string };
  }

  async submitHeartbeat(input: AdapterHeartbeatInput): Promise<Record<string, unknown>> {
    if (!this.config.adapterToken) {
      throw new GuardApiError("AgentGuard adapter token is not configured");
    }

    const response = await this.request("/v1/adapters/openclaw/heartbeat", {
      method: "POST",
      body: JSON.stringify({
        status: "loaded",
        loaded: true,
        runtime: "openclaw",
        runtime_id: this.config.runtimeId,
        agent_id: this.config.agentId,
        plugin_version: input.pluginVersion,
        runtime_version: input.runtimeVersion ?? null,
        source: "openclaw-plugin",
        capabilities: input.capabilities,
        hooks: input.hooks.length > 0 ? input.hooks : this.config.enabledHooks,
        hook_count: input.hooks.length,
        expected_hook_count: this.config.enabledHooks.length,
        fail_closed_stages: this.config.failClosedStages,
        enforcement_mode: this.config.enforcementMode,
      }),
    });
    return (await response.json()) as Record<string, unknown>;
  }

  async waitForApproval(approvalId: string, timeoutBudgetMs = this.config.approvalTimeoutMs): Promise<ApprovalWaitResponse> {
    const startedAt = Date.now();
    const timeoutMs = Math.min(this.config.approvalTimeoutMs, timeoutBudgetMs);
    do {
      const response = await this.request(`/v1/approvals/${encodeURIComponent(approvalId)}/wait`, {
        method: "GET",
      });
      const parsed = (await response.json()) as ApprovalWaitResponse;
      if (parsed.status !== "pending") {
        return parsed;
      }
      await delay(this.config.approvalPollIntervalMs);
    } while (Date.now() - startedAt < timeoutMs);
    return { status: "timeout", decision: "deny" };
  }

  private async request(path: string, init: RequestInit): Promise<Response> {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), this.config.requestTimeoutMs);
    try {
      const response = await this.fetchImpl(`${trimTrailingSlash(this.config.guardApiBaseUrl)}${path}`, {
        ...init,
        signal: controller.signal,
        headers: {
          "Accept": "application/json",
          "Authorization": `Bearer ${this.config.adapterToken}`,
          "Content-Type": "application/json",
          ...(init.headers ?? {}),
        },
      });
      if (!response.ok) {
        logDiagnostic(this.config, "Guard API request returned an error response", {
          path,
          status: response.status,
        });
        throw new GuardApiError(`Guard API request failed with status ${response.status}`);
      }
      return response;
    } catch (error) {
      if (error instanceof GuardApiError) {
        throw error;
      }
      logDiagnostic(this.config, "Guard API request failed", {
        path,
        error: error instanceof Error ? error.message : String(error),
      });
      throw new GuardApiError("Guard API request failed");
    } finally {
      clearTimeout(timeout);
    }
  }
}

export function buildPluginConfig(
  input: OpenClawPluginConfigInput,
  env: Record<string, string | undefined> = process.env,
): AgentGuardPluginConfig {
  return {
    guardApiBaseUrl: nonEmptyString(input?.guardApiBaseUrl, DEFAULT_CONFIG.guardApiBaseUrl),
    adapterToken: nonEmptyString(input?.adapterToken, env.AGENTGUARD_ADAPTER_TOKEN ?? DEFAULT_CONFIG.adapterToken),
    enforcementMode: enforcementMode(input?.enforcementMode, DEFAULT_CONFIG.enforcementMode),
    requestTimeoutMs: positiveInteger(input?.requestTimeoutMs, DEFAULT_CONFIG.requestTimeoutMs),
    approvalPollIntervalMs: positiveInteger(
      input?.approvalPollIntervalMs,
      DEFAULT_CONFIG.approvalPollIntervalMs,
    ),
    approvalTimeoutMs: positiveInteger(input?.approvalTimeoutMs, DEFAULT_CONFIG.approvalTimeoutMs),
    approvalWaitBudgetMs: positiveInteger(input?.approvalWaitBudgetMs, DEFAULT_CONFIG.approvalWaitBudgetMs),
    diagnosticLogging: input?.diagnosticLogging === true,
    runtimeId: nonEmptyString(input?.runtimeId, DEFAULT_CONFIG.runtimeId),
    agentId: nonEmptyString(input?.agentId, DEFAULT_CONFIG.agentId),
    enabledHooks: stringArray(input?.enabledHooks, DEFAULT_CONFIG.enabledHooks),
    failClosedStages: stringArray(input?.failClosedStages, DEFAULT_CONFIG.failClosedStages),
    redaction: redactionConfig(input?.redaction, DEFAULT_CONFIG.redaction),
    heartbeatIntervalMs: positiveInteger(input?.heartbeatIntervalMs, DEFAULT_CONFIG.heartbeatIntervalMs),
  };
}

export async function decisionToToolResult(
  response: GuardEvaluationResponse,
  waiter: ApprovalWaiter,
): Promise<ToolHookResult | undefined> {
  if (response.decision.decision === "allow") {
    return undefined;
  }
  if (response.decision.decision === "deny") {
    return { block: true, blockReason: safeDecisionMessage(response) };
  }
  if (response.approval === null || waiter.waitForApproval === undefined) {
    return { block: true, blockReason: safeDecisionMessage(response, response.approval?.approval_id) };
  }
  const approval = await waiter.waitForApproval(response.approval.approval_id);
  return approval.status === "resolved" && approval.decision === "allow_once"
    ? undefined
    : { block: true, blockReason: safeDecisionMessage(response, response.approval.approval_id) };
}

export async function decisionToMessageResult(
  response: GuardEvaluationResponse,
  waiter: ApprovalWaiter,
): Promise<MessageHookResult | undefined> {
  if (response.decision.decision === "allow") {
    return undefined;
  }
  if (response.decision.decision === "deny") {
    return { cancel: true, cancelReason: safeDecisionMessage(response) };
  }
  if (response.approval === null || waiter.waitForApproval === undefined) {
    return { cancel: true, cancelReason: safeDecisionMessage(response, response.approval?.approval_id) };
  }
  const approval = await waiter.waitForApproval(response.approval.approval_id);
  return approval.status === "resolved" && approval.decision === "allow_once"
    ? undefined
    : { cancel: true, cancelReason: safeDecisionMessage(response, response.approval.approval_id) };
}

export function failClosedToolResult(): ToolHookResult {
  return { block: true, blockReason: "AgentGuard is unavailable; blocked by fail-closed policy." };
}

export function failClosedMessageResult(): MessageHookResult {
  return { cancel: true, cancelReason: "AgentGuard is unavailable; cancelled by fail-closed policy." };
}

function safeDecisionMessage(response: GuardEvaluationResponse, approvalId?: string): string {
  const message = response.decision.safe_message || response.decision.reason || "Blocked by AgentGuard policy.";
  return approvalId ? `${message} (approval_id=${approvalId})` : message;
}

function nonEmptyString(value: unknown, fallback: string): string {
  return typeof value === "string" && value.trim() ? value.trim() : fallback;
}

function positiveInteger(value: unknown, fallback: number): number {
  return typeof value === "number" && Number.isInteger(value) && value > 0 ? value : fallback;
}

function stringArray(value: unknown, fallback: string[]): string[] {
  if (!Array.isArray(value)) {
    return [...fallback];
  }
  const items = value.filter((item): item is string => typeof item === "string" && item.length > 0);
  return items.length > 0 ? [...items] : [...fallback];
}

function enforcementMode(
  value: unknown,
  fallback: AgentGuardPluginConfig["enforcementMode"],
): AgentGuardPluginConfig["enforcementMode"] {
  return value === "enforce" || value === "observe" || value === "disabled" ? value : fallback;
}

function redactionConfig(value: unknown, fallback: AgentGuardPluginConfig["redaction"]): AgentGuardPluginConfig["redaction"] {
  if (typeof value !== "object" || value === null) {
    return { ...fallback };
  }
  const record = value as Record<string, unknown>;
  return {
    enabled: record.enabled !== false,
    previewLimit: positiveInteger(record.previewLimit, fallback.previewLimit),
  };
}

function trimTrailingSlash(value: string): string {
  return value.replace(/\/+$/, "");
}

function delay(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

export function logDiagnostic(
  config: AgentGuardPluginConfig,
  message: string,
  details: Record<string, unknown> = {},
): void {
  if (!config.diagnosticLogging) {
    return;
  }
  console.warn("[AgentGuard OpenClaw]", message, JSON.stringify(sanitizeDiagnostic(details, config.adapterToken)));
}

function sanitizeDiagnostic(value: unknown, adapterToken: string): unknown {
  if (typeof value === "string") {
    return adapterToken ? value.replaceAll(adapterToken, "[redacted]") : value;
  }
  if (Array.isArray(value)) {
    return value.map((item) => sanitizeDiagnostic(item, adapterToken));
  }
  if (typeof value !== "object" || value === null) {
    return value;
  }
  return Object.fromEntries(
    Object.entries(value).map(([key, nestedValue]) => [
      key,
      /token|secret|authorization|credential/i.test(key)
        ? "[redacted]"
        : sanitizeDiagnostic(nestedValue, adapterToken),
    ]),
  );
}
