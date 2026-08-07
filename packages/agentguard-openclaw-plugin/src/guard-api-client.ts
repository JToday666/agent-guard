import {
  OPENCLAW_REQUIRED_HOOK_COUNT,
  OPENCLAW_REQUIRED_HOOKS,
} from "../hook-contract.mjs";
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
import type { OutcomeApprovalEvidence } from "./mapping/audit-outcomes.js";

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
  failClosedStages: ["before_tool_call", "message_sending", "before_install", "before_prompt_build", "llm_input"],
  redaction: { enabled: true, previewLimit: 2000 },
  heartbeatIntervalMs: 60000,
};

export class GuardApiError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "GuardApiError";
  }
}

/**
 * HTTP 409：同 audit_id 已绑定不同内容（§12.3 AUDIT_ID_CONFLICT）。
 * 与 5xx / 网络错误区分开：回执对 409 只记诊断，不重试也不 fail-closed。
 */
export class GuardApiConflictError extends GuardApiError {
  constructor(message: string) {
    super(message);
    this.name = "GuardApiConflictError";
  }
}

/** §12.3 审计提交响应：首次写入与幂等重放用 created/idempotent_replay 区分。 */
export type AuditSubmitResponse = {
  ok: boolean;
  audit_id: string;
  created?: boolean;
  idempotent_replay?: boolean;
};

/** decisionToToolResult / decisionToMessageResult 回传给调用方的运行时结果通知。 */
export type DecisionOutcome =
  | { kind: "pre_execution_deny"; approval: OutcomeApprovalEvidence | null }
  | { kind: "approval_release"; approval: OutcomeApprovalEvidence };

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

  async submitRuntimeObservation(event: AuditEvent): Promise<AuditSubmitResponse> {
    if (!this.config.adapterToken) {
      throw new GuardApiError("AgentGuard adapter token is not configured");
    }

    const response = await this.request("/v1/audit/events", {
      method: "POST",
      body: JSON.stringify(event),
    });
    return (await response.json()) as AuditSubmitResponse;
  }

  /**
   * 提交 runtime_outcome 回执（复用 POST /v1/audit/events，不新增端点）。
   * 回执是 fire-and-forget：409 只记诊断（不重试、不 fail-closed），
   * 其余错误继续抛给调用方的 .catch(logDiagnostic) 处理。
   */
  async submitRuntimeOutcome(event: AuditEvent): Promise<AuditSubmitResponse> {
    if (!this.config.adapterToken) {
      throw new GuardApiError("AgentGuard adapter token is not configured");
    }

    try {
      const response = await this.request("/v1/audit/events", {
        method: "POST",
        body: JSON.stringify(event),
      });
      return (await response.json()) as AuditSubmitResponse;
    } catch (error) {
      if (error instanceof GuardApiConflictError) {
        logDiagnostic(
          this.config,
          "runtime outcome receipt rejected with 409 conflict",
          { audit_id: event.audit_id ?? null },
        );
        return {
          ok: false,
          audit_id: event.audit_id ?? "",
          created: false,
          idempotent_replay: false,
        };
      }
      throw error;
    }
  }

  async submitHeartbeat(input: AdapterHeartbeatInput): Promise<Record<string, unknown>> {
    if (!this.config.adapterToken) {
      throw new GuardApiError("AgentGuard adapter token is not configured");
    }
    const hooks = input.hooks.length > 0 ? input.hooks : [...OPENCLAW_REQUIRED_HOOKS];

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
        hooks,
        hook_count: hooks.length,
        expected_hook_count: OPENCLAW_REQUIRED_HOOK_COUNT,
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
        if (response.status === 409) {
          throw new GuardApiConflictError(
            "Guard API request failed with status 409",
          );
        }
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
    failClosedStages: stringArray(input?.failClosedStages, DEFAULT_CONFIG.failClosedStages),
    redaction: redactionConfig(input?.redaction, DEFAULT_CONFIG.redaction),
    heartbeatIntervalMs: positiveInteger(input?.heartbeatIntervalMs, DEFAULT_CONFIG.heartbeatIntervalMs),
  };
}

export async function decisionToToolResult(
  response: GuardEvaluationResponse,
  waiter: ApprovalWaiter,
  onOutcome?: (outcome: DecisionOutcome) => void,
): Promise<ToolHookResult | undefined> {
  if (response.decision.decision === "allow") {
    return undefined;
  }
  if (response.decision.decision === "deny") {
    onOutcome?.({ kind: "pre_execution_deny", approval: null });
    return { block: true, blockReason: safeDecisionMessage(response) };
  }
  if (response.approval === null || waiter.waitForApproval === undefined) {
    onOutcome?.({ kind: "pre_execution_deny", approval: null });
    return { block: true, blockReason: safeDecisionMessage(response, response.approval?.approval_id) };
  }
  const approval = await waiter.waitForApproval(response.approval.approval_id);
  if (approval.status === "resolved" && approval.decision === "allow_once") {
    onOutcome?.({
      kind: "approval_release",
      approval: approvalEvidenceFromWait(response.approval.approval_id, approval),
    });
    return undefined;
  }
  onOutcome?.({
    kind: "pre_execution_deny",
    approval: approvalEvidenceFromWait(response.approval.approval_id, approval),
  });
  return { block: true, blockReason: safeDecisionMessage(response, response.approval.approval_id) };
}

export async function decisionToMessageResult(
  response: GuardEvaluationResponse,
  waiter: ApprovalWaiter,
  onOutcome?: (outcome: DecisionOutcome) => void,
): Promise<MessageHookResult | undefined> {
  if (response.decision.decision === "allow") {
    return undefined;
  }
  if (response.decision.decision === "deny") {
    onOutcome?.({ kind: "pre_execution_deny", approval: null });
    return { cancel: true, cancelReason: safeDecisionMessage(response) };
  }
  if (response.approval === null || waiter.waitForApproval === undefined) {
    onOutcome?.({ kind: "pre_execution_deny", approval: null });
    return { cancel: true, cancelReason: safeDecisionMessage(response, response.approval?.approval_id) };
  }
  const approval = await waiter.waitForApproval(response.approval.approval_id);
  if (approval.status === "resolved" && approval.decision === "allow_once") {
    onOutcome?.({
      kind: "approval_release",
      approval: approvalEvidenceFromWait(response.approval.approval_id, approval),
    });
    return undefined;
  }
  onOutcome?.({
    kind: "pre_execution_deny",
    approval: approvalEvidenceFromWait(response.approval.approval_id, approval),
  });
  return { cancel: true, cancelReason: safeDecisionMessage(response, response.approval.approval_id) };
}

/** 把审批等待结果映射为 §9.8 evidence 稳定状态（timeout→expired）。 */
function approvalEvidenceFromWait(
  approvalId: string,
  wait: ApprovalWaitResponse,
): OutcomeApprovalEvidence {
  const resolvedAt = new Date().toISOString();
  if (wait.decision === "allow_once") {
    return { approvalId, status: "allowed", decision: "allow_once", resolvedAt };
  }
  if (wait.status === "timeout" || wait.status === "expired") {
    return { approvalId, status: "expired", decision: null, resolvedAt };
  }
  return {
    approvalId,
    status: "denied",
    decision: wait.decision === "deny" ? "deny" : null,
    resolvedAt,
  };
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
