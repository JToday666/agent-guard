import {
  OPENCLAW_FAIL_CLOSED_HOOKS,
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
  approvalTimeoutMs: 25000,
  diagnosticLogging: false,
  agentId: "main",
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

  async evaluate(
    event: GuardEvent | Record<string, unknown>,
  ): Promise<GuardEvaluationResponse> {
    if (!this.config.adapterToken) {
      throw new GuardApiError("AgentGuard adapter token is not configured");
    }

    const response = await this.request("/v1/guard/evaluate", {
      method: "POST",
      body: JSON.stringify(event),
    });
    return (await response.json()) as GuardEvaluationResponse;
  }

  async evaluateConfigAudit(
    event: ConfigAuditEvent,
  ): Promise<ConfigAuditResult> {
    if (!this.config.adapterToken) {
      throw new GuardApiError("AgentGuard adapter token is not configured");
    }

    const response = await this.request("/v1/config-audit/evaluate", {
      method: "POST",
      body: JSON.stringify(event),
    });
    return (await response.json()) as ConfigAuditResult;
  }

  async submitRuntimeObservation(
    event: AuditEvent,
  ): Promise<AuditSubmitResponse> {
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

  async submitHeartbeat(
    input: AdapterHeartbeatInput,
  ): Promise<Record<string, unknown>> {
    if (!this.config.adapterToken) {
      throw new GuardApiError("AgentGuard adapter token is not configured");
    }
    const hooks =
      input.hooks.length > 0 ? input.hooks : [...OPENCLAW_REQUIRED_HOOKS];

    const response = await this.request("/v1/adapters/openclaw/heartbeat", {
      method: "POST",
      body: JSON.stringify({
        status: "loaded",
        loaded: true,
        runtime_id: "openclaw",
        agent_id: this.config.agentId,
        plugin_version: input.pluginVersion,
        runtime_version: input.runtimeVersion ?? null,
        source: "openclaw-plugin",
        capabilities: input.capabilities,
        hooks,
        hook_count: hooks.length,
        expected_hook_count: OPENCLAW_REQUIRED_HOOK_COUNT,
        fail_closed_stages: [...OPENCLAW_FAIL_CLOSED_HOOKS],
        enforcement_mode: this.config.enforcementMode,
      }),
    });
    return (await response.json()) as Record<string, unknown>;
  }

  async waitForApproval(approvalId: string): Promise<ApprovalWaitResponse> {
    const deadline = Date.now() + this.config.approvalTimeoutMs;
    while (Date.now() < deadline) {
      const remainingMs = deadline - Date.now();
      let response: Response;
      try {
        response = await this.request(
          `/v1/approvals/${encodeURIComponent(approvalId)}/wait`,
          { method: "GET" },
          Math.min(this.config.requestTimeoutMs, remainingMs),
        );
      } catch (error) {
        if (Date.now() >= deadline) {
          return { status: "timeout", decision: "deny" };
        }
        throw error;
      }
      const parsed = (await response.json()) as ApprovalWaitResponse;
      if (parsed.status !== "pending") {
        return parsed;
      }
      const delayMs = Math.min(
        this.config.approvalPollIntervalMs,
        Math.max(0, deadline - Date.now()),
      );
      if (delayMs > 0) {
        await delay(delayMs);
      }
    }
    return { status: "timeout", decision: "deny" };
  }

  private async request(
    path: string,
    init: RequestInit,
    timeoutMs = this.config.requestTimeoutMs,
  ): Promise<Response> {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), timeoutMs);
    try {
      const response = await this.fetchImpl(
        `${trimTrailingSlash(this.config.guardApiBaseUrl)}${path}`,
        {
          ...init,
          signal: controller.signal,
          headers: {
            Accept: "application/json",
            Authorization: `Bearer ${this.config.adapterToken}`,
            "Content-Type": "application/json",
            ...(init.headers ?? {}),
          },
        },
      );
      if (!response.ok) {
        logDiagnostic(
          this.config,
          "Guard API request returned an error response",
          {
            path,
            status: response.status,
          },
        );
        if (response.status === 409) {
          throw new GuardApiConflictError(
            "Guard API request failed with status 409",
          );
        }
        throw new GuardApiError(
          `Guard API request failed with status ${response.status}`,
        );
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
): AgentGuardPluginConfig {
  const config: AgentGuardPluginConfig = {
    guardApiBaseUrl: nonEmptyString(
      input?.guardApiBaseUrl,
      DEFAULT_CONFIG.guardApiBaseUrl,
    ),
    adapterToken: nonEmptyString(
      input?.adapterToken,
      DEFAULT_CONFIG.adapterToken,
    ),
    enforcementMode: enforcementMode(
      input?.enforcementMode,
      DEFAULT_CONFIG.enforcementMode,
    ),
    requestTimeoutMs: positiveInteger(
      input?.requestTimeoutMs,
      DEFAULT_CONFIG.requestTimeoutMs,
    ),
    approvalPollIntervalMs: positiveInteger(
      input?.approvalPollIntervalMs,
      DEFAULT_CONFIG.approvalPollIntervalMs,
    ),
    approvalTimeoutMs: positiveInteger(
      input?.approvalTimeoutMs,
      DEFAULT_CONFIG.approvalTimeoutMs,
    ),
    diagnosticLogging: input?.diagnosticLogging === true,
    agentId: nonEmptyString(input?.agentId, DEFAULT_CONFIG.agentId),
  };
  if (!config.adapterToken) {
    throw new GuardApiError(
      "AgentGuard adapterToken must be configured through an OpenClaw SecretRef",
    );
  }
  return config;
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
    return {
      block: true,
      blockReason: safeDecisionMessage(
        response,
        response.approval?.approval_id,
      ),
    };
  }
  const approval = await waiter.waitForApproval(response.approval.approval_id);
  if (approval.status === "resolved" && approval.decision === "allow_once") {
    onOutcome?.({
      kind: "approval_release",
      approval: approvalEvidenceFromWait(
        response.approval.approval_id,
        approval,
      ),
    });
    return undefined;
  }
  onOutcome?.({
    kind: "pre_execution_deny",
    approval: approvalEvidenceFromWait(response.approval.approval_id, approval),
  });
  return {
    block: true,
    blockReason: safeDecisionMessage(response, response.approval.approval_id),
  };
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
    return {
      cancel: true,
      cancelReason: safeDecisionMessage(
        response,
        response.approval?.approval_id,
      ),
    };
  }
  const approval = await waiter.waitForApproval(response.approval.approval_id);
  if (approval.status === "resolved" && approval.decision === "allow_once") {
    onOutcome?.({
      kind: "approval_release",
      approval: approvalEvidenceFromWait(
        response.approval.approval_id,
        approval,
      ),
    });
    return undefined;
  }
  onOutcome?.({
    kind: "pre_execution_deny",
    approval: approvalEvidenceFromWait(response.approval.approval_id, approval),
  });
  return {
    cancel: true,
    cancelReason: safeDecisionMessage(response, response.approval.approval_id),
  };
}

/** 把审批等待结果映射为 §9.8 evidence 稳定状态（timeout→expired）。 */
function approvalEvidenceFromWait(
  approvalId: string,
  wait: ApprovalWaitResponse,
): OutcomeApprovalEvidence {
  const resolvedAt = new Date().toISOString();
  if (wait.decision === "allow_once") {
    return {
      approvalId,
      status: "allowed",
      decision: "allow_once",
      resolvedAt,
    };
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
  return {
    block: true,
    blockReason: "AgentGuard is unavailable; blocked by fail-closed policy.",
  };
}

export function failClosedMessageResult(): MessageHookResult {
  return {
    cancel: true,
    cancelReason: "AgentGuard is unavailable; cancelled by fail-closed policy.",
  };
}

function safeDecisionMessage(
  response: GuardEvaluationResponse,
  approvalId?: string,
): string {
  const message =
    response.decision.safe_message ||
    response.decision.reason ||
    "Blocked by AgentGuard policy.";
  return approvalId ? `${message} (approval_id=${approvalId})` : message;
}

function nonEmptyString(value: unknown, fallback: string): string {
  return typeof value === "string" && value.trim() ? value.trim() : fallback;
}

function positiveInteger(value: unknown, fallback: number): number {
  return typeof value === "number" && Number.isInteger(value) && value > 0
    ? value
    : fallback;
}

function enforcementMode(
  value: unknown,
  fallback: AgentGuardPluginConfig["enforcementMode"],
): AgentGuardPluginConfig["enforcementMode"] {
  return value === "enforce" || value === "observe" || value === "disabled"
    ? value
    : fallback;
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
  console.warn(
    "[AgentGuard OpenClaw]",
    message,
    JSON.stringify(sanitizeDiagnostic(details, config.adapterToken)),
  );
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
