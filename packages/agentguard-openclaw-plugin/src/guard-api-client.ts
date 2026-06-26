import type {
  AgentGuardPluginConfig,
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
  requestTimeoutMs: 5000,
  approvalPollIntervalMs: 1000,
  approvalTimeoutMs: 120000,
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

  async waitForApproval(approvalId: string): Promise<ApprovalWaitResponse> {
    const startedAt = Date.now();
    while (Date.now() - startedAt < this.config.approvalTimeoutMs) {
      const response = await this.request(`/v1/approvals/${encodeURIComponent(approvalId)}/wait`, {
        method: "GET",
      });
      const parsed = (await response.json()) as ApprovalWaitResponse;
      if (parsed.status !== "pending") {
        return parsed;
      }
      await delay(this.config.approvalPollIntervalMs);
    }
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
        throw new GuardApiError(`Guard API request failed with status ${response.status}`);
      }
      return response;
    } catch (error) {
      if (error instanceof GuardApiError) {
        throw error;
      }
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
    requestTimeoutMs: positiveInteger(input?.requestTimeoutMs, DEFAULT_CONFIG.requestTimeoutMs),
    approvalPollIntervalMs: positiveInteger(
      input?.approvalPollIntervalMs,
      DEFAULT_CONFIG.approvalPollIntervalMs,
    ),
    approvalTimeoutMs: positiveInteger(input?.approvalTimeoutMs, DEFAULT_CONFIG.approvalTimeoutMs),
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
    return { block: true, blockReason: safeDecisionMessage(response) };
  }
  const approval = await waiter.waitForApproval(response.approval.approval_id);
  return approval.status === "resolved" && approval.decision === "allow_once"
    ? undefined
    : { block: true, blockReason: safeDecisionMessage(response) };
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
    return { cancel: true, cancelReason: safeDecisionMessage(response) };
  }
  const approval = await waiter.waitForApproval(response.approval.approval_id);
  return approval.status === "resolved" && approval.decision === "allow_once"
    ? undefined
    : { cancel: true, cancelReason: safeDecisionMessage(response) };
}

export function failClosedToolResult(): ToolHookResult {
  return { block: true, blockReason: "AgentGuard is unavailable; blocked by fail-closed policy." };
}

export function failClosedMessageResult(): MessageHookResult {
  return { cancel: true, cancelReason: "AgentGuard is unavailable; cancelled by fail-closed policy." };
}

function safeDecisionMessage(response: GuardEvaluationResponse): string {
  return response.decision.safe_message || response.decision.reason || "Blocked by AgentGuard policy.";
}

function nonEmptyString(value: unknown, fallback: string): string {
  return typeof value === "string" && value.trim() ? value.trim() : fallback;
}

function positiveInteger(value: unknown, fallback: number): number {
  return typeof value === "number" && Number.isInteger(value) && value > 0 ? value : fallback;
}

function trimTrailingSlash(value: string): string {
  return value.replace(/\/+$/, "");
}

function delay(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}
