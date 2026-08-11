import { isIP } from "node:net";

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
  RuntimeOutcomeReceipt,
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

const CONTROL_CHARACTER = /[\u0000-\u001f\u007f]/u;
const ENCODED_LINE_BREAK = /%0[ad]/iu;

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

export function validateGuardApiBaseUrl(value: unknown): string {
  if (typeof value !== "string" || value === "" || value.trim() !== value) {
    throw new GuardApiError("Guard API URL must be a non-empty absolute URL");
  }
  if (
    CONTROL_CHARACTER.test(value) ||
    ENCODED_LINE_BREAK.test(value) ||
    value.includes("\\")
  ) {
    throw new GuardApiError("Guard API URL contains forbidden characters");
  }
  if (value.includes("?") || value.includes("#")) {
    throw new GuardApiError("Guard API URL cannot contain a query or fragment");
  }

  let parsed: URL;
  try {
    parsed = new URL(value);
  } catch {
    throw new GuardApiError("Guard API URL is invalid");
  }
  if (!["http:", "https:"].includes(parsed.protocol)) {
    throw new GuardApiError("Guard API URL must use http or https");
  }
  if (parsed.username || parsed.password) {
    throw new GuardApiError("Guard API URL cannot contain user information");
  }

  const rawHost = rawHostname(value);
  const hostname = parsed.hostname.replace(/^\[|\]$/gu, "").toLowerCase();
  if (
    !rawHost ||
    hostname.includes("%") ||
    !hasCanonicalIpSpelling(rawHost, hostname)
  ) {
    throw new GuardApiError("Guard API URL must contain a valid host and port");
  }
  if (parsed.protocol === "http:" && !isExplicitLoopback(rawHost, hostname)) {
    throw new GuardApiError(
      "Guard API HTTP is allowed only for explicit loopback addresses",
    );
  }

  const normalizedPath = parsed.pathname.replace(/\/+$/u, "");
  return `${parsed.protocol}//${parsed.host}${normalizedPath}`;
}

function rawHostname(value: string): string {
  const authority = /^[a-z][a-z0-9+.-]*:\/\/([^/?#]*)/iu.exec(value)?.[1];
  if (!authority || authority.includes("@")) {
    return "";
  }
  if (authority.startsWith("[")) {
    const end = authority.indexOf("]");
    return end >= 0 ? authority.slice(0, end + 1) : "";
  }
  return authority.split(":", 1)[0] ?? "";
}

function hasCanonicalIpSpelling(
  rawHost: string,
  parsedHostname: string,
): boolean {
  const unwrapped = rawHost.replace(/^\[|\]$/gu, "");
  const parsedKind = isIP(parsedHostname);
  if (parsedKind === 4) {
    return (
      isIP(unwrapped) === 4 &&
      unwrapped
        .split(".")
        .every((part) => String(Number.parseInt(part, 10)) === part)
    );
  }
  if (parsedKind === 6) {
    return rawHost.startsWith("[") && isIP(unwrapped) === 6;
  }
  return !/^(?:0x[0-9a-f]+|[0-9.]+)$/iu.test(unwrapped);
}

function isExplicitLoopback(rawHost: string, parsedHostname: string): boolean {
  if (parsedHostname === "localhost") {
    return rawHost.toLowerCase() === "localhost";
  }
  if (isIP(parsedHostname) === 4) {
    return (
      parsedHostname.startsWith("127.") &&
      hasCanonicalIpSpelling(rawHost, parsedHostname)
    );
  }
  return (
    parsedHostname === "::1" && hasCanonicalIpSpelling(rawHost, parsedHostname)
  );
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

/** Non-retryable producer/authorization failures for durable receipt delivery. */
export class GuardApiPermanentError extends GuardApiError {
  readonly status: number;

  constructor(status: number) {
    super(`Guard API request failed permanently with status ${status}`);
    this.name = "GuardApiPermanentError";
    this.status = status;
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
    this.config = {
      ...params.config,
      guardApiBaseUrl: validateGuardApiBaseUrl(params.config.guardApiBaseUrl),
    };
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
   * 回执是 fire-and-forget：永久 4xx 只记诊断，网络、429 与 5xx
   * 交给持久化投递队列重试，均不改变已经完成的运行时处置。
   */
  async submitRuntimeOutcome(
    event: RuntimeOutcomeReceipt,
  ): Promise<AuditSubmitResponse> {
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
      if (
        error instanceof GuardApiConflictError ||
        error instanceof GuardApiPermanentError
      ) {
        logDiagnostic(
          this.config,
          "runtime outcome receipt was permanently rejected",
          {
            audit_id: event.audit_id ?? null,
            status:
              error instanceof GuardApiPermanentError ? error.status : 409,
          },
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
          redirect: "error",
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
        if (
          response.status >= 400 &&
          response.status < 500 &&
          response.status !== 408 &&
          response.status !== 429
        ) {
          throw new GuardApiPermanentError(response.status);
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
    guardApiBaseUrl: validateGuardApiBaseUrl(
      nonEmptyString(input?.guardApiBaseUrl, DEFAULT_CONFIG.guardApiBaseUrl),
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
