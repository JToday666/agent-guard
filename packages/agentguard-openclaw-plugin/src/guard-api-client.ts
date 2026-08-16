import { isIP } from "node:net";

import {
  OPENCLAW_REQUIRED_HOOK_COUNT,
  OPENCLAW_REQUIRED_HOOKS,
} from "../hook-contract.mjs";
import { OPENCLAW_EFFECTIVE_FAIL_CLOSED_HOOKS } from "./runtime/host-capabilities.js";
import type {
  AgentGuardPluginConfig,
  AdapterHeartbeatInput,
  AuditEvent,
  ApprovalWaitResponse,
  ConfigAuditEvent,
  ConfigAuditResult,
  EnforcementBinding,
  ExecutionLeaseReference,
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
const AUTHORIZATION_FINGERPRINT = /^hmac-sha256:[0-9a-f]{64}$/u;
const SECRET_FINGERPRINT = /hmac-sha256:[0-9a-f]{64}/gu;
const LEASE_TOKEN = /lease-v1:[0-9a-f]{64}/gu;
const STRICT_LEASE_TOKEN = /^lease-v1:[0-9a-f]{64}$/u;
const LEASE_IDENTIFIER = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,159}$/u;
const RUNTIME_BINDING_IDENTIFIER = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,255}$/u;
const RFC3339_TIMESTAMP =
  /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,9}))?(Z|([+-])(\d{2}):(\d{2}))$/u;
const MAX_LEASE_CONSUME_ATTEMPTS = 5;
const MAX_GUARD_API_RESPONSE_BYTES = 1024 * 1024;

type GuardApiJsonResponse = {
  ok: boolean;
  status: number;
  body: unknown;
};

const DEFAULT_CONFIG: AgentGuardPluginConfig = {
  guardApiBaseUrl: "http://127.0.0.1:8088",
  adapterToken: "",
  enforcementMode: "enforce",
  requestTimeoutMs: 5000,
  approvalPollIntervalMs: 1000,
  approvalTimeoutMs: 25000,
  strongApprovalBindingEnabled: false,
  runtimeBindingId: "",
  diagnosticLogging: false,
  agentId: "main",
};

export class GuardApiError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "GuardApiError";
  }
}

export type GuardApiResponseFailure =
  | "timed_out"
  | "too_large"
  | "malformed";

/** Stable, body-free classification for bounded response handling failures. */
export class GuardApiResponseError extends GuardApiError {
  readonly failure: GuardApiResponseFailure;

  constructor(failure: GuardApiResponseFailure) {
    super(`Guard API response failed: ${failure}`);
    this.name = "GuardApiResponseError";
    this.failure = failure;
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

export type ExecutionLeaseFailure =
  | "identity_denied"
  | "approval_not_found"
  | "approval_not_consumable"
  | "consumption_conflict"
  | "approval_expired"
  | "lease_expired"
  | "lease_revoked"
  | "lease_unavailable"
  | "timed_out"
  | "invalid_response"
  | "rejected";

/** Stable, bounded consume failure. It never retains a response body. */
export class ExecutionLeaseConsumeError extends GuardApiError {
  readonly failure: ExecutionLeaseFailure;
  readonly status: number | null;
  readonly code: string | null;

  constructor(
    failure: ExecutionLeaseFailure,
    options: { status?: number; code?: string } = {},
  ) {
    super(`Execution lease consume failed: ${failure}`);
    this.name = "ExecutionLeaseConsumeError";
    this.failure = failure;
    this.status = options.status ?? null;
    this.code = options.code ?? null;
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
    return parseEvaluationResponse(response.body);
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
    return response.body as ConfigAuditResult;
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
    return response.body as AuditSubmitResponse;
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
      return response.body as AuditSubmitResponse;
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
        fail_closed_stages: [...OPENCLAW_EFFECTIVE_FAIL_CLOSED_HOOKS],
        enforcement_mode: this.config.enforcementMode,
      }),
    });
    return response.body as Record<string, unknown>;
  }

  approvalDeadlineMs(): number {
    return Date.now() + this.config.approvalTimeoutMs;
  }

  async waitForApproval(
    approvalId: string,
    deadlineMs = this.approvalDeadlineMs(),
  ): Promise<ApprovalWaitResponse> {
    const deadline = deadlineMs;
    while (Date.now() < deadline) {
      const remainingMs = deadline - Date.now();
      let response: GuardApiJsonResponse;
      try {
        response = await this.request(
          `/v1/approvals/${encodeURIComponent(approvalId)}/wait`,
          { method: "GET" },
          Math.min(this.config.requestTimeoutMs, remainingMs),
        );
      } catch (error) {
        if (Date.now() >= deadline) {
          return timeoutApproval();
        }
        if (
          error instanceof GuardApiPermanentError ||
          error instanceof GuardApiConflictError
        ) {
          throw error;
        }
        if (
          error instanceof GuardApiResponseError &&
          error.failure !== "timed_out"
        ) {
          throw error;
        }
        await delayWithinDeadline(
          this.config.approvalPollIntervalMs,
          deadline,
        );
        continue;
      }
      const parsed = parseApprovalWaitResponse(response.body);
      if (parsed.status !== "pending") {
        return parsed;
      }
      await delayWithinDeadline(this.config.approvalPollIntervalMs, deadline);
    }
    return timeoutApproval();
  }

  /**
   * Consume a strong approval binding using one immutable request body.
   * The plaintext lease token is validated in this stack frame and discarded;
   * callers receive only non-secret correlation IDs.
   */
  async consumeExecutionLease(
    approvalId: string,
    binding: EnforcementBinding,
    deadlineMs: number,
  ): Promise<ExecutionLeaseReference> {
    const path = `/v1/approvals/${encodeURIComponent(approvalId)}/execution-leases/consume`;
    const serializedBody = JSON.stringify({
      action_id: binding.action_id,
      authorization_fingerprint: binding.authorization_fingerprint,
    });

    for (
      let attempt = 0;
      attempt < MAX_LEASE_CONSUME_ATTEMPTS && Date.now() < deadlineMs;
      attempt += 1
    ) {
      const remainingMs = deadlineMs - Date.now();
      let response: GuardApiJsonResponse;
      try {
        response = await this.requestRaw(
          path,
          { method: "POST", body: serializedBody },
          Math.min(this.config.requestTimeoutMs, remainingMs),
        );
      } catch (error) {
        if (error instanceof GuardApiResponseError) {
          if (error.failure !== "timed_out") {
            throw new ExecutionLeaseConsumeError("invalid_response");
          }
          if (Date.now() >= deadlineMs) {
            throw new ExecutionLeaseConsumeError("timed_out");
          }
        }
        if (Date.now() >= deadlineMs) {
          throw new ExecutionLeaseConsumeError("timed_out");
        }
        if (attempt + 1 >= MAX_LEASE_CONSUME_ATTEMPTS) {
          throw new ExecutionLeaseConsumeError("lease_unavailable");
        }
        await delayWithinDeadline(
          this.config.approvalPollIntervalMs,
          deadlineMs,
        );
        continue;
      }

      if (response.ok) {
        return parseExecutionLeaseResponse(response.body);
      }

      const code = boundedErrorCode(response.body);
      if (response.status === 409) {
        if (code === "APPROVAL_NOT_CONSUMABLE") {
          throw new ExecutionLeaseConsumeError("approval_not_consumable", {
            status: response.status,
            code,
          });
        }
        if (code === "APPROVAL_CONSUMPTION_CONFLICT") {
          throw new ExecutionLeaseConsumeError("consumption_conflict", {
            status: response.status,
            code,
          });
        }
        throw new ExecutionLeaseConsumeError("rejected", {
          status: response.status,
          code: code ?? undefined,
        });
      }
      if (response.status === 410) {
        const failure =
          code === "APPROVAL_EXPIRED"
            ? "approval_expired"
            : code === "EXECUTION_LEASE_EXPIRED"
              ? "lease_expired"
              : "rejected";
        throw new ExecutionLeaseConsumeError(failure, {
          status: response.status,
          code: code ?? undefined,
        });
      }
      if (response.status === 403) {
        throw new ExecutionLeaseConsumeError("identity_denied", {
          status: response.status,
          code: code ?? undefined,
        });
      }
      if (response.status === 404) {
        throw new ExecutionLeaseConsumeError("approval_not_found", {
          status: response.status,
          code: code ?? undefined,
        });
      }
      if (
        response.status === 408 ||
        response.status === 429 ||
        response.status === 503 ||
        response.status >= 500
      ) {
        if (Date.now() >= deadlineMs) {
          throw new ExecutionLeaseConsumeError("timed_out", {
            status: response.status,
            code: code ?? undefined,
          });
        }
        if (attempt + 1 >= MAX_LEASE_CONSUME_ATTEMPTS) {
          throw new ExecutionLeaseConsumeError("lease_unavailable", {
            status: response.status,
            code: code ?? undefined,
          });
        }
        await delayWithinDeadline(
          this.config.approvalPollIntervalMs,
          deadlineMs,
        );
        continue;
      }
      if (code === "APPROVAL_NOT_CONSUMABLE") {
        throw new ExecutionLeaseConsumeError("approval_not_consumable", {
          status: response.status,
          code,
        });
      }
      throw new ExecutionLeaseConsumeError("rejected", {
        status: response.status,
        code: code ?? undefined,
      });
    }
    throw new ExecutionLeaseConsumeError(
      Date.now() >= deadlineMs ? "timed_out" : "lease_unavailable",
    );
  }

  private async request(
    path: string,
    init: RequestInit,
    timeoutMs = this.config.requestTimeoutMs,
  ): Promise<GuardApiJsonResponse> {
    const response = await this.requestRaw(path, init, timeoutMs);
    try {
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
      throw new GuardApiError("Guard API request failed");
    }
  }

  private async requestRaw(
    path: string,
    init: RequestInit,
    timeoutMs: number,
  ): Promise<GuardApiJsonResponse> {
    const controller = new AbortController();
    const boundedTimeoutMs = Math.max(1, timeoutMs);
    const deadlineMs = Date.now() + boundedTimeoutMs;
    const timeout = setTimeout(() => controller.abort(), boundedTimeoutMs);
    let abortListener: (() => void) | undefined;
    const abortPromise = new Promise<never>((_resolve, reject) => {
      abortListener = () => reject(new GuardApiResponseError("timed_out"));
      controller.signal.addEventListener("abort", abortListener, {
        once: true,
      });
    });
    try {
      const response = await Promise.race([
        this.fetchImpl(
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
        ),
        abortPromise,
      ]);
      const body = await readBoundedJsonResponse(
        response,
        controller.signal,
        abortPromise,
      );
      if (Date.now() >= deadlineMs || controller.signal.aborted) {
        throw new GuardApiResponseError("timed_out");
      }
      return { ok: response.ok, status: response.status, body };
    } catch (error) {
      const classified = classifyResponseHandlingError(
        error,
        controller.signal.aborted,
      );
      controller.abort();
      logDiagnostic(this.config, "Guard API request failed", {
        path,
        error_type: diagnosticErrorType(classified),
      });
      if (classified instanceof GuardApiResponseError) {
        throw classified;
      }
      throw new GuardApiError("Guard API request failed");
    } finally {
      clearTimeout(timeout);
      if (abortListener) {
        controller.signal.removeEventListener("abort", abortListener);
      }
    }
  }
}

async function readBoundedJsonResponse(
  response: Response,
  signal: AbortSignal,
  abortPromise: Promise<never>,
): Promise<unknown> {
  const declaredLength = response.headers.get("content-length");
  if (
    declaredLength !== null &&
    /^\d+$/u.test(declaredLength) &&
    Number(declaredLength) > MAX_GUARD_API_RESPONSE_BYTES
  ) {
    throw new GuardApiResponseError("too_large");
  }
  if (!response.body) {
    if (response.ok) {
      throw new GuardApiResponseError("malformed");
    }
    return null;
  }

  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let totalBytes = 0;
  let completed = false;
  try {
    while (true) {
      const chunk = await Promise.race([reader.read(), abortPromise]);
      if (chunk.done) {
        completed = true;
        break;
      }
      totalBytes += chunk.value.byteLength;
      if (totalBytes > MAX_GUARD_API_RESPONSE_BYTES) {
        throw new GuardApiResponseError("too_large");
      }
      chunks.push(chunk.value);
    }
  } finally {
    if (!completed) {
      void reader.cancel().catch(() => undefined);
    }
  }
  if (signal.aborted) {
    throw new GuardApiResponseError("timed_out");
  }

  const bytes = new Uint8Array(totalBytes);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.byteLength;
  }
  let text: string;
  try {
    text = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  } catch {
    throw new GuardApiResponseError("malformed");
  }
  if (!text.trim()) {
    if (response.ok) {
      throw new GuardApiResponseError("malformed");
    }
    return null;
  }
  try {
    return JSON.parse(text) as unknown;
  } catch {
    if (response.ok) {
      throw new GuardApiResponseError("malformed");
    }
    return null;
  }
}

function classifyResponseHandlingError(
  error: unknown,
  aborted: boolean,
): unknown {
  if (error instanceof GuardApiResponseError) {
    return error;
  }
  return aborted ? new GuardApiResponseError("timed_out") : error;
}

function diagnosticErrorType(error: unknown): string {
  if (error instanceof GuardApiResponseError) {
    return `response_${error.failure}`;
  }
  if (error instanceof DOMException && error.name === "AbortError") {
    return "abort";
  }
  if (error instanceof TypeError) {
    return "type_error";
  }
  if (error instanceof Error) {
    return "error";
  }
  return "non_error_throwable";
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
    strongApprovalBindingEnabled:
      input?.strongApprovalBindingEnabled === true,
    runtimeBindingId: optionalRuntimeBindingId(input?.runtimeBindingId),
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
export function approvalEvidenceFromWait(
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

function optionalRuntimeBindingId(value: unknown): string {
  if (value === undefined || value === null || value === "") {
    return "";
  }
  if (
    typeof value !== "string" ||
    !RUNTIME_BINDING_IDENTIFIER.test(value)
  ) {
    throw new GuardApiError(
      "runtimeBindingId must be a 1-256 character trusted runtime identifier",
    );
  }
  return value;
}

function trimTrailingSlash(value: string): string {
  return value.replace(/\/+$/, "");
}

function delay(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function delayWithinDeadline(
  requestedMs: number,
  deadlineMs: number,
): Promise<void> {
  const wakeAtMs = Math.min(Date.now() + requestedMs, deadlineMs);
  while (Date.now() < wakeAtMs) {
    await delay(wakeAtMs - Date.now());
  }
}

function timeoutApproval(): ApprovalWaitResponse {
  return {
    status: "timeout",
    decision: "deny",
    resolution_source: null,
  };
}

function parseEvaluationResponse(value: unknown): GuardEvaluationResponse {
  if (!isRecord(value) || !isRecord(value.decision)) {
    throw new GuardApiError("Guard API evaluation response is invalid");
  }
  const candidate = value as unknown as GuardEvaluationResponse;
  const bindingValue = value.enforcement_binding;
  if (bindingValue === undefined) {
    return candidate;
  }
  try {
    return {
      ...candidate,
      enforcement_binding: parseEnforcementBinding(bindingValue),
    };
  } catch {
    // Preserve only the fact that the field was present. The raw fingerprint
    // must not escape the response parser into runtime state or diagnostics.
    return { ...candidate, enforcement_binding: { invalid: true } };
  }
}

function parseEnforcementBinding(value: unknown): EnforcementBinding {
  if (!isRecord(value)) {
    throw new GuardApiError("Guard API enforcement binding is invalid");
  }
  const keys = Object.keys(value).sort();
  const expected = [
    "action_id",
    "authorization_fingerprint",
    "requires_execution_lease",
    "runtime_binding_id",
    "schema_version",
  ];
  if (
    keys.length !== expected.length ||
    keys.some((key, index) => key !== expected[index]) ||
    value.schema_version !== "2.1" ||
    typeof value.action_id !== "string" ||
    value.action_id.length === 0 ||
    typeof value.authorization_fingerprint !== "string" ||
    !AUTHORIZATION_FINGERPRINT.test(value.authorization_fingerprint) ||
    typeof value.runtime_binding_id !== "string" ||
    !RUNTIME_BINDING_IDENTIFIER.test(value.runtime_binding_id) ||
    value.requires_execution_lease !== true
  ) {
    throw new GuardApiError("Guard API enforcement binding is invalid");
  }
  return {
    schema_version: "2.1",
    action_id: value.action_id,
    authorization_fingerprint: value.authorization_fingerprint,
    runtime_binding_id: value.runtime_binding_id,
    requires_execution_lease: true,
  };
}

function parseApprovalWaitResponse(value: unknown): ApprovalWaitResponse {
  if (
    !isRecord(value) ||
    (value.status !== "pending" &&
      value.status !== "resolved" &&
      value.status !== "expired")
  ) {
    throw new GuardApiError("Guard API approval response is invalid");
  }
  const decision = value.decision;
  const resolutionSource = value.resolution_source;
  if (
    decision !== "allow_once" &&
    decision !== "deny" &&
    decision !== null
  ) {
    throw new GuardApiError("Guard API approval response is invalid");
  }
  if (
    resolutionSource !== undefined &&
    resolutionSource !== null &&
    resolutionSource !== "human" &&
    resolutionSource !== "llm" &&
    resolutionSource !== "system"
  ) {
    throw new GuardApiError("Guard API approval response is invalid");
  }
  return {
    status: value.status,
    decision,
    ...(resolutionSource === undefined
      ? {}
      : { resolution_source: resolutionSource }),
  };
}

function parseExecutionLeaseResponse(value: unknown): ExecutionLeaseReference {
  if (!isRecord(value)) {
    throw new ExecutionLeaseConsumeError("invalid_response");
  }
  const keys = Object.keys(value).sort();
  const expected = ["consumption_id", "expires_at", "lease_id", "lease_token"];
  if (
    keys.length !== expected.length ||
    keys.some((key, index) => key !== expected[index]) ||
    typeof value.lease_id !== "string" ||
    !LEASE_IDENTIFIER.test(value.lease_id) ||
    typeof value.consumption_id !== "string" ||
    !LEASE_IDENTIFIER.test(value.consumption_id) ||
    typeof value.lease_token !== "string" ||
    !STRICT_LEASE_TOKEN.test(value.lease_token) ||
    typeof value.expires_at !== "string"
  ) {
    throw new ExecutionLeaseConsumeError("invalid_response");
  }
  const expiresAtMs = strictRfc3339EpochMs(value.expires_at);
  if (!Number.isFinite(expiresAtMs) || expiresAtMs <= Date.now()) {
    throw new ExecutionLeaseConsumeError("invalid_response");
  }

  // Intentionally do not return or retain value.lease_token.
  return {
    leaseId: value.lease_id,
    consumptionId: value.consumption_id,
    expiresAt: new Date(expiresAtMs).toISOString(),
  };
}

function strictRfc3339EpochMs(value: string): number {
  const match = RFC3339_TIMESTAMP.exec(value);
  if (!match) {
    return Number.NaN;
  }
  const [, yearText, monthText, dayText, hourText, minuteText, secondText,
    fractionText = "", zoneText, signText, offsetHourText, offsetMinuteText] =
    match;
  const year = Number(yearText);
  const month = Number(monthText);
  const day = Number(dayText);
  const hour = Number(hourText);
  const minute = Number(minuteText);
  const second = Number(secondText);
  const millisecond = Number(`${fractionText}000`.slice(0, 3));
  const local = new Date(0);
  local.setUTCFullYear(year, month - 1, day);
  local.setUTCHours(hour, minute, second, millisecond);
  if (
    month < 1 ||
    month > 12 ||
    day < 1 ||
    local.getUTCFullYear() !== year ||
    local.getUTCMonth() !== month - 1 ||
    local.getUTCDate() !== day ||
    hour > 23 ||
    minute > 59 ||
    second > 59
  ) {
    return Number.NaN;
  }
  let offsetMinutes = 0;
  if (zoneText !== "Z") {
    const offsetHour = Number(offsetHourText);
    const offsetMinute = Number(offsetMinuteText);
    if (offsetHour > 23 || offsetMinute > 59) {
      return Number.NaN;
    }
    offsetMinutes = (offsetHour * 60 + offsetMinute) *
      (signText === "+" ? 1 : -1);
  }
  const expected = local.getTime() - offsetMinutes * 60_000;
  const parsed = Date.parse(value);
  return parsed === expected ? parsed : Number.NaN;
}

function boundedErrorCode(value: unknown): string | null {
  if (!isRecord(value) || !isRecord(value.error)) {
    return null;
  }
  const code = value.error.code;
  return typeof code === "string" && LEASE_ERROR_CODES.has(code) ? code : null;
}

const LEASE_ERROR_CODES: ReadonlySet<string> = new Set([
  "APPROVAL_CONSUMPTION_DENIED",
  "APPROVAL_NOT_FOUND",
  "APPROVAL_NOT_CONSUMABLE",
  "APPROVAL_CONSUMPTION_CONFLICT",
  "APPROVAL_EXPIRED",
  "EXECUTION_LEASE_EXPIRED",
  "EXECUTION_LEASE_UNAVAILABLE",
]);

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
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
    const withoutAdapterToken = adapterToken
      ? value.replaceAll(adapterToken, "[redacted]")
      : value;
    return withoutAdapterToken
      .replace(SECRET_FINGERPRINT, "[redacted-fingerprint]")
      .replace(LEASE_TOKEN, "[redacted-lease-token]");
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
