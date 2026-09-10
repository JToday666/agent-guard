import {
  GuardApiError,
  GuardApiResponseError,
  validateGuardApiBaseUrl,
  readBoundedJsonResponse,
} from "./guard-api-http.js";
export {
  GuardApiError,
  GuardApiResponseError,
  validateGuardApiBaseUrl,
  type GuardApiResponseFailure,
} from "./guard-api-http.js";
import {
  OpenClawProductTransport,
  productTransportBindingDigest,
} from "./runtime/product-transport.js";
import { types } from "node:util";
import { isAbsolute, relative, sep } from "node:path";

import {
  OPENCLAW_REQUIRED_HOOK_COUNT,
  OPENCLAW_REQUIRED_HOOKS,
} from "../hook-contract.mjs";
import { OPENCLAW_EFFECTIVE_FAIL_CLOSED_HOOKS } from "./runtime/host-capabilities.js";
import {
  OpenClawActivationSession,
  type OpenClawActivationSessionOptions,
} from "./runtime/activation-session.js";
import {
  isOpenClawActivationAckHandle,
  type OpenClawActivationAckHandle,
} from "./runtime/activation-ack-handle.js";
import {
  OpenClawProductManifest,
  OpenClawProductActivationError,
} from "./runtime/product-manifest.js";
import {
  bindEvaluationActivationAck,
  bindConsumptionActivationAck,
  evaluationActivationAck,
  runtimeOutcomeToWire,
  hasProductReceiptCarrier,
  hasPrivateProductReceiptCarrier,
} from "./runtime/product-authority-context.js";
import { readOpenClawProductEvaluation } from "./runtime/product-evaluation.js";
import { captureProductReceiptWire } from "./runtime/product-receipt-wire.js";
import {
  productReceiptCompatibilityResponse,
  type ProductReceiptDeliveryResult,
  type ProductReceiptTransportResult,
} from "./runtime/product-delivery.js";
import type { OpenClawProductReceiptOutbox } from "./runtime/product-receipt-outbox.js";
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

const AUTHORIZATION_FINGERPRINT = /^hmac-sha256:[0-9a-f]{64}$/u;
const SECRET_FINGERPRINT = /hmac-sha256:[0-9a-f]{64}/gu;
const LEASE_TOKEN = /lease-v1:[0-9a-f]{64}/gu;
const STRICT_LEASE_TOKEN = /^lease-v1:[0-9a-f]{64}$/u;
const LEASE_IDENTIFIER = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,159}$/u;
const RUNTIME_BINDING_IDENTIFIER = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,255}$/u;
const RFC3339_TIMESTAMP =
  /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,9}))?(Z|([+-])(\d{2}):(\d{2}))$/u;
const MAX_LEASE_CONSUME_ATTEMPTS = 5;
const PRODUCT_DRIFT_CODES = new Set([
  "V21_PRODUCT_ACTIVATION_NOT_CURRENT",
  "V21_PRODUCT_RUNTIME_IDENTITY_MISMATCH",
  "V21_PRODUCT_RUNTIME_OBSERVATION_MISMATCH",
]);

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
  officialProfileId: "",
  officialProfileDigest: "",
  restrictedAskReleaseEnabled: false,
  activationAckMaxAgeMs: 120000,
  runtimeBindingId: "",
  diagnosticLogging: false,
  agentId: "main",
};

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
  delivery_status?: ProductReceiptDeliveryResult["status"];
  error?: string;
};

/** decisionToToolResult / decisionToMessageResult 回传给调用方的运行时结果通知。 */
export type DecisionOutcome =
  | { kind: "pre_execution_deny"; approval: OutcomeApprovalEvidence | null }
  | { kind: "approval_release"; approval: OutcomeApprovalEvidence };

export type RestrictedLeaseConsumeRequest = Readonly<{
  mode: "restricted_allow_once";
  action_id: string;
}>;

export class GuardApiClient {
  readonly #config: Readonly<AgentGuardPluginConfig>;
  readonly #fetchImpl: FetchLike;
  #session: OpenClawActivationSession | undefined;
  #sessionCreation: Promise<OpenClawActivationSession> | undefined;
  #productClosed = false;
  #productAbort = new AbortController();
  #productDelivery: Promise<OpenClawProductReceiptOutbox> | undefined;
  #productDeliveryClosed = false;
  #productTransport?: OpenClawProductTransport;
  #consumptions = new WeakMap<
    GuardEvaluationResponse,
    Promise<ExecutionLeaseReference>
  >();
  #consumptionInputs = new WeakMap<GuardEvaluationResponse, string>();
  #productActionIds = new WeakMap<GuardEvaluationResponse, string>();

  private get config(): Readonly<AgentGuardPluginConfig> {
    return this.#config;
  }
  private get fetchImpl(): FetchLike {
    return this.#fetchImpl;
  }

  constructor(params: ClientParams) {
    this.#config = Object.freeze({
      ...params.config,
      guardApiBaseUrl: validateGuardApiBaseUrl(params.config.guardApiBaseUrl),
    });
    this.#fetchImpl = params.fetchImpl ?? fetch;
  }

  get productEnabled(): boolean {
    return Boolean(
      this.#config.officialProfileId ||
      this.#config.officialProfileDigest ||
      this.#config.productManifestPath ||
      this.#config.productReceiptDirectory ||
      this.#config.productReceiptKeyPath ||
      this.#config.restrictedAskReleaseEnabled,
    );
  }

  /** Transport lifecycle only. Plugin registration remains fused until composition is complete. */
  async startProductSession(
    observe: OpenClawActivationSessionOptions["observe"],
  ): Promise<OpenClawActivationAckHandle> {
    this.assertProductConfiguration();
    if (!this.#sessionCreation) {
      this.#sessionCreation = (async () => {
        const manifest = await OpenClawProductManifest.fromFile(
          this.#config.productManifestPath!,
        );
        if (
          manifest.data.agent_id !== this.#config.agentId ||
          manifest.data.runtime_binding_id !== this.#config.runtimeBindingId ||
          manifest.data.profile_id !== this.#config.officialProfileId ||
          manifest.data.profile_digest !== this.#config.officialProfileDigest
        ) {
          throw new OpenClawProductActivationError(
            "configuration_identity_mismatch",
          );
        }
        this.assertProductConfiguration();
        const session = new OpenClawActivationSession({
          manifest,
          observe,
          maxAckAgeMs: this.#config.activationAckMaxAgeMs,
          refreshIntervalMs: Math.max(
            1,
            Math.min(
              30_000,
              Math.floor(this.#config.activationAckMaxAgeMs / 2),
            ),
          ),
          sendHeartbeat: async (body, { signal }) => {
            this.assertProductConfiguration();
            const response = await this.request(
              "/v1/adapters/openclaw/heartbeat",
              {
                method: "POST",
                body: JSON.stringify(body),
                signal,
              },
            );
            return response.body;
          },
        });
        this.#session = session;
        return session;
      })();
    }
    const session = await this.#sessionCreation;
    this.assertProductConfiguration();
    return session.start();
  }

  async refreshProductAck(): Promise<OpenClawActivationAckHandle> {
    this.assertProductConfiguration();
    if (!this.#session)
      throw new OpenClawProductActivationError("session_not_started");
    return this.#session.refresh();
  }

  async snapshotProductAck(): Promise<OpenClawActivationAckHandle> {
    this.assertProductConfiguration();
    if (!this.#session)
      throw new OpenClawProductActivationError("session_not_started");
    return this.#session.snapshot();
  }

  closeProductSession(): void {
    this.#productClosed = true;
    this.#productAbort.abort();
    this.#session?.close();
  }

  private assertProductConfiguration(historicalDelivery = false): void {
    const config = this.#config;
    if (this.#productClosed && !historicalDelivery)
      throw new OpenClawProductActivationError("session_closed");
    if (
      !this.productEnabled ||
      config.officialProfileId !== "agentguard-openclaw-v2-restricted" ||
      !/^sha256:[0-9a-f]{64}$/u.test(config.officialProfileDigest) ||
      !config.productManifestPath ||
      !isAbsolute(config.productManifestPath) ||
      !config.adapterToken ||
      !config.agentId ||
      !config.runtimeBindingId ||
      config.enforcementMode !== "enforce" ||
      config.strongApprovalBindingEnabled ||
      !Number.isSafeInteger(config.activationAckMaxAgeMs) ||
      config.activationAckMaxAgeMs < 1 ||
      config.activationAckMaxAgeMs > 120_000
    ) {
      throw new OpenClawProductActivationError("product_configuration_invalid");
    }
  }

  async evaluateProductEvent(
    event: GuardEvent | Record<string, unknown>,
  ): Promise<{
    evaluation: GuardEvaluationResponse;
    activationAck: OpenClawActivationAckHandle;
  }> {
    this.assertProductConfiguration();
    // Capture before the first await: caller mutation cannot change the event
    // that establishes a later restricted action's consumption identity.
    let body: string;
    let captured: Record<string, unknown>;
    try {
      body = JSON.stringify(event);
      captured = JSON.parse(body) as Record<string, unknown>;
    } catch {
      throw new OpenClawProductActivationError("event_identity_mismatch");
    }
    if (
      !isRecord(captured) ||
      captured.runtime !== "openclaw" ||
      !isRecord(captured.security_context) ||
      captured.security_context.agent_id !== this.#config.agentId
    ) {
      throw new OpenClawProductActivationError("event_identity_mismatch");
    }
    const activationAck = await this.snapshotProductAck();
    const response = await this.request("/v1/guard/evaluate", {
      method: "POST",
      body,
      headers: { "X-AgentGuard-Activation-Ack": activationAck.headerValue() },
      signal: this.#productAbort.signal,
    });
    await this.snapshotProductAck();
    activationAck.assertFresh(Date.now(), this.#config.activationAckMaxAgeMs);
    try {
      const evaluation = readOpenClawProductEvaluation(
        response.body,
        activationAck,
      );
      bindEvaluationActivationAck(evaluation, activationAck);
      const actionId = productActionId(captured);
      if (actionId !== undefined)
        this.#productActionIds.set(evaluation, actionId);
      return { evaluation, activationAck };
    } catch {
      this.closeProductSession();
      throw new OpenClawProductActivationError("official_response_mismatch");
    }
  }

  async evaluate(
    event: GuardEvent | Record<string, unknown>,
  ): Promise<GuardEvaluationResponse> {
    if (this.productEnabled)
      return (await this.evaluateProductEvent(event)).evaluation;
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
   * Product 使用 required encrypted delivery；兼容返回仅 recorded 为 ok:true。
   * 旧路径保留永久 4xx 的 ok:false 返回，旧队列不能把它当成确认。
   */
  async submitRuntimeOutcome(
    event: RuntimeOutcomeReceipt,
  ): Promise<AuditSubmitResponse> {
    if (this.productEnabled || hasProductReceiptCarrier(event)) {
      if (!hasPrivateProductReceiptCarrier(event))
        throw new OpenClawProductActivationError("receipt_ack_context_missing");
      captureProductReceiptWire(event);
      return productReceiptCompatibilityResponse(
        await this.submitProductReceipt(event),
      );
    }
    if (!this.config.adapterToken) {
      throw new GuardApiError("AgentGuard adapter token is not configured");
    }

    const wire = runtimeOutcomeToWire(event);

    try {
      const response = await this.request("/v1/audit/events", {
        method: "POST",
        body: JSON.stringify(wire),
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

  /** Lifecycle of the encrypted queue is independent from the current ACK. */
  async openProductDelivery(): Promise<OpenClawProductReceiptOutbox> {
    if (this.#productDeliveryClosed)
      throw new OpenClawProductActivationError("product_delivery_closed");
    if (!this.#productDelivery) {
      this.#productDelivery = (async () => {
        this.assertProductConfiguration(true);
        validateProductReceiptPaths(this.#config, true);
        const manifest = await OpenClawProductManifest.fromFile(
          this.#config.productManifestPath!,
        );
        if (
          manifest.data.agent_id !== this.#config.agentId ||
          manifest.data.runtime_binding_id !== this.#config.runtimeBindingId ||
          manifest.data.profile_id !== this.#config.officialProfileId ||
          manifest.data.profile_digest !== this.#config.officialProfileDigest
        )
          throw new OpenClawProductActivationError(
            "configuration_identity_mismatch",
          );
        const { OpenClawProductEnvelopeStore } =
          await import("./runtime/product-envelope-store.js");
        const { OpenClawProductReceiptOutbox } =
          await import("./runtime/product-receipt-outbox.js");
        const store = await OpenClawProductEnvelopeStore.open({
          directory: this.#config.productReceiptDirectory!,
          keyPath: this.#config.productReceiptKeyPath!,
          namespace: {
            runtime: "openclaw",
            agentId: manifest.data.agent_id,
            principalId: manifest.data.principal_id,
            runtimeBindingId: manifest.data.runtime_binding_id,
          },
        });
        try {
          if (this.#productDeliveryClosed)
            throw new OpenClawProductActivationError("product_delivery_closed");
          const delivery = new OpenClawProductReceiptOutbox({
            store,
            sendReceipt: (wire) => this.submitProductReceiptWire(wire),
            transportBindingDigest: productTransportBindingDigest(
              this.#config.guardApiBaseUrl,
              store.namespace,
            ),
            transportIdle: () => this.#receiptTransport().whenIdle(),
            transportBusy: () => this.#receiptTransport().busy,
          });
          delivery.start();
          return delivery;
        } catch {
          await store.close();
          throw new OpenClawProductActivationError(
            "product_delivery_unavailable",
          );
        }
      })();
    }
    return this.#productDelivery;
  }

  async closeProductDelivery(): Promise<void> {
    this.#productDeliveryClosed = true;
    if (this.#productDelivery) {
      try {
        await (await this.#productDelivery).close();
      } catch {
        /* Initialization already failed closed; no live queue exists. */
      }
    }
  }

  async submitProductReceipt(
    event: RuntimeOutcomeReceipt,
  ): Promise<ProductReceiptDeliveryResult> {
    try {
      if (!hasProductReceiptCarrier(event))
        throw new OpenClawProductActivationError("receipt_ack_context_missing");
      const wire = captureProductReceiptWire(event);
      return await (
        await this.openProductDelivery()
      ).submitHistoricalWire(wire);
    } catch {
      return { status: "failed", errorCode: "product_delivery_unavailable" };
    }
  }

  /** One bounded HTTP attempt using immutable original UTF-8 bytes and no live ACK. */
  async submitProductReceiptWire(
    wire: string,
  ): Promise<ProductReceiptTransportResult> {
    try {
      this.assertProductConfiguration(true);
      return await this.#receiptTransport().send(wire);
    } catch {
      return { status: "failed", errorCode: "receipt_transport_invalid" };
    }
  }

  #receiptTransport(): OpenClawProductTransport {
    return (this.#productTransport ??= new OpenClawProductTransport(
      {
        guardApiBaseUrl: this.#config.guardApiBaseUrl,
        adapterToken: this.#config.adapterToken,
        agentId: this.#config.agentId,
        runtimeBindingId: this.#config.runtimeBindingId,
        requestTimeoutMs: this.#config.requestTimeoutMs,
      },
      this.#fetchImpl,
    ));
  }

  async submitHeartbeat(
    input: AdapterHeartbeatInput,
  ): Promise<Record<string, unknown>> {
    if (this.productEnabled)
      throw new OpenClawProductActivationError("legacy_heartbeat_forbidden");
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
    if (this.productEnabled) this.assertProductConfiguration();
    const deadline = deadlineMs;
    while (Date.now() < deadline) {
      if (this.productEnabled) await this.snapshotProductAck();
      const remainingMs = deadline - Date.now();
      if (remainingMs <= 0) return timeoutApproval();
      let response: GuardApiJsonResponse;
      try {
        response = await this.request(
          `/v1/approvals/${encodeURIComponent(approvalId)}/wait`,
          {
            method: "GET",
            ...(this.productEnabled
              ? { signal: this.#productAbort.signal }
              : {}),
          },
          Math.min(this.config.requestTimeoutMs, remainingMs),
        );
      } catch (error) {
        if (this.productEnabled) this.assertProductConfiguration();
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
        await delayWithinDeadline(this.config.approvalPollIntervalMs, deadline);
        continue;
      }
      if (this.productEnabled) await this.snapshotProductAck();
      const parsed = parseApprovalWaitResponse(response.body);
      if (parsed.status !== "pending") {
        return parsed;
      }
      await delayWithinDeadline(this.config.approvalPollIntervalMs, deadline);
    }
    return timeoutApproval();
  }

  /** Fresh ACK after approval; duplicate calls reuse the entire original attempt. */
  consumeProductExecutionLease(
    evaluation: GuardEvaluationResponse,
    request: RestrictedLeaseConsumeRequest,
    deadlineMs: number,
  ): Promise<ExecutionLeaseReference> {
    this.assertProductConfiguration();
    const original = evaluationActivationAck(evaluation);
    if (
      !original ||
      evaluation.decision.decision !== "ask" ||
      evaluation.approval_release_directive?.mode !== "restricted_allow_once" ||
      !evaluation.approval?.approval_id ||
      !this.#productActionIds.has(evaluation)
    ) {
      throw new OpenClawProductActivationError("consumption_authority_missing");
    }
    const checked = parseRestrictedLeaseConsumeRequest(request);
    if (!Number.isFinite(deadlineMs)) {
      throw new OpenClawProductActivationError("consumption_identity_mismatch");
    }
    const input = JSON.stringify([evaluation.approval.approval_id, checked]);
    const previous = this.#consumptions.get(evaluation);
    if (previous) {
      if (this.#consumptionInputs.get(evaluation) !== input) {
        throw new OpenClawProductActivationError(
          "consumption_request_conflict",
        );
      }
      return previous;
    }
    if (checked.action_id !== this.#productActionIds.get(evaluation)) {
      throw new OpenClawProductActivationError("consumption_identity_mismatch");
    }
    const approvalId = evaluation.approval.approval_id;
    const serializedBody = JSON.stringify(checked);
    const operation = (async () => {
      const ack = await this.refreshProductAck();
      bindConsumptionActivationAck(evaluation, ack);
      return this.#consumeLeaseWire(
        approvalId,
        serializedBody,
        Math.min(
          deadlineMs,
          Date.now() +
            ack.assertFresh(Date.now(), this.#config.activationAckMaxAgeMs),
        ),
        ack,
      );
    })();
    this.#consumptionInputs.set(evaluation, input);
    this.#consumptions.set(evaluation, operation);
    return operation;
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
    activationAck?: OpenClawActivationAckHandle,
  ): Promise<ExecutionLeaseReference> {
    if (this.productEnabled || activationAck !== undefined) {
      throw new OpenClawProductActivationError("consumption_authority_missing");
    }
    const checked = parseEnforcementBinding(binding);
    return this.#consumeLeaseWire(
      approvalId,
      JSON.stringify({
        action_id: checked.action_id,
        authorization_fingerprint: checked.authorization_fingerprint,
      }),
      deadlineMs,
    );
  }

  async #consumeLeaseWire(
    approvalId: string,
    serializedBody: string,
    deadlineMs: number,
    activationAck?: OpenClawActivationAckHandle,
  ): Promise<ExecutionLeaseReference> {
    if (this.productEnabled) {
      this.assertProductConfiguration();
      if (
        !isOpenClawActivationAckHandle(activationAck) ||
        !this.#session ||
        activationAck.identity.agent_id !== this.#config.agentId ||
        activationAck.identity.runtime_binding_id !==
          this.#config.runtimeBindingId ||
        Object.entries(this.#session.manifest.expectedAckIdentity).some(
          ([key, value]) =>
            activationAck.identity[
              key as keyof typeof activationAck.identity
            ] !== value,
        )
      ) {
        throw new OpenClawProductActivationError("consumption_ack_missing");
      }
      deadlineMs = Math.min(
        deadlineMs,
        Date.now() +
          activationAck.assertFresh(
            Date.now(),
            this.#config.activationAckMaxAgeMs,
          ),
      );
    } else if (activationAck !== undefined) {
      throw new OpenClawProductActivationError("product_configuration_invalid");
    }
    const path = `/v1/approvals/${encodeURIComponent(approvalId)}/execution-leases/consume`;
    for (
      let attempt = 0;
      attempt < MAX_LEASE_CONSUME_ATTEMPTS && Date.now() < deadlineMs;
      attempt += 1
    ) {
      if (this.productEnabled) await this.snapshotProductAck();
      const remainingMs = deadlineMs - Date.now();
      if (remainingMs <= 0) throw new ExecutionLeaseConsumeError("timed_out");
      let response: GuardApiJsonResponse;
      try {
        response = await this.requestRaw(
          path,
          {
            method: "POST",
            body: serializedBody,
            ...(activationAck
              ? {
                  headers: {
                    "X-AgentGuard-Activation-Ack": activationAck.headerValue(),
                  },
                }
              : {}),
            ...(this.productEnabled
              ? { signal: this.#productAbort.signal }
              : {}),
          },
          Math.min(this.config.requestTimeoutMs, remainingMs),
        );
      } catch (error) {
        if (this.productEnabled) this.assertProductConfiguration();
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

      this.rejectProductDrift(response);
      if (this.productEnabled) await this.snapshotProductAck();
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
    this.rejectProductDrift(response);
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
    const outerAbort = () => controller.abort();
    init.signal?.addEventListener("abort", outerAbort, { once: true });
    try {
      if (init.signal?.aborted) {
        controller.abort();
        await abortPromise;
      }
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
      init.signal?.removeEventListener("abort", outerAbort);
      if (abortListener) {
        controller.signal.removeEventListener("abort", abortListener);
      }
    }
  }

  private rejectProductDrift(response: GuardApiJsonResponse): void {
    if (!this.productEnabled || response.ok) return;
    const body = response.body;
    const detail = isRecord(body) ? body.error : undefined;
    const code = isRecord(detail) ? detail.code : undefined;
    if (typeof code === "string" && PRODUCT_DRIFT_CODES.has(code)) {
      this.closeProductSession();
      throw new OpenClawProductActivationError(code);
    }
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
  // Host schema defaults must not inject these fields: explicit presence is
  // significant even for false, so legacy/new configurations cannot be mixed.
  const hasField = (name: string): boolean =>
    input !== undefined && Object.hasOwn(input, name);
  const v2Fields = [
    "officialProfileId",
    "officialProfileDigest",
    "productManifestPath",
    "productReceiptDirectory",
    "productReceiptKeyPath",
    "restrictedAskReleaseEnabled",
    "activationAckMaxAgeMs",
  ];
  if (hasField("strongApprovalBindingEnabled") && v2Fields.some(hasField)) {
    throw new GuardApiError(
      "strongApprovalBindingEnabled is deprecated and cannot be combined with V2 configuration fields",
    );
  }
  const hasProfile =
    hasField("officialProfileId") ||
    hasField("officialProfileDigest") ||
    hasField("productManifestPath") ||
    hasField("productReceiptDirectory") ||
    hasField("productReceiptKeyPath");
  validateProductReceiptPaths(input ?? {});
  if (
    hasField("productManifestPath") &&
    (typeof input?.productManifestPath !== "string" ||
      !isAbsolute(input.productManifestPath))
  ) {
    throw new GuardApiError(
      "productManifestPath must be an absolute protected file path",
    );
  }
  if (hasProfile) {
    if (input?.officialProfileId !== "agentguard-openclaw-v2-restricted") {
      throw new GuardApiError(
        "officialProfileId must be agentguard-openclaw-v2-restricted",
      );
    }
    if (
      typeof input?.officialProfileDigest !== "string" ||
      !/^sha256:[0-9a-f]{64}$/u.test(input.officialProfileDigest)
    ) {
      throw new GuardApiError(
        "officialProfileDigest must be a canonical SHA-256 digest",
      );
    }
    if (hasField("enforcementMode") && input?.enforcementMode !== "enforce") {
      throw new GuardApiError(
        "officialProfileId requires enforcementMode=enforce",
      );
    }
  }
  if (
    hasField("restrictedAskReleaseEnabled") &&
    typeof input?.restrictedAskReleaseEnabled !== "boolean"
  ) {
    throw new GuardApiError("restrictedAskReleaseEnabled must be a boolean");
  }
  // This reader/config batch deliberately cannot open a half-wired release path.
  // Remove this fuse only with handshake, durable delivery and breaker consumers.
  if (input?.restrictedAskReleaseEnabled === true) {
    throw new GuardApiError(
      "restrictedAskReleaseEnabled is not available in this build",
    );
  }
  if (
    hasField("activationAckMaxAgeMs") &&
    (typeof input?.activationAckMaxAgeMs !== "number" ||
      !Number.isInteger(input.activationAckMaxAgeMs) ||
      input.activationAckMaxAgeMs < 1 ||
      input.activationAckMaxAgeMs > 120000)
  ) {
    throw new GuardApiError(
      "activationAckMaxAgeMs must be an integer from 1 to 120000",
    );
  }
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
    strongApprovalBindingEnabled: input?.strongApprovalBindingEnabled === true,
    officialProfileId:
      input?.officialProfileId ?? DEFAULT_CONFIG.officialProfileId,
    officialProfileDigest:
      input?.officialProfileDigest ?? DEFAULT_CONFIG.officialProfileDigest,
    ...(input?.productManifestPath === undefined
      ? {}
      : { productManifestPath: input.productManifestPath }),
    ...(input?.productReceiptDirectory === undefined
      ? {}
      : { productReceiptDirectory: input.productReceiptDirectory }),
    ...(input?.productReceiptKeyPath === undefined
      ? {}
      : { productReceiptKeyPath: input.productReceiptKeyPath }),
    restrictedAskReleaseEnabled: false,
    activationAckMaxAgeMs:
      input?.activationAckMaxAgeMs ?? DEFAULT_CONFIG.activationAckMaxAgeMs,
    runtimeBindingId: optionalRuntimeBindingId(input?.runtimeBindingId),
    diagnosticLogging: input?.diagnosticLogging === true,
    agentId: nonEmptyString(input?.agentId, DEFAULT_CONFIG.agentId),
  };
  if (hasProfile && !config.runtimeBindingId) {
    throw new GuardApiError(
      "officialProfileId requires a trusted runtimeBindingId",
    );
  }
  if (!config.adapterToken) {
    throw new GuardApiError(
      "AgentGuard adapterToken must be configured through an OpenClaw SecretRef",
    );
  }
  if (hasProfile) {
    // A configured official profile must never silently run the legacy client.
    // Keep registration closed until ACK/authority/receipt consumers are atomic.
    throw new GuardApiError(
      "officialProfileId activation is not available in this build",
    );
  }
  return config;
}

export function validateProductReceiptPaths(
  config: {
    productReceiptDirectory?: unknown;
    productReceiptKeyPath?: unknown;
  },
  required = false,
): void {
  const directory = config.productReceiptDirectory;
  const keyPath = config.productReceiptKeyPath;
  if (!required && directory === undefined && keyPath === undefined) return;
  if (
    typeof directory !== "string" ||
    !directory ||
    !isAbsolute(directory) ||
    typeof keyPath !== "string" ||
    !keyPath ||
    !isAbsolute(keyPath)
  )
    throw new OpenClawProductActivationError("product_receipt_paths_invalid");
  const keyRelative = relative(directory, keyPath);
  if (
    keyRelative === "" ||
    (!isAbsolute(keyRelative) &&
      keyRelative !== ".." &&
      !keyRelative.startsWith(`..${sep}`))
  )
    throw new OpenClawProductActivationError(
      "product_receipt_key_not_separate",
    );
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
    return { block: true, blockReason: blockedDecisionMessage(response) };
  }
  if (mustBlockV2AskWithoutRuntimeRelease(response)) {
    onOutcome?.({ kind: "pre_execution_deny", approval: null });
    return { block: true, blockReason: blockedDecisionMessage(response) };
  }
  if (response.approval === null || waiter.waitForApproval === undefined) {
    onOutcome?.({ kind: "pre_execution_deny", approval: null });
    return {
      block: true,
      blockReason: approvalNotGrantedMessage(response.approval?.approval_id),
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
    blockReason: approvalOutcomeMessage(
      response.approval.approval_id,
      approval,
    ),
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
    return { cancel: true, cancelReason: blockedDecisionMessage(response) };
  }
  if (mustBlockV2AskWithoutRuntimeRelease(response)) {
    onOutcome?.({ kind: "pre_execution_deny", approval: null });
    return { cancel: true, cancelReason: blockedDecisionMessage(response) };
  }
  if (response.approval === null || waiter.waitForApproval === undefined) {
    onOutcome?.({ kind: "pre_execution_deny", approval: null });
    return {
      cancel: true,
      cancelReason: approvalNotGrantedMessage(response.approval?.approval_id),
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
    cancelReason: approvalOutcomeMessage(
      response.approval.approval_id,
      approval,
    ),
  };
}

/**
 * Compatibility reader safety: generic C1 approval waiting is never release
 * authority for a V2 ASK. Product restricted release is consumed only by the
 * explicit restricted runtime path; until that path is enabled, the legacy
 * projection (`forbidden`) and even a malformed/orphan directive block.
 */
function mustBlockV2AskWithoutRuntimeRelease(
  response: GuardEvaluationResponse,
): boolean {
  if (response.approval_release_directive !== undefined) {
    return true;
  }
  const authority: unknown = response.decision_authority;
  return (
    typeof authority === "object" &&
    authority !== null &&
    "source" in authority &&
    authority.source === "v21"
  );
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

const BLOCKED_ACTION_GUIDANCE =
  "This action was blocked by AgentGuard and was NOT executed. Do not automatically retry the same blocked action. If the task cannot be completed without it, clearly tell the user that AgentGuard blocked the action.";

const APPROVAL_NOT_GRANTED_GUIDANCE =
  "This action required AgentGuard approval, but approval was not granted; the action was NOT executed. Do not automatically retry the same action. If the task cannot be completed without it, clearly tell the user that AgentGuard approval was not granted.";

const REVIEW_DENIED_GUIDANCE =
  "This action was denied by AgentGuard review and was NOT executed. Do not automatically retry the same denied action. If the task cannot be completed without it, clearly tell the user that AgentGuard review denied the action.";

const APPROVAL_EXPIRED_GUIDANCE =
  "AgentGuard approval timed out or expired before this action could run; the action was NOT executed. Do not automatically retry the same action. If the task cannot be completed without it, clearly tell the user that AgentGuard approval expired.";

function blockedDecisionMessage(response: GuardEvaluationResponse): string {
  return `${safeDecisionMessage(response)} ${BLOCKED_ACTION_GUIDANCE}`;
}

function approvalNotGrantedMessage(approvalId?: string): string {
  return approvalId
    ? `${APPROVAL_NOT_GRANTED_GUIDANCE} (approval_id=${approvalId})`
    : APPROVAL_NOT_GRANTED_GUIDANCE;
}

function approvalOutcomeMessage(
  approvalId: string,
  approval: ApprovalWaitResponse,
): string {
  if (approval.status === "timeout" || approval.status === "expired") {
    return `${APPROVAL_EXPIRED_GUIDANCE} (approval_id=${approvalId})`;
  }
  if (approval.status === "resolved" && approval.decision === "deny") {
    return `${REVIEW_DENIED_GUIDANCE} (approval_id=${approvalId})`;
  }
  return `${APPROVAL_NOT_GRANTED_GUIDANCE} (approval_id=${approvalId})`;
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
  if (typeof value !== "string" || !RUNTIME_BINDING_IDENTIFIER.test(value)) {
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

function parseRestrictedLeaseConsumeRequest(
  value: unknown,
): RestrictedLeaseConsumeRequest {
  try {
    if (
      !isRecord(value) ||
      types.isProxy(value) ||
      ![Object.prototype, null].includes(Object.getPrototypeOf(value))
    )
      throw new Error();
    const keys = Reflect.ownKeys(value);
    if (
      keys.length !== 2 ||
      !keys.includes("mode") ||
      !keys.includes("action_id")
    )
      throw new Error();
    const mode = Object.getOwnPropertyDescriptor(value, "mode");
    const action = Object.getOwnPropertyDescriptor(value, "action_id");
    if (
      !mode ||
      !("value" in mode) ||
      mode.value !== "restricted_allow_once" ||
      !action ||
      !("value" in action) ||
      typeof action.value !== "string" ||
      !LEASE_IDENTIFIER.test(action.value)
    )
      throw new Error();
    return Object.freeze({
      mode: "restricted_allow_once",
      action_id: action.value,
    });
  } catch {
    throw new OpenClawProductActivationError("consumption_request_invalid");
  }
}

function productActionId(event: Record<string, unknown>): string | undefined {
  if (event.pre_execution !== true || !isRecord(event.payload)) return;
  const payload = event.payload;
  let action: unknown;
  if (event.event_type === "tool_call_proposed") {
    action = isRecord(payload.tool) ? payload.tool.call_id : undefined;
  } else if (event.event_type === "memory_write_proposed") {
    action =
      payload.action_id ||
      (typeof event.event_id === "string"
        ? `act_${event.event_id}`
        : undefined);
  } else if (
    event.event_type === "message_send_proposed" &&
    typeof event.event_id === "string"
  ) {
    action = `act_${event.event_id}`;
  }
  return typeof action === "string" && LEASE_IDENTIFIER.test(action)
    ? action
    : undefined;
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
  if (decision !== "allow_once" && decision !== "deny" && decision !== null) {
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
  const [
    ,
    yearText,
    monthText,
    dayText,
    hourText,
    minuteText,
    secondText,
    fractionText = "",
    zoneText,
    signText,
    offsetHourText,
    offsetMinuteText,
  ] = match;
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
    offsetMinutes =
      (offsetHour * 60 + offsetMinute) * (signText === "+" ? 1 : -1);
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
