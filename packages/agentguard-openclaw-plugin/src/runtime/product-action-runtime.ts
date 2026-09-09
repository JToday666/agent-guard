import type { GuardApiClient } from "../guard-api-client.js";
import type {
  ApprovalWaitResponse,
  ExecutionLeaseReference,
  GuardEvaluationResponse,
  GuardEvent,
  JsonObject,
  RuntimeOutcomeReceipt,
  ToolHookResult,
} from "../types.js";
import {
  buildProductToolEvent,
  freezeProductValue,
  nativeProductCallKey,
  productActionError,
  productCanonicalActionId,
  readNativeProductAfter,
  readNativeProductFields,
  readNativeProductToolCall,
  snapshotProductJson,
  snapshotNativeProductResult,
  type NativeProductToolCall,
  type OpenClawProductActionOrigin,
  type OpenClawProductToolProfile,
} from "../mapping/product-events.js";
import {
  buildProductActionReceipt,
  type ProductReceiptOptions,
} from "../mapping/product-receipts.js";
import {
  consumptionActivationAck,
  evaluationActivationAck,
} from "./product-authority-context.js";
import { restrictedCanonicalJson, restrictedDigest } from "./canonical.js";
import type { ProductReceiptDeliveryResult } from "./product-delivery.js";
import type {
  OpenClawProductActionTicket,
  OpenClawProductReceiptOutbox,
} from "./product-receipt-outbox.js";

export type ProductActionClient = Pick<
  GuardApiClient,
  | "startProductSession"
  | "closeProductSession"
  | "snapshotProductAck"
  | "evaluateProductEvent"
  | "waitForApproval"
  | "consumeProductExecutionLease"
  | "openProductDelivery"
  | "closeProductDelivery"
>;
export type ProductResultCheckpoint = Readonly<{
  status: "recorded" | "blocked";
  /** A complete safe Host ToolResult message; only the trusted B08 boundary supplies it. */
  message?: unknown;
}>;
export type ProductMessageAuthorization = Pick<
  NativeProductToolCall,
  "runId" | "toolCallId" | "sessionKey" | "toolName" | "argumentsJson"
> &
  Readonly<{
    actionId: string;
    assertCanSend(): void;
    assertReadyToSend(): Promise<void>;
    onMessageDelivered(messageId: string): void;
  }>;
export type ProductActionRuntimeOptions = {
  client: ProductActionClient;
  observe: Parameters<GuardApiClient["startProductSession"]>[0];
  profile: OpenClawProductToolProfile;
  originProvider(
    call: NativeProductToolCall,
    signal: AbortSignal,
  ): Promise<OpenClawProductActionOrigin>;
  resultCheckpoint(
    input: Readonly<{
      call: NativeProductToolCall;
      event: GuardEvent;
      evaluation: GuardEvaluationResponse;
      result: unknown;
      terminalReceipt: RuntimeOutcomeReceipt;
    }>,
    signal: AbortSignal,
  ): Promise<ProductResultCheckpoint>;
  messageBridge?: {
    authorize(released: ProductMessageAuthorization): void;
    close(): void;
  };
  approvalTimeoutMs?: number;
  maxAckAgeMs?: number;
};
type Entry = {
  call: NativeProductToolCall;
  phase: "evaluating" | "blocked" | "released" | "terminal" | "unknown";
  event?: GuardEvent;
  evaluation?: GuardEvaluationResponse;
  lease?: ExecutionLeaseReference;
  approval?: {
    status: "allowed" | "denied" | "expired";
    decision: "allow_once" | "deny" | null;
  };
  ticket?: OpenClawProductActionTicket;
  afterDigest?: string;
  middlewareObserved?: boolean;
  middlewareDigest?: string;
  approvedAfterDigest?: string;
  approvedAfterFailed?: boolean;
  completion?: Promise<ProductReceiptDeliveryResult | undefined>;
  safeMessage?: unknown;
  persisted?: boolean;
  messageId?: string;
  consumeAttempted?: boolean;
};
const BLOCKED: ToolHookResult = Object.freeze({
  block: true,
  blockReason: "Product action withheld",
});
/** A partial or legacy Host composition cannot grant Product execution. */
export function assertOpenClawProductExecutionAvailable(): never {
  return productActionError("product_execution_unavailable");
}
/** Internal orchestration; the public Product factory verifies all registered consumers. */
export class OpenClawProductActionRuntime {
  #options: ProductActionRuntimeOptions;
  #profile: OpenClawProductToolProfile;
  #entries = new Map<string, Entry>();
  #nativeIds = new Map<string, string>();
  #outbox?: OpenClawProductReceiptOutbox;
  #start?: Promise<void>;
  #closed = false;
  #failed = false;
  #active?: string;
  #abort = new AbortController();
  constructor(options: ProductActionRuntimeOptions) {
    if (
      typeof options.originProvider !== "function" ||
      typeof options.resultCheckpoint !== "function" ||
      typeof options.observe !== "function" ||
      (options.approvalTimeoutMs !== undefined &&
        (!Number.isSafeInteger(options.approvalTimeoutMs) ||
          options.approvalTimeoutMs < 1 ||
          options.approvalTimeoutMs > 120000))
    )
      productActionError("native_composition_invalid");
    if (
      options.maxAckAgeMs !== undefined &&
      (!Number.isSafeInteger(options.maxAckAgeMs) ||
        options.maxAckAgeMs < 1 ||
        options.maxAckAgeMs > 120000)
    )
      productActionError("native_composition_invalid");
    this.#options = Object.freeze({ ...options });
    this.#profile = freezeProductValue(
      snapshotProductJson(options.profile),
    ) as OpenClawProductToolProfile;
  }
  start(): Promise<void> {
    if (this.#closed)
      return Promise.reject(new Error("product_runtime_closed"));
    if (!this.#start) this.#start = this.#startRuntime();
    return this.#start;
  }
  async #startRuntime(): Promise<void> {
    try {
      await this.#options.client.startProductSession(this.#options.observe);
      this.#checkOpen();
      this.#outbox = await this.#options.client.openProductDelivery();
      this.#checkOpen();
      this.#outbox.start();
    } catch {
      this.#failed = true;
      this.#options.client.closeProductSession();
      throw new Error("product_runtime_start_failed");
    }
  }
  async close(): Promise<void> {
    if (this.#closed) return;
    this.#closed = true;
    this.#abort.abort();
    this.#options.messageBridge?.close();
    for (const entry of this.#entries.values())
      if (entry.ticket && ["released", "evaluating"].includes(entry.phase))
        this.#unknown(entry);
    this.#options.client.closeProductSession();
    await this.#options.client.closeProductDelivery();
  }
  onRunEnd(runId: unknown): void {
    for (const entry of this.#entries.values())
      if (
        (typeof runId !== "string" || entry.call.runId === runId) &&
        ["released", "evaluating"].includes(entry.phase)
      )
        this.#unknown(entry);
  }
  async before(event: unknown, context: unknown): Promise<ToolHookResult> {
    let entry: Entry | undefined;
    try {
      this.#checkOpen();
      if (!this.#outbox) productActionError("product_runtime_not_started");
      this.#outbox.assertReady();
      const call = readNativeProductToolCall(event, context);
      const key = nativeProductCallKey(call);
      if (
        this.#active ||
        this.#entries.has(key) ||
        this.#nativeIds.has(call.toolCallId) ||
        this.#entries.size >= 10000
      )
        return BLOCKED;
      entry = { call, phase: "evaluating" };
      this.#entries.set(key, entry);
      this.#nativeIds.set(call.toolCallId, key);
      this.#active = key;
      const recheck = () => {
        this.#checkOpen();
        if (
          this.#active !== key ||
          restrictedCanonicalJson(readNativeProductToolCall(event, context)) !==
            restrictedCanonicalJson(call)
        )
          productActionError("native_identity_mismatch");
      };
      const origin = await this.#options.originProvider(
        call,
        this.#abort.signal,
      );
      recheck();
      entry.event = buildProductToolEvent(call, origin, this.#profile);
      const selected = await this.#options.client.evaluateProductEvent(
        entry.event,
      );
      entry.evaluation = selected.evaluation;
      recheck();
      if (evaluationActivationAck(entry.evaluation) !== selected.activationAck)
        productActionError("evaluation_ack_missing");
      const decision = entry.evaluation.decision.decision;
      if (decision === "deny") return await this.#deny(entry);
      if (decision === "ask") {
        if (
          entry.evaluation.approval_release_directive?.mode !==
            "restricted_allow_once" ||
          !entry.evaluation.approval
        )
          return await this.#deny(entry);
        const deadline =
          Date.now() + (this.#options.approvalTimeoutMs ?? 25000);
        const approval = await this.#options.client.waitForApproval(
          entry.evaluation.approval.approval_id,
          deadline,
        );
        recheck();
        entry.approval = approvalEvidence(approval);
        if (
          approval.status !== "resolved" ||
          approval.decision !== "allow_once" ||
          approval.resolution_source !== "human"
        )
          return await this.#deny(entry);
        entry.consumeAttempted = true;
        entry.lease = await this.#options.client.consumeProductExecutionLease(
          entry.evaluation,
          {
            mode: "restricted_allow_once",
            action_id: productCanonicalActionId(entry.event),
          },
          deadline,
        );
        recheck();
        if (Date.now() >= deadline)
          return await this.#deny(entry, "rte-05:lease_consume_timed_out");
        if (!Number.isFinite(Date.parse(entry.lease.expiresAt)))
          return await this.#deny(entry, "rte-05:lease_response_invalid");
        if (Date.parse(entry.lease.expiresAt) <= Date.now())
          return await this.#deny(entry, "rte-05:lease_expired");
      } else if (decision !== "allow")
        productActionError("official_response_mismatch");
      await this.#options.client.snapshotProductAck();
      recheck();
      if (entry.lease && Date.parse(entry.lease.expiresAt) <= Date.now())
        return await this.#deny(entry, "rte-05:lease_expired");
      const ack = entry.lease
        ? consumptionActivationAck(entry.evaluation)
        : evaluationActivationAck(entry.evaluation);
      if (!ack) productActionError("consumption_ack_missing");
      ack.assertFresh(Date.now(), this.#options.maxAckAgeMs ?? 120000);
      entry.ticket = this.#outbox.prepareAction({
        actionId: productCanonicalActionId(entry.event),
        eventId: entry.event.event_id,
        policyAuditId: entry.evaluation.policy_audit_id!,
        decisionId: entry.evaluation.decision.decision_id!,
        ...(entry.evaluation.approval
          ? { approvalId: entry.evaluation.approval.approval_id }
          : {}),
        ...(entry.lease
          ? {
              leaseId: entry.lease.leaseId,
              consumptionId: entry.lease.consumptionId,
            }
          : {}),
        activationAck: ack,
      });
      if (entry.lease) {
        const release = buildProductActionReceipt(
          entry.event,
          entry.evaluation,
          {
            kind: "approval_release",
            lease: entry.lease,
            approval: entry.approval,
          },
        );
        const delivery = await this.#outbox.submit(release);
        recheck();
        if (delivery.status !== "recorded") return await this.#deny(entry);
      }
      recheck();
      ack.assertFresh(Date.now(), this.#options.maxAckAgeMs ?? 120000);
      if (entry.lease && Date.parse(entry.lease.expiresAt) <= Date.now())
        return await this.#deny(entry, "rte-05:lease_expired");
      this.#outbox.releaseAction(entry.ticket);
      entry.phase = "released";
      if (call.toolName === "message") {
        if (!this.#options.messageBridge) return await this.#deny(entry);
        const current = entry;
        this.#options.messageBridge.authorize(
          Object.freeze({
            runId: call.runId,
            toolCallId: call.toolCallId,
            sessionKey: call.sessionKey,
            toolName: call.toolName,
            argumentsJson: call.argumentsJson,
            actionId: productCanonicalActionId(entry.event),
            assertCanSend: () => this.#assertCanSend(current),
            assertReadyToSend: async () => {
              this.#assertCanSend(current);
              try {
                await this.#options.client.snapshotProductAck();
                this.#assertCanSend(current);
              } catch {
                this.#trip();
                productActionError("native_send_unavailable");
              }
            },
            onMessageDelivered: (messageId: string) => {
              this.#assertCanSend(current);
              if (
                current.messageId ||
                typeof messageId !== "string" ||
                !/^fixture:[0-9a-f-]{36}$/u.test(messageId)
              )
                productActionError("native_message_identity_invalid");
              current.messageId = messageId;
            },
          }),
        );
      }
      recheck();
      return { params: JSON.parse(call.argumentsJson) };
    } catch {
      if (entry?.phase === "released") return await this.#deny(entry);
      if (entry?.evaluation && entry.event) return await this.#deny(entry);
      if (entry) entry.phase = "blocked";
      this.#trip();
      return BLOCKED;
    } finally {
      if (
        entry?.phase === "blocked" &&
        this.#active === nativeProductCallKey(entry.call)
      )
        this.#active = undefined;
    }
  }
  async #deny(
    entry: Entry,
    postConsumeFailure?: ProductReceiptOptions["postConsumeFailure"],
  ): Promise<ToolHookResult> {
    entry.phase = "blocked";
    if (this.#active === nativeProductCallKey(entry.call))
      this.#active = undefined;
    if (!entry.event || !entry.evaluation || !this.#outbox || this.#closed) {
      this.#trip();
      return BLOCKED;
    }
    try {
      const receipt = buildProductActionReceipt(entry.event, entry.evaluation, {
        kind: "pre_execution_deny",
        lease: entry.lease,
        approval: entry.approval,
        consumeAttempted: entry.consumeAttempted,
        postConsumeFailure,
      });
      const result = entry.ticket
        ? await this.#outbox.finishAction(entry.ticket, receipt)
        : await this.#outbox.submit(receipt);
      if (result.status !== "recorded") this.#trip();
    } catch {
      this.#trip();
    }
    return BLOCKED;
  }
  after(
    event: unknown,
    context: unknown,
  ): Promise<ProductReceiptDeliveryResult | undefined> {
    let entry: Entry | undefined;
    try {
      const call = readNativeProductToolCall(event, context);
      entry = this.#entries.get(nativeProductCallKey(call));
      if (!entry) {
        this.#trip();
        return Promise.resolve(undefined);
      }
      if (entry.phase === "blocked") return Promise.resolve(undefined);
      if (
        restrictedCanonicalJson(call) !== restrictedCanonicalJson(entry.call)
      ) {
        this.#unknown(entry);
        return Promise.resolve(undefined);
      }
      const terminal = readNativeProductAfter(event, entry.call.toolName);
      if (entry.middlewareObserved) {
        if (
          !entry.approvedAfterDigest ||
          entry.approvedAfterDigest !==
            restrictedDigest(terminal.result ?? null) ||
          entry.approvedAfterFailed !== terminal.failed
        )
          this.#trip();
        return entry.completion ?? Promise.resolve(undefined);
      }
      return this.#observeTerminal(entry, terminal, "after_tool_call");
    } catch {
      if (entry) this.#unknown(entry);
      else this.#trip();
      return Promise.resolve(undefined);
    }
  }
  #observeTerminal(
    entry: Entry,
    terminal: Readonly<{ failed: boolean; result: unknown }>,
    observation: "after_tool_call" | "native_tool_result_middleware",
  ): Promise<ProductReceiptDeliveryResult | undefined> {
    const call = entry.call;
    // A successful message envelope alone cannot prove the one local delivery.
    // Missing/mismatched confirmation preserves unknown effects and never re-sends.
    if (
      entry.call.toolName === "message" &&
      !messageDelivered(entry, terminal.result)
    ) {
      this.#unknown(entry);
      return Promise.resolve(undefined);
    }
    const digest = restrictedDigest({
      call,
      failed: terminal.failed,
      result: terminal.result ?? null,
    });
    if (entry.afterDigest) {
      if (entry.afterDigest !== digest) this.#trip();
      return entry.completion ?? Promise.resolve(undefined);
    }
    if (
      !entry.ticket ||
      !entry.event ||
      !entry.evaluation ||
      !["released", "unknown"].includes(entry.phase)
    ) {
      this.#unknown(entry);
      return Promise.resolve(undefined);
    }
    entry.afterDigest = digest;
    entry.phase = "terminal";
    const receipt = buildProductActionReceipt(entry.event, entry.evaluation, {
      observation,
      kind: terminal.failed ? "execution_failed" : "execution_completed",
      lease: entry.lease,
      approval: entry.approval,
      persisted: !terminal.failed && memoryWritten(entry.call, terminal.result),
    });
    // finishAction persists synchronously before its first HTTP await.
    const delivery = this.#outbox!.finishAction(entry.ticket, receipt);
    entry.completion = this.#finish(entry, terminal.result, receipt, delivery);
    return entry.completion;
  }

  /** This is the actual awaited postinvoke seam, before the Host after notification. */
  async observeToolResultMiddleware(
    event: unknown,
    context: unknown,
  ): Promise<{
    result: { content: unknown[]; details?: unknown; isError?: boolean };
  }> {
    let entry: Entry | undefined;
    try {
      const raw = readNativeProductFields(event),
        host = readNativeProductFields(context);
      if (
        host.runtime !== "openclaw" ||
        (host.harness !== undefined && host.harness !== "openclaw") ||
        typeof raw.toolCallId !== "string"
      )
        productActionError("native_result_identity_invalid");
      const key = this.#nativeIds.get(raw.toolCallId);
      entry = key ? this.#entries.get(key) : undefined;
      if (
        !entry ||
        raw.toolName !== entry.call.toolName ||
        restrictedCanonicalJson(snapshotProductJson(raw.args)) !==
          entry.call.argumentsJson
      )
        productActionError("native_result_identity_invalid");
      for (const field of ["agentId", "sessionKey", "runId"] as const)
        if (host[field] !== undefined && host[field] !== entry.call[field])
          productActionError("native_result_identity_invalid");
      if (raw.isError !== undefined && typeof raw.isError !== "boolean")
        productActionError("native_terminal_invalid");
      const result = readNativeProductFields(
        snapshotNativeProductResult(raw.result, entry.call.toolName),
      );
      if (
        !Array.isArray(result.content) ||
        result.content.length > 100 ||
        Buffer.byteLength(restrictedCanonicalJson(result)) > 64 * 1024 ||
        Object.keys(result).some(
          (k) => !["content", "details", "isError", "terminate"].includes(k),
        )
      )
        productActionError("native_terminal_invalid");
      for (const block of result.content) {
        const content = readNativeProductFields(block);
        if (
          Object.keys(content).sort().join("|") !== "text|type" ||
          content.type !== "text" ||
          typeof content.text !== "string" ||
          /(?:\[truncated\]|\[omitted\]|content truncated)/iu.test(content.text)
        )
          productActionError("native_terminal_invalid");
      }
      const terminal = readNativeProductAfter(
        {
          result: {
            ...result,
            isError: raw.isError === true || result.isError === true,
          },
        },
        entry.call.toolName,
      );
      const digest = restrictedDigest(terminal);
      if (entry.middlewareDigest && entry.middlewareDigest !== digest)
        productActionError("native_result_identity_invalid");
      entry.middlewareObserved = true;
      entry.middlewareDigest = digest;
      await this.#observeTerminal(
        entry,
        terminal,
        "native_tool_result_middleware",
      );
      this.#checkOpen();
      if (!entry.safeMessage) productActionError("native_result_unconfirmed");
      const safe = readNativeProductFields(entry.safeMessage);
      const returned = {
        content: safe.content as unknown[],
        ...(safe.details !== undefined ? { details: safe.details } : {}),
        isError: safe.isError === true,
      };
      const { sanitizeToolResult } =
        await import("openclaw/plugin-sdk/agent-harness");
      // Host finalize strips the isError flag out of result into its separate event field.
      const afterProjection = {
        content: returned.content,
        ...(returned.details !== undefined
          ? { details: returned.details }
          : {}),
      };
      const expectedAfter = snapshotProductJson(
        sanitizeToolResult(afterProjection),
      );
      entry.approvedAfterDigest = restrictedDigest(expectedAfter);
      entry.approvedAfterFailed = readNativeProductAfter(
        {
          result: expectedAfter,
          ...(returned.isError ? { error: "native_tool_failed" } : {}),
        },
        entry.call.toolName,
      ).failed;
      this.#checkOpen();
      return { result: freezeProductValue(returned) };
    } catch {
      if (entry && !entry.afterDigest) this.#unknown(entry);
      else this.#trip();
      return {
        result: {
          content: [{ type: "text", text: "Product result withheld" }],
          details: {},
          isError: true,
        },
      };
    }
  }
  async #finish(
    entry: Entry,
    result: unknown,
    receipt: RuntimeOutcomeReceipt,
    pending: Promise<ProductReceiptDeliveryResult>,
  ): Promise<ProductReceiptDeliveryResult | undefined> {
    try {
      const delivery = await pending;
      if (delivery.status !== "recorded") {
        this.#trip();
        return delivery;
      }
      this.#checkOpen();
      const checkpointResult = await this.#options.resultCheckpoint(
        Object.freeze({
          call: entry.call,
          event: entry.event!,
          evaluation: entry.evaluation!,
          result: freezeProductValue(result),
          terminalReceipt: receipt,
        }),
        this.#abort.signal,
      );
      this.#checkOpen();
      const checkpoint = readNativeProductFields(checkpointResult);
      if (checkpoint.status !== "recorded" || checkpoint.message === undefined)
        this.#trip();
      else {
        const message = snapshotProductJson(checkpoint.message) as JsonObject;
        if (
          !message ||
          message.role !== "toolResult" ||
          message.toolCallId !== entry.call.toolCallId ||
          message.toolName !== entry.call.toolName
        )
          productActionError("native_result_identity_invalid");
        entry.safeMessage = freezeProductValue(message);
      }
      return delivery;
    } catch {
      this.#trip();
      return undefined;
    } finally {
      if (this.#active === nativeProductCallKey(entry.call))
        this.#active = undefined;
    }
  }
  /** Synchronous Host persistence fence; B08 supplies the already-confirmed safe message. */
  resultForPersistence(event: unknown, context: unknown): { message: unknown } {
    let callId = "unknown";
    try {
      const raw = readNativeProductFields(event),
        host = readNativeProductFields(context);
      if (typeof raw.toolCallId !== "string") productActionError();
      callId = raw.toolCallId;
      const key = this.#nativeIds.get(callId),
        entry = key ? this.#entries.get(key) : undefined;
      this.#checkOpen();
      if (
        !entry ||
        host.agentId !== entry.call.agentId ||
        host.sessionKey !== entry.call.sessionKey ||
        host.toolName !== entry.call.toolName ||
        raw.toolName !== entry.call.toolName ||
        host.toolCallId !== callId ||
        entry.phase !== "terminal" ||
        entry.safeMessage === undefined ||
        entry.persisted
      )
        productActionError();
      if (
        entry.middlewareObserved &&
        restrictedCanonicalJson(messageProjection(raw.message)) !==
          restrictedCanonicalJson(messageProjection(entry.safeMessage))
      )
        productActionError("native_result_identity_invalid");
      entry.persisted = true;
      return { message: snapshotProductJson(entry.safeMessage) };
    } catch {
      this.#trip();
      return {
        message: {
          role: "toolResult",
          toolCallId: callId,
          toolName: "product_boundary",
          content: [{ type: "text", text: "Product result withheld" }],
          isError: true,
          timestamp: Date.now(),
        },
      };
    }
  }
  /** This hook has no native call identity. It can veto the one current permit;
   * the channel's private nonce proves correlation at actual dispatch. */
  messageSending(
    event: unknown,
    context: unknown,
  ): { cancel?: boolean; content?: string } {
    try {
      const e = readNativeProductFields(event);
      const c = readNativeProductFields(context);
      const entry = this.#active ? this.#entries.get(this.#active) : undefined;
      if (!entry || entry.call.toolName !== "message")
        productActionError("native_send_unavailable");
      this.#assertCanSend(entry);
      const args = JSON.parse(entry.call.argumentsJson) as JsonObject;
      if (
        e.to !== args.target ||
        e.content !== args.message ||
        c.channelId !== args.channel ||
        c.accountId !== "default"
      )
        productActionError("native_send_unavailable");
      return { content: args.message as string };
    } catch {
      this.#trip();
      return { cancel: true };
    }
  }
  #assertCanSend(entry: Entry): void {
    this.#checkOpen();
    const status = this.#outbox?.status();
    if (
      entry.phase !== "released" ||
      this.#active !== nativeProductCallKey(entry.call) ||
      !status ||
      status.breakerOpen ||
      status.pendingCount > 0
    )
      productActionError("native_send_unavailable");
    if (entry.lease && Date.parse(entry.lease.expiresAt) <= Date.now())
      productActionError("native_send_unavailable");
    if (!entry.evaluation) productActionError("native_send_unavailable");
    const ack = entry.lease
      ? consumptionActivationAck(entry.evaluation)
      : evaluationActivationAck(entry.evaluation);
    if (!ack) productActionError("native_send_unavailable");
    ack.assertFresh(Date.now(), this.#options.maxAckAgeMs ?? 120000);
  }
  #checkOpen(): void {
    if (this.#closed || this.#failed)
      productActionError("product_runtime_closed");
  }
  #trip(): void {
    this.#failed = true;
    try {
      this.#outbox?.tripActionBarrier();
    } catch {
      /* fixed in-memory cutoff remains closed */
    }
  }
  #unknown(entry: Entry): void {
    entry.phase = "unknown";
    try {
      if (entry.ticket) this.#outbox?.markActionUnknown(entry.ticket);
    } catch {
      /* retain the durable failure and never mint another ticket */
    }
    this.#trip();
  }
}
function approvalEvidence(value: ApprovalWaitResponse): Entry["approval"] {
  if (
    value.status === "resolved" &&
    value.decision === "allow_once" &&
    value.resolution_source === "human"
  )
    return { status: "allowed", decision: "allow_once" };
  if (value.status === "resolved" && value.decision === "deny")
    return { status: "denied", decision: "deny" };
  return { status: "expired", decision: null };
}
function memoryWritten(call: NativeProductToolCall, result: unknown): boolean {
  if (
    call.toolName !== "agentguard_memory_write" ||
    !result ||
    typeof result !== "object"
  )
    return false;
  const details = (result as JsonObject).details as JsonObject | undefined;
  return Boolean(
    details &&
    Object.keys(details).sort().join("|") === "entryId|written" &&
    details.entryId === (JSON.parse(call.argumentsJson) as JsonObject).key &&
    details.written === true,
  );
}

/** Pinned message.execute details, tied to the channel's actual inbox callback. */
function messageDelivered(entry: Entry, result: unknown): boolean {
  if (
    !entry.messageId ||
    !result ||
    typeof result !== "object" ||
    Array.isArray(result)
  )
    return false;
  const details = (result as JsonObject).details;
  if (!details || typeof details !== "object" || Array.isArray(details))
    return false;
  const d = details as JsonObject,
    sent = d.result;
  if (!sent || typeof sent !== "object" || Array.isArray(sent)) return false;
  const args = JSON.parse(entry.call.argumentsJson) as JsonObject;
  const delivery = sent as JsonObject;
  return (
    d.channel === args.channel &&
    d.to === args.target &&
    d.via === "direct" &&
    d.deliveryStatus === "sent" &&
    delivery.channel === args.channel &&
    delivery.chatId === args.target &&
    delivery.messageId === entry.messageId
  );
}

function messageProjection(raw: unknown): unknown {
  const value = readNativeProductFields(snapshotProductJson(raw));
  if (
    Object.keys(value).some(
      (k) =>
        ![
          "role",
          "toolCallId",
          "toolName",
          "content",
          "details",
          "isError",
          "timestamp",
        ].includes(k),
    )
  )
    productActionError("native_result_identity_invalid");
  const { timestamp: _timestamp, ...body } = value;
  return body;
}
