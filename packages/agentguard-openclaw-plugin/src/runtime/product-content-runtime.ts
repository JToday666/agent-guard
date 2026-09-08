import { snapshotProductNativeData } from "./product-native-stream.js";
import type {
  GuardEvent,
  GuardEvaluationResponse,
  JsonObject,
} from "../types.js";
import type {
  ProductActionClient,
  ProductResultCheckpoint,
  ProductActionRuntimeOptions,
} from "./product-action-runtime.js";
import type {
  OpenClawProductActionTicket,
  OpenClawProductReceiptOutbox,
} from "./product-receipt-outbox.js";
import { evaluationActivationAck } from "./product-authority-context.js";
import { restrictedCanonicalJson, restrictedDigest } from "./canonical.js";
import {
  buildProductContentCheckpoint,
  buildProductContentReceipt,
  assertProductContentAuthority,
} from "../mapping/product-content-receipts.js";
import {
  buildProductContextEvent,
  buildProductModelEvent,
  buildProductResultEvent,
  freezeProductModelInput,
  normalizeProductModelOutput,
  productContentText,
  productMemorySourceId,
} from "../mapping/product-content-events.js";
import {
  freezeProductValue,
  snapshotProductJson,
  readNativeProductFields,
  productActionError,
  type NativeProductToolCall,
  type OpenClawProductActionOrigin,
} from "../mapping/product-events.js";
import type {
  ProductContentBinding,
  ProductContextSource,
  ProductContextConsumer,
  ProductPreparedContext,
  FrozenNativeModelInput,
  PreparedNativeModelInput,
  OpaqueModelInvocationTicket,
  CompleteNativeModelOutcome,
  ApprovedNativeModelOutput,
  ProductNativeStreamHooks,
} from "./product-content-types.js";
export type {
  ProductContentBinding,
  ProductContextSource,
  ProductContextConsumer,
  ProductPreparedContext,
  FrozenNativeModelInput,
  PreparedNativeModelInput,
  OpaqueModelInvocationTicket,
  CompleteNativeModelOutcome,
  ApprovedNativeModelOutput,
  ProductNativeStreamHooks,
} from "./product-content-types.js";

export type ProductContentRuntimeOptions = Readonly<{
  client: ProductActionClient;
  binding: ProductContentBinding;
  tools: readonly unknown[];
  memoryNamespace: string;
  /** Starts the same B07 action session and encrypted outbox, not another session. */
  ensureStarted(): Promise<void>;
  consumeContext: ProductContextConsumer;
  verifyWirePayload(input: PreparedNativeModelInput, payload: unknown): void;
  maxAckAgeMs?: number;
}>;
type ModelState = {
  input: PreparedNativeModelInput;
  context: ProductPreparedContext;
  event: GuardEvent;
  evaluation: GuardEvaluationResponse;
  phase: "prepared" | "released" | "finished";
  ticket?: OpenClawProductActionTicket;
  verified: boolean;
};
type ModelOrigin = {
  modelOutputAuditId: string;
  modelSourceRef: string;
  call: Readonly<{ id: string; name: string; args: JsonObject }>;
  refs: readonly string[];
  consumed: boolean;
};
type ConfirmedResult = { message: unknown; source: ProductContextSource };
const WITHHELD = "Product native content withheld";

/** One trusted session, shared durable action journal, and no public activation switch. */
export class OpenClawProductContentRuntime implements ProductNativeStreamHooks {
  #options: ProductContentRuntimeOptions;
  #binding: ProductContentBinding;
  #tools: readonly unknown[];
  #outbox?: OpenClawProductReceiptOutbox;
  #start?: Promise<void>;
  #closed = false;
  #failed = false;
  #preparing = false;
  #active?: ModelState;
  #prepared = new WeakMap<object, ModelState>();
  #tickets = new WeakMap<object, ModelState>();
  #outputs: unknown[] = [];
  #results = new Map<string, ConfirmedResult>();
  #origin?: ModelOrigin;
  #callIds = new Set<string>();
  constructor(options: ProductContentRuntimeOptions) {
    if (
      !options ||
      typeof options.ensureStarted !== "function" ||
      typeof options.consumeContext !== "function" ||
      typeof options.verifyWirePayload !== "function" ||
      !options.client ||
      (options.maxAckAgeMs !== undefined &&
        (!Number.isSafeInteger(options.maxAckAgeMs) ||
          options.maxAckAgeMs < 1 ||
          options.maxAckAgeMs > 120000))
    )
      productActionError("native_composition_invalid");
    this.#binding = freezeProductValue(
      snapshotProductJson(options.binding),
    ) as ProductContentBinding;
    for (const key of [
      "agentId",
      "sessionKey",
      "taskId",
      "traceId",
      "provider",
      "modelId",
    ] as const)
      if (
        typeof this.#binding[key] !== "string" ||
        !this.#binding[key] ||
        this.#binding[key].length > 256
      )
        productActionError("native_composition_invalid");
    if (
      typeof this.#binding.userTask !== "string" ||
      !this.#binding.userTask ||
      typeof options.memoryNamespace !== "string" ||
      !options.memoryNamespace.startsWith("/")
    )
      productActionError("native_composition_invalid");
    this.#tools = freezeProductValue(
      snapshotProductJson(options.tools),
    ) as readonly unknown[];
    if (!Array.isArray(this.#tools) || this.#tools.length !== 8)
      productActionError("native_composition_invalid");
    this.#options = Object.freeze({ ...options });
  }
  toJSON(): object {
    return {
      type: "OpenClawProductContentRuntime",
      blocked: this.#failed || this.#closed,
    };
  }
  streamHooks(): ProductNativeStreamHooks {
    return Object.freeze({
      prepareInput: this.prepareInput.bind(this),
      verifyWirePayload: this.verifyWirePayload.bind(this),
      beginModelCall: this.beginModelCall.bind(this),
      finishModelCall: this.finishModelCall.bind(this),
      block: this.block.bind(this),
    });
  }
  async start(): Promise<void> {
    this.#check();
    this.#start ??= (async () => {
      await this.#options.ensureStarted();
      this.#check();
      this.#outbox = await this.#options.client.openProductDelivery();
      this.#check();
    })();
    try {
      await this.#start;
    } catch {
      this.block("start");
      this.#fail();
    }
  }
  close(): void {
    if (this.#closed) return;
    this.#closed = true;
    if (this.#active?.ticket) {
      try {
        this.#outbox?.markActionUnknown(this.#active.ticket);
      } catch {
        /* fixed breaker below */
      }
    }
    this.block("closed");
  }
  block(_code: string): void {
    this.#failed = true;
    this.#origin = undefined;
    try {
      this.#outbox?.tripActionBarrier();
    } catch {
      /* storage failure is never success */
    }
  }
  #fail(): never {
    return productActionError("native_content_blocked");
  }
  #check(): void {
    if (this.#failed || this.#closed || this.#outbox?.status().breakerOpen)
      this.#fail();
  }
  async #fresh(signal?: AbortSignal): Promise<void> {
    this.#check();
    if (signal?.aborted) this.#fail();
    await this.#options.client.snapshotProductAck();
    this.#check();
    if (signal?.aborted) this.#fail();
  }
  #authority(event: GuardEvent, evaluation: GuardEvaluationResponse): void {
    assertProductContentAuthority(event, evaluation);
    evaluationActivationAck(evaluation)!.assertFresh(
      Date.now(),
      this.#options.maxAckAgeMs ?? 120000,
    );
  }
  async #evaluate(
    event: GuardEvent,
    signal: AbortSignal,
  ): Promise<GuardEvaluationResponse> {
    await this.#fresh(signal);
    const { evaluation } =
      await this.#options.client.evaluateProductEvent(event);
    this.#check();
    if (signal.aborted) this.#fail();
    this.#authority(event, evaluation);
    return evaluation;
  }
  #sources(input: FrozenNativeModelInput): readonly ProductContextSource[] {
    const sources: ProductContextSource[] = [];
    if (input.systemPrompt)
      sources.push({
        source_id: "runtime:system",
        source_type: "runtime",
        source_trust: "unknown",
        role: "system",
        content: input.systemPrompt,
      });
    let taskSeen = false;
    for (const raw of input.messages) {
      const message = readNativeProductFields(raw);
      if (message.role === "user") {
        const text = userText(message.content);
        if (taskSeen || text !== this.#binding.userTask)
          productActionError("native_source_identity_invalid");
        taskSeen = true;
        sources.push({
          source_id: `user:${this.#binding.taskId}`,
          source_type: "user",
          source_trust: "trusted",
          role: "user",
          content: text,
        });
      } else if (message.role === "assistant") {
        if (
          !this.#outputs.some(
            (output) => nativeIdentity(output) === nativeIdentity(message),
          )
        )
          productActionError("native_source_identity_invalid");
        sources.push({
          source_id: `model:history:${sources.length}`,
          source_type: "model",
          source_trust: "unknown",
          role: "assistant",
          content: message.content,
        });
      } else if (message.role === "toolResult") {
        if (typeof message.toolCallId !== "string")
          productActionError("native_source_identity_invalid");
        const confirmed = this.#results.get(message.toolCallId);
        if (!confirmed) productActionError("native_source_identity_invalid");
        const incoming = toolMessageProjection(message);
        const expected = toolMessageProjection(confirmed.message);
        // Pinned normalizeMessagesForLlmBoundary unconditionally strips details.
        // The remaining Host content and native identity must match exactly.
        // If details are present they must still equal the confirmed original.
        if (!Object.hasOwn(incoming, "details")) delete expected.details;
        if (
          restrictedCanonicalJson(expected) !==
          restrictedCanonicalJson(incoming)
        )
          productActionError("native_source_identity_invalid");
        sources.push(confirmed.source);
      } else productActionError("native_source_identity_invalid");
    }
    if (!taskSeen) productActionError("native_source_identity_invalid");
    return freezeProductValue(sources);
  }
  async prepareInput(
    raw: FrozenNativeModelInput,
    signal: AbortSignal,
  ): Promise<PreparedNativeModelInput> {
    if (
      this.#preparing ||
      this.#active ||
      (this.#origin &&
        (!this.#origin.consumed || !this.#results.has(this.#origin.call.id)))
    ) {
      this.block("concurrent");
      this.#fail();
    }
    this.#preparing = true;
    try {
      await this.start();
      await this.#fresh(signal);
      this.#outbox!.assertReady();
      const observed = freezeProductModelInput(raw);
      if (
        observed.provider !== this.#binding.provider ||
        observed.modelId !== this.#binding.modelId ||
        restrictedCanonicalJson(observed.tools) !==
          restrictedCanonicalJson(this.#tools)
      )
        productActionError("native_model_identity_invalid");
      const sources = this.#sources(observed);
      const contextEvent = buildProductContextEvent(this.#binding, sources);
      const contextEvaluation = await this.#evaluate(contextEvent, signal);
      if (contextEvaluation.decision.decision !== "allow") {
        await this.#outbox!.submitCheckpoint(
          buildProductContentCheckpoint(contextEvent, contextEvaluation, false),
        );
        this.#fail();
      }
      let context: ProductPreparedContext;
      try {
        context = freezeProductValue(
          snapshotProductJson(
            this.#options.consumeContext(
              contextEvent,
              contextEvaluation,
              sources,
            ),
          ),
        ) as ProductPreparedContext;
      } catch {
        await this.#outbox!.submitCheckpoint(
          buildProductContentCheckpoint(contextEvent, contextEvaluation, false),
        );
        this.#fail();
      }
      const checkpoint = await this.#outbox!.submitCheckpoint(
        buildProductContentCheckpoint(contextEvent, contextEvaluation, true),
      );
      if (checkpoint.status !== "recorded") this.#fail();
      this.#check();
      const input = freezeProductModelInput({
        ...observed,
        systemPrompt: "",
        messages: context.messages,
      });
      const event = buildProductModelEvent(
        this.#binding,
        "input",
        { messages: input.messages, tools: input.tools },
        context,
      );
      const evaluation = await this.#evaluate(event, signal);
      if (evaluation.decision.decision !== "allow") {
        await this.#outbox!.submit(
          buildProductContentReceipt(event, evaluation, {
            accepted: false,
            status: "not_invoked",
            modelTerminal: true,
          }),
        );
        this.#fail();
      }
      const state: ModelState = {
        input,
        context,
        event,
        evaluation,
        phase: "prepared",
        verified: false,
      };
      this.#prepared.set(input, state);
      this.#active = state;
      return input;
    } catch {
      this.block("prepare");
      return this.#fail();
    } finally {
      this.#preparing = false;
    }
  }
  verifyWirePayload(input: PreparedNativeModelInput, payload: unknown): void {
    try {
      this.#check();
      const state = this.#prepared.get(input);
      if (
        !state ||
        state !== this.#active ||
        state.phase !== "prepared" ||
        state.verified
      )
        this.#fail();
      this.#authority(state.event, state.evaluation);
      this.#options.verifyWirePayload(
        input,
        snapshotProductNativeData(payload),
      );
      state.verified = true;
    } catch {
      this.block("wire");
      this.#fail();
    }
  }
  async beginModelCall(
    input: PreparedNativeModelInput,
    signal: AbortSignal,
  ): Promise<OpaqueModelInvocationTicket> {
    try {
      const state = this.#prepared.get(input);
      if (
        !state ||
        state !== this.#active ||
        state.phase !== "prepared" ||
        !state.verified
      )
        this.#fail();
      await this.#fresh(signal);
      this.#authority(state.event, state.evaluation);
      state.ticket = this.#outbox!.prepareAction({
        actionId: `act_${state.event.event_id}`,
        eventId: state.event.event_id,
        policyAuditId: state.evaluation.policy_audit_id!,
        decisionId: state.evaluation.decision.decision_id!,
        activationAck: evaluationActivationAck(state.evaluation)!,
      });
      this.#outbox!.releaseAction(state.ticket);
      state.phase = "released";
      const ticket = Object.freeze({});
      this.#tickets.set(ticket, state);
      return ticket;
    } catch {
      this.block("begin");
      return this.#fail();
    }
  }
  async finishModelCall(
    ticket: OpaqueModelInvocationTicket,
    raw: CompleteNativeModelOutcome,
    signal: AbortSignal,
  ): Promise<ApprovedNativeModelOutput> {
    const state = this.#tickets.get(ticket);
    if (!state || state.phase !== "released" || !state.ticket) {
      this.block("ticket");
      return this.#fail();
    }
    state.phase = "finished"; // single-flight, never mint another output on duplicate completion
    let completed = false,
      accepted = false,
      normalized: ReturnType<typeof normalizeProductModelOutput> | undefined;
    let outputEvent: GuardEvent | undefined,
      outputEvaluation: GuardEvaluationResponse | undefined;
    let terminalPersisted = false;
    try {
      const outcome = readNativeProductFields(snapshotProductNativeData(raw));
      if (outcome.status === "completed") {
        completed = true;
        normalized = normalizeProductModelOutput(outcome.message);
        const identity = readNativeProductFields(normalized.message);
        if (
          identity.provider !== this.#binding.provider ||
          identity.model !== this.#binding.modelId ||
          identity.api !== "openai-completions"
        )
          this.#fail();
        await this.#fresh(signal);
        outputEvent = buildProductModelEvent(
          this.#binding,
          "output",
          normalized.projection,
          state.context,
          state.evaluation.policy_audit_id!,
        );
        outputEvaluation = await this.#evaluate(outputEvent, signal);
        accepted = outputEvaluation.decision.decision === "allow";
        const checkpoint = await this.#outbox!.submitCheckpoint(
          buildProductContentCheckpoint(
            outputEvent,
            outputEvaluation,
            accepted,
          ),
        );
        accepted = accepted && checkpoint.status === "recorded";
      } else if (
        outcome.status !== "failed" ||
        Object.keys(outcome).length !== 1
      )
        productActionError("native_model_output_invalid");
      const delivery = await this.#outbox!.finishAction(
        state.ticket,
        buildProductContentReceipt(state.event, state.evaluation, {
          accepted,
          status: completed ? "executed" : "failed",
          modelTerminal: true,
        }),
      );
      terminalPersisted = true;
      if (
        !accepted ||
        delivery.status !== "recorded" ||
        !normalized ||
        !outputEvent ||
        !outputEvaluation
      )
        this.#fail();
      await this.#fresh(signal);
      this.#authority(outputEvent, outputEvaluation);
      if (normalized.call) {
        if (this.#callIds.has(normalized.call.id)) this.#fail();
        this.#callIds.add(normalized.call.id);
        this.#origin = {
          modelOutputAuditId: outputEvaluation.policy_audit_id!,
          modelSourceRef: `source:model:${outputEvent.event_id}`,
          call: normalized.call,
          refs: state.context.visibleSourceRefs,
          consumed: false,
        };
      } else this.#origin = undefined;
      if (this.#outputs.length >= 20) this.#fail();
      this.#outputs.push(normalized.message);
      return freezeProductValue({ message: normalized.message });
    } catch {
      if (!terminalPersisted) {
        try {
          await this.#outbox!.finishAction(
            state.ticket,
            buildProductContentReceipt(state.event, state.evaluation, {
              accepted: false,
              status: completed ? "executed" : "failed",
              modelTerminal: true,
            }),
          );
        } catch {
          try {
            this.#outbox!.markActionUnknown(state.ticket);
          } catch {
            /* durable breaker below */
          }
        }
      }
      this.block("finish");
      return this.#fail();
    } finally {
      if (this.#active === state) this.#active = undefined;
    }
  }
  async originProvider(
    call: NativeProductToolCall,
    signal: AbortSignal,
  ): Promise<OpenClawProductActionOrigin> {
    try {
      await this.#fresh(signal);
      const origin = this.#origin;
      if (
        !origin ||
        origin.consumed ||
        call.agentId !== this.#binding.agentId ||
        call.sessionKey !== this.#binding.sessionKey ||
        call.toolCallId !== origin.call.id ||
        call.toolName !== origin.call.name ||
        call.argumentsJson !== restrictedCanonicalJson(origin.call.args)
      )
        this.#fail();
      origin.consumed = true;
      return freezeProductValue({
        modelOutputAuditId: origin.modelOutputAuditId,
        modelSourceRef: origin.modelSourceRef,
        callId: call.toolCallId,
        runId: call.runId,
        argumentsDigest: restrictedDigest(origin.call.args),
        taskId: this.#binding.taskId,
        userTask: this.#binding.userTask,
        traceId: this.#binding.traceId,
        visibleSourceRefs: [
          ...new Set([origin.modelSourceRef, ...origin.refs]),
        ],
      });
    } catch {
      this.block("origin");
      return this.#fail();
    }
  }
  async resultCheckpoint(
    input: Parameters<ProductActionRuntimeOptions["resultCheckpoint"]>[0],
    signal: AbortSignal,
  ): Promise<ProductResultCheckpoint> {
    try {
      await this.#fresh(signal);
      const result = snapshotProductJson(input.result);
      const event = buildProductResultEvent(
        this.#binding,
        input.call,
        input.event,
        input.evaluation,
        result,
      );
      const evaluation = await this.#evaluate(event, signal);
      const accepted = evaluation.decision.decision === "allow";
      const delivery = await this.#outbox!.submitCheckpoint(
        buildProductContentCheckpoint(event, evaluation, accepted),
      );
      if (!accepted || delivery.status !== "recorded") this.#fail();
      await this.#fresh(signal);
      this.#authority(event, evaluation);
      const body = readNativeProductFields(result);
      if (!Array.isArray(body.content)) this.#fail();
      const message = freezeProductValue({
        role: "toolResult",
        toolCallId: input.call.toolCallId,
        toolName: input.call.toolName,
        content: body.content,
        details: body.details ?? {},
        isError: body.isError === true,
        timestamp: Date.now(),
      });
      let source: ProductContextSource = {
        source_id: `tool_result:${input.call.toolCallId}`,
        source_type: "tool_result",
        source_trust: "untrusted",
        role: "user",
        content: {
          tool_name: input.call.toolName,
          tool_call_id: input.call.toolCallId,
          content: body.content,
          details: body.details ?? {},
        },
      };
      if (input.call.toolName === "agentguard_memory_read") {
        const args = readNativeProductFields(
          JSON.parse(input.call.argumentsJson),
        );
        if (body.content.length !== 1) this.#fail();
        const first = readNativeProductFields(body.content[0]);
        if (first.type !== "text" || typeof first.text !== "string")
          this.#fail();
        const value = readNativeProductFields(JSON.parse(first.text));
        if (
          Object.keys(value).sort().join("|") !== "key|value" ||
          value.key !== args.key
        )
          this.#fail();
        source = {
          source_id: productMemorySourceId(
            this.#options.memoryNamespace,
            String(args.key),
          ),
          source_type: "memory",
          source_trust: "untrusted",
          role: "user",
          content: first.text,
        };
      }
      productContentText(source.content);
      if (this.#results.has(input.call.toolCallId) || this.#results.size >= 20)
        this.#fail();
      this.#results.set(input.call.toolCallId, {
        message,
        source: freezeProductValue(source),
      });
      this.#check();
      return { status: "recorded", message };
    } catch {
      this.block("result");
      return { status: "blocked" };
    }
  }
}
function userText(content: unknown): string {
  if (typeof content === "string") return content;
  if (Array.isArray(content) && content.length === 1) {
    const block = readNativeProductFields(content[0]);
    if (
      Object.keys(block).sort().join("|") === "text|type" &&
      block.type === "text" &&
      typeof block.text === "string"
    )
      return block.text;
  }
  return productActionError("native_source_identity_invalid");
}
function toolMessageProjection(raw: unknown): JsonObject {
  const message = readNativeProductFields(raw);
  if (
    Object.keys(message).some(
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
    productActionError("native_source_identity_invalid");
  const { timestamp: _timestamp, ...projection } = message;
  return projection;
}

function nativeIdentity(raw: unknown): string {
  return JSON.stringify(raw, (_key, value) => {
    if (value && typeof value === "object" && !Array.isArray(value))
      return Object.fromEntries(
        Object.keys(value)
          .sort()
          .map((key) => [key, value[key]]),
      );
    return value;
  });
}
