import type { GuardEvent, GuardEvaluationResponse } from "../types.js";

/** These values are provisioned by the one-session trusted assembly. */
export type ProductContentBinding = Readonly<{
  agentId: string;
  sessionKey: string;
  taskId: string;
  userTask: string;
  traceId: string;
  provider: string;
  modelId: string;
}>;
export type ProductContextSource = Readonly<{
  source_id: string;
  source_type: string;
  source_trust: string;
  role: string;
  content: unknown;
  name?: string;
}>;
export type FrozenNativeModelInput = Readonly<{
  provider: string;
  modelId: string;
  systemPrompt: string;
  messages: readonly unknown[];
  tools: readonly unknown[];
}>;
export type PreparedNativeModelInput = FrozenNativeModelInput;
export type OpaqueModelInvocationTicket = object;
export type CompleteNativeModelOutcome =
  | Readonly<{ status: "completed"; message: unknown }>
  | Readonly<{ status: "failed" }>;
export type ApprovedNativeModelOutput = Readonly<{ message: unknown }>;
export type ProductNativeStreamHooks = Readonly<{
  prepareInput(
    input: FrozenNativeModelInput,
    signal: AbortSignal,
  ): Promise<PreparedNativeModelInput>;
  verifyWirePayload(input: PreparedNativeModelInput, payload: unknown): void;
  beginModelCall(
    input: PreparedNativeModelInput,
    signal: AbortSignal,
  ): Promise<OpaqueModelInvocationTicket>;
  finishModelCall(
    ticket: OpaqueModelInvocationTicket,
    outcome: CompleteNativeModelOutcome,
    signal: AbortSignal,
  ): Promise<ApprovedNativeModelOutput>;
  block(code: string): void;
}>;
export type ProductPreparedContext = Readonly<{
  messages: readonly unknown[];
  planId: string;
  planDigest: string;
  contextRef: string;
  visibleSourceRefs: readonly string[];
}>;
export type ProductContextConsumer = (
  event: GuardEvent,
  evaluation: GuardEvaluationResponse,
  sources: readonly ProductContextSource[],
) => ProductPreparedContext;
