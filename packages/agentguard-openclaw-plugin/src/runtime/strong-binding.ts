import { createHash } from "node:crypto";

import {
  ExecutionLeaseConsumeError,
  GuardApiPermanentError,
  approvalEvidenceFromWait,
  type GuardApiClient,
} from "../guard-api-client.js";
import type { OutcomeApprovalEvidence } from "../mapping/audit-outcomes.js";
import type {
  EnforcementBinding,
  ExecutionLeaseReference,
  GuardEvaluationResponse,
  GuardEvent,
  JsonObject,
  RuntimeEnforcementEvidence,
} from "../types.js";

const AUTHORIZATION_FINGERPRINT = /^hmac-sha256:[0-9a-f]{64}$/u;
const RUNTIME_BINDING_IDENTIFIER = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,255}$/u;
const MAX_SNAPSHOT_DEPTH = 32;
const MAX_SNAPSHOT_NODES = 20_000;
const MAX_SNAPSHOT_BYTES = 1024 * 1024;

export type StrongApprovalGateResult =
  | {
      outcome: "released";
      approval: OutcomeApprovalEvidence;
      lease: ExecutionLeaseReference;
      enforcement: RuntimeEnforcementEvidence;
    }
  | {
      outcome: "blocked";
      approval: OutcomeApprovalEvidence | null;
      lease?: ExecutionLeaseReference;
      enforcement: RuntimeEnforcementEvidence;
    };

export function runtimeActionId(event: GuardEvent): string {
  if (
    (event.event_type === "tool_call_proposed" ||
      event.event_type === "tool_result_produced") &&
    "tool" in event.payload &&
    typeof event.payload.tool.call_id === "string" &&
    event.payload.tool.call_id.length > 0
  ) {
    return event.payload.tool.call_id;
  }
  if (
    event.event_type === "memory_write_proposed" &&
    "action_id" in event.payload &&
    typeof event.payload.action_id === "string" &&
    event.payload.action_id.length > 0
  ) {
    return event.payload.action_id;
  }
  return `act_${event.event_id}`;
}

export function validateStrongBinding(
  evaluation: GuardEvaluationResponse,
  event: GuardEvent,
  expectedRuntimeBindingId: string,
):
  | { ok: true; binding: EnforcementBinding }
  | { ok: false; enforcement: RuntimeEnforcementEvidence } {
  const binding = evaluation.enforcement_binding;
  if (!isValidBinding(binding)) {
    return {
      ok: false,
      enforcement: failedEvidence("rte-05:binding_invalid"),
    };
  }
  if (
    evaluation.decision.decision !== "ask" ||
    evaluation.approval === null ||
    binding.action_id !== runtimeActionId(event) ||
    !RUNTIME_BINDING_IDENTIFIER.test(expectedRuntimeBindingId) ||
    binding.runtime_binding_id !== expectedRuntimeBindingId
  ) {
    return {
      ok: false,
      enforcement: failedEvidence("rte-05:binding_mismatch"),
    };
  }
  return { ok: true, binding: { ...binding } };
}

export async function consumeStrongApproval(
  client: GuardApiClient,
  evaluation: GuardEvaluationResponse,
  binding: EnforcementBinding,
  deadlineMs: number,
  revalidateAction?: () => boolean,
): Promise<StrongApprovalGateResult> {
  const approvalId = evaluation.approval?.approval_id;
  if (!approvalId) {
    return {
      outcome: "blocked",
      approval: null,
      enforcement: failedEvidence("rte-05:binding_mismatch"),
    };
  }

  let wait;
  try {
    wait = await client.waitForApproval(approvalId, deadlineMs);
  } catch (error) {
    return {
      outcome: "blocked",
      approval: null,
      enforcement: waitFailureEvidence(error),
    };
  }
  const approval = approvalEvidenceFromWait(approvalId, wait);
  if (wait.status === "timeout") {
    return {
      outcome: "blocked",
      approval,
      enforcement: {
        gate_state: "timed_out",
        binding_check_status: "passed",
        lease_consume_outcome: "not_attempted",
        reason_codes: [
          "rte-05:binding_exact",
          "rte-05:approval_timed_out",
        ],
      },
    };
  }
  if (wait.status === "expired") {
    return {
      outcome: "blocked",
      approval,
      enforcement: {
        gate_state: "timed_out",
        binding_check_status: "passed",
        lease_consume_outcome: "not_attempted",
        reason_codes: ["rte-05:binding_exact", "rte-05:approval_expired"],
      },
    };
  }
  if (wait.status !== "resolved" || wait.decision !== "allow_once") {
    return {
      outcome: "blocked",
      approval,
      enforcement: {
        gate_state: "blocked",
        binding_check_status: "passed",
        lease_consume_outcome: "not_attempted",
        reason_codes: [
          "rte-05:binding_exact",
          "rte-05:approval_not_consumable",
        ],
      },
    };
  }
  if (wait.resolution_source !== "human") {
    return {
      outcome: "blocked",
      approval,
      enforcement: {
        gate_state: "binding_failed",
        binding_check_status: "passed",
        lease_consume_outcome: "not_attempted",
        reason_codes: [
          "rte-05:binding_exact",
          "rte-05:approval_not_human",
        ],
      },
    };
  }

  if (!revalidationPassed(revalidateAction)) {
    return {
      outcome: "blocked",
      approval,
      enforcement: failedEvidence("rte-05:binding_mismatch"),
    };
  }

  const current = evaluation.enforcement_binding;
  if (
    !isValidBinding(current) ||
    current.action_id !== binding.action_id ||
    current.authorization_fingerprint !== binding.authorization_fingerprint ||
    current.runtime_binding_id !== binding.runtime_binding_id
  ) {
    return {
      outcome: "blocked",
      approval,
      enforcement: failedEvidence("rte-05:binding_mismatch"),
    };
  }

  try {
    const lease = await client.consumeExecutionLease(
      approvalId,
      binding,
      deadlineMs,
    );
    if (
      !revalidationPassed(revalidateAction) ||
      !bindingStillExact(evaluation.enforcement_binding, binding)
    ) {
      return {
        outcome: "blocked",
        approval,
        lease,
        enforcement: postConsumeMismatchEvidence(),
      };
    }
    return {
      outcome: "released",
      approval,
      lease,
      enforcement: {
        gate_state: "approval_released",
        binding_check_status: "passed",
        lease_consume_outcome: "consumed",
        reason_codes: ["rte-05:binding_exact", "rte-05:lease_consumed"],
      },
    };
  } catch (error) {
    return {
      outcome: "blocked",
      approval,
      enforcement: consumeFailureEvidence(error),
    };
  }
}

/**
 * Deep-copy a mapped event before evaluate so later host mutation cannot alter
 * the authoritative event retained for receipts. The copy is deliberately
 * bounded and accepts JSON data only, matching the Guard API transport.
 */
export function snapshotGuardEvent(event: GuardEvent): GuardEvent {
  return JSON.parse(boundedStableJson(event)) as GuardEvent;
}

/** Return a detached copy that can be handed back to the host after release. */
export function snapshotToolParams(hostEvent: unknown): JsonObject {
  const params = plainRecord(hostEvent).params;
  return JSON.parse(boundedStableJson(plainRecord(params))) as JsonObject;
}

/**
 * Digest the actual host-controlled inputs, including the full outbound
 * message body (not its truncated GuardEvent preview). Generated event/action
 * IDs are deliberately excluded so message revalidation remains stable.
 * The digest is local to the hook stack and is never logged or persisted.
 */
export function strongHostInputSnapshot(
  hostEvent: unknown,
  hostContext: unknown,
  mappedEvent: GuardEvent,
): string {
  const eventRecord = plainRecord(hostEvent);
  const contextRecord = plainRecord(hostContext);
  const fullMessageInput =
    mappedEvent.event_type === "message_send_proposed"
      ? {
          to: eventRecord.to ?? null,
          content: eventRecord.content ?? null,
          attachments: eventRecord.attachments ?? null,
          media_urls: eventRecord.mediaUrls ?? null,
          reply_to_id: eventRecord.replyToId ?? null,
          thread_id: eventRecord.threadId ?? null,
          channel_id: contextRecord.channelId ?? null,
          account_id: contextRecord.accountId ?? null,
          conversation_id: contextRecord.conversationId ?? null,
          session_key: contextRecord.sessionKey ?? null,
          message_id: contextRecord.messageId ?? null,
          sender_id: contextRecord.senderId ?? null,
          metadata: eventRecord.metadata ?? null,
        }
      : null;
  const canonical = boundedStableJson({
    event_type: mappedEvent.event_type,
    runtime: mappedEvent.runtime,
    agent_id: mappedEvent.security_context.agent_id,
    task_id: mappedEvent.metadata.task_id ?? null,
    derived_paths: mappedEvent.security_context.derived_paths,
    payload: mappedEvent.payload,
    full_message_input: fullMessageInput,
  });
  return createHash("sha256").update(canonical).digest("hex");
}

export function capacityFailureEvidence(): RuntimeEnforcementEvidence {
  return {
    gate_state: "binding_failed",
    binding_check_status: "not_performed",
    lease_consume_outcome: "not_attempted",
    reason_codes: ["rte-05:correlation_capacity_exhausted"],
  };
}

export function correlationFailureEvidence(): RuntimeEnforcementEvidence {
  return failedEvidence("rte-05:binding_mismatch");
}

export function isStrongBindingDegraded(
  evidence: RuntimeEnforcementEvidence,
): boolean {
  return evidence.reason_codes.some((reason) =>
    [
      "rte-05:binding_invalid",
      "rte-05:binding_mismatch",
      "rte-05:lease_unavailable",
      "rte-05:lease_response_invalid",
      "rte-05:lease_consume_timed_out",
      "rte-05:correlation_capacity_exhausted",
    ].includes(reason),
  );
}

function isValidBinding(value: unknown): value is EnforcementBinding {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    return false;
  }
  const binding = value as Record<string, unknown>;
  const keys = Object.keys(binding).sort();
  const expected = [
    "action_id",
    "authorization_fingerprint",
    "requires_execution_lease",
    "runtime_binding_id",
    "schema_version",
  ];
  return (
    keys.length === expected.length &&
    keys.every((key, index) => key === expected[index]) &&
    binding.schema_version === "2.1" &&
    typeof binding.action_id === "string" &&
    binding.action_id.length > 0 &&
    typeof binding.authorization_fingerprint === "string" &&
    AUTHORIZATION_FINGERPRINT.test(binding.authorization_fingerprint) &&
    typeof binding.runtime_binding_id === "string" &&
    RUNTIME_BINDING_IDENTIFIER.test(binding.runtime_binding_id) &&
    binding.requires_execution_lease === true
  );
}

function failedEvidence(
  reason: "rte-05:binding_invalid" | "rte-05:binding_mismatch",
): RuntimeEnforcementEvidence {
  return {
    gate_state: "binding_failed",
    binding_check_status: "failed",
    lease_consume_outcome: "not_attempted",
    reason_codes: [reason],
  };
}

function postConsumeMismatchEvidence(): RuntimeEnforcementEvidence {
  return {
    gate_state: "binding_failed",
    binding_check_status: "failed",
    lease_consume_outcome: "consumed",
    reason_codes: ["rte-05:binding_mismatch", "rte-05:lease_consumed"],
  };
}

function revalidationPassed(revalidateAction?: () => boolean): boolean {
  try {
    return revalidateAction?.() ?? true;
  } catch {
    return false;
  }
}

function bindingStillExact(
  current: unknown,
  expected: EnforcementBinding,
): boolean {
  return (
    isValidBinding(current) &&
    current.action_id === expected.action_id &&
    current.authorization_fingerprint === expected.authorization_fingerprint &&
    current.runtime_binding_id === expected.runtime_binding_id
  );
}

function consumeFailureEvidence(error: unknown): RuntimeEnforcementEvidence {
  if (!(error instanceof ExecutionLeaseConsumeError)) {
    return {
      gate_state: "timed_out",
      binding_check_status: "passed",
      lease_consume_outcome: "unknown",
      reason_codes: [
        "rte-05:binding_exact",
        "rte-05:lease_consume_timed_out",
      ],
    };
  }

  const base = {
    gate_state: "binding_failed" as const,
    binding_check_status: "passed" as const,
  };
  switch (error.failure) {
    case "identity_denied":
      return {
        ...base,
        lease_consume_outcome: "rejected",
        reason_codes: ["rte-05:binding_exact", "rte-05:identity_denied"],
      };
    case "approval_not_found":
      return {
        ...base,
        lease_consume_outcome: "rejected",
        reason_codes: ["rte-05:binding_exact", "rte-05:approval_not_found"],
      };
    case "approval_not_consumable":
      return {
        ...base,
        lease_consume_outcome: "rejected",
        reason_codes: [
          "rte-05:binding_exact",
          "rte-05:approval_not_consumable",
        ],
      };
    case "consumption_conflict":
      return {
        gate_state: "binding_failed",
        binding_check_status: "failed",
        lease_consume_outcome: "rejected",
        reason_codes: [
          "rte-05:binding_mismatch",
          "rte-05:consumption_conflict",
        ],
      };
    case "approval_expired":
      return {
        ...base,
        lease_consume_outcome: "expired",
        reason_codes: ["rte-05:binding_exact", "rte-05:approval_expired"],
      };
    case "lease_expired":
      return {
        ...base,
        lease_consume_outcome: "expired",
        reason_codes: ["rte-05:binding_exact", "rte-05:lease_expired"],
      };
    case "lease_revoked":
      return {
        ...base,
        lease_consume_outcome: "revoked",
        reason_codes: ["rte-05:binding_exact", "rte-05:lease_revoked"],
      };
    case "invalid_response":
      return {
        ...base,
        lease_consume_outcome: "unknown",
        reason_codes: [
          "rte-05:binding_exact",
          "rte-05:lease_response_invalid",
        ],
      };
    case "timed_out":
      return {
        gate_state: "timed_out",
        binding_check_status: "passed",
        lease_consume_outcome: "unknown",
        reason_codes: [
          "rte-05:binding_exact",
          "rte-05:lease_consume_timed_out",
        ],
      };
    case "lease_unavailable":
      return {
        ...base,
        lease_consume_outcome: "unknown",
        reason_codes: ["rte-05:binding_exact", "rte-05:lease_unavailable"],
      };
    case "rejected":
      return {
        ...base,
        lease_consume_outcome: "rejected",
        reason_codes: ["rte-05:binding_exact", "rte-05:lease_rejected"],
      };
  }
}

function waitFailureEvidence(error: unknown): RuntimeEnforcementEvidence {
  if (error instanceof ExecutionLeaseConsumeError) {
    return consumeFailureEvidence(error);
  }
  if (error instanceof GuardApiPermanentError) {
    if (error.status === 403) {
      return {
        gate_state: "binding_failed",
        binding_check_status: "passed",
        lease_consume_outcome: "not_attempted",
        reason_codes: ["rte-05:binding_exact", "rte-05:identity_denied"],
      };
    }
    if (error.status === 404) {
      return {
        gate_state: "binding_failed",
        binding_check_status: "passed",
        lease_consume_outcome: "not_attempted",
        reason_codes: ["rte-05:binding_exact", "rte-05:approval_not_found"],
      };
    }
    if (error.status === 410) {
      return {
        gate_state: "timed_out",
        binding_check_status: "passed",
        lease_consume_outcome: "not_attempted",
        reason_codes: ["rte-05:binding_exact", "rte-05:approval_expired"],
      };
    }
  }
  return {
    gate_state: "binding_failed",
    binding_check_status: "passed",
    lease_consume_outcome: "not_attempted",
    reason_codes: ["rte-05:binding_exact", "rte-05:lease_response_invalid"],
  };
}

function boundedStableJson(value: unknown): string {
  const seen = new WeakSet<object>();
  let nodes = 0;
  let approximateBytes = 0;

  const charge = (text: string): void => {
    approximateBytes += Buffer.byteLength(text, "utf8");
    if (approximateBytes > MAX_SNAPSHOT_BYTES) {
      throw new Error("strong binding snapshot exceeds byte limit");
    }
  };

  const normalize = (item: unknown, depth: number): unknown => {
    nodes += 1;
    if (nodes > MAX_SNAPSHOT_NODES || depth > MAX_SNAPSHOT_DEPTH) {
      throw new Error("strong binding snapshot exceeds structural limits");
    }
    if (
      item === null ||
      typeof item === "string" ||
      typeof item === "boolean"
    ) {
      if (typeof item === "string") {
        charge(item);
      }
      return item;
    }
    if (typeof item === "number") {
      return Number.isFinite(item) ? item : null;
    }
    if (item === undefined) {
      return null;
    }
    if (
      typeof item === "bigint" ||
      typeof item === "function" ||
      typeof item === "symbol"
    ) {
      throw new Error("strong binding snapshot contains non-JSON input");
    }
    if (typeof item !== "object") {
      return null;
    }
    if (seen.has(item)) {
      throw new Error("strong binding snapshot contains a cycle");
    }
    seen.add(item);
    try {
      if (Array.isArray(item)) {
        return item.map((nested) => normalize(nested, depth + 1));
      }
      const record = item as Record<string, unknown>;
      return Object.fromEntries(
        Object.keys(record)
          .sort()
          .map((key) => {
            charge(key);
            return [key, normalize(record[key], depth + 1)];
          }),
      );
    } finally {
      seen.delete(item);
    }
  };

  const serialized = JSON.stringify(normalize(value, 0));
  if (Buffer.byteLength(serialized, "utf8") > MAX_SNAPSHOT_BYTES) {
    throw new Error("strong binding snapshot exceeds byte limit");
  }
  return serialized;
}

function plainRecord(value: unknown): Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : {};
}
