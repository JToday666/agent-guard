import type {
  ExecutionLeaseReference,
  GuardEvaluationResponse,
  GuardEvent,
  RuntimeEnforcementEvidence,
  RuntimeOutcomeReceipt,
} from "../types.js";
import { attachRuntimeOutcomeActivationAck } from "../runtime/product-authority-context.js";
import { productCanonicalActionId } from "./product-events.js";

export type ProductReceiptOptions = {
  observation?: "after_tool_call" | "native_tool_result_middleware";
  kind:
    | "pre_execution_deny"
    | "approval_release"
    | "execution_completed"
    | "execution_failed";
  lease?: ExecutionLeaseReference;
  approval?: {
    status: "allowed" | "denied" | "expired";
    decision: "allow_once" | "deny" | null;
  };
  consumeAttempted?: boolean;
  postConsumeFailure?:
    | "v21:restricted_host_mismatch"
    | "rte-05:lease_expired"
    | "rte-05:lease_response_invalid"
    | "rte-05:lease_consume_timed_out";
  persisted?: boolean;
  timestamp?: string;
};
/** Honest gate/after evidence; never an invocation-start or public C3 binding. */
export function buildProductActionReceipt(
  event: GuardEvent,
  evaluation: GuardEvaluationResponse,
  options: ProductReceiptOptions,
): RuntimeOutcomeReceipt {
  const deny = options.kind === "pre_execution_deny";
  const released = options.kind === "approval_release";
  const failed = options.kind === "execution_failed";
  const timestamp = options.timestamp ?? new Date().toISOString();
  const lease = options.lease;
  // The original memory-write acknowledgement was observed, not admitted to
  // model context. Content checkpointing remains a separate required boundary.
  const memoryWriteConfirmed =
    options.kind === "execution_completed" &&
    options.persisted === true &&
    event.event_type === "memory_write_proposed";
  const approvalId = evaluation.approval?.approval_id;
  const restricted =
    evaluation.approval_release_directive?.mode === "restricted_allow_once";
  let enforcement: RuntimeEnforcementEvidence | undefined;
  if (restricted) {
    enforcement = {
      release_mode: "restricted_allow_once",
      gate_state: lease
        ? deny
          ? options.postConsumeFailure === "rte-05:lease_consume_timed_out"
            ? "timed_out"
            : "binding_failed"
          : "approval_released"
        : "blocked",
      binding_check_status: "not_performed",
      lease_consume_outcome: lease
        ? "consumed"
        : options.consumeAttempted
          ? "unknown"
          : "not_attempted",
      reason_codes: lease
        ? deny
          ? [
              "v21:restricted_allow_once",
              options.postConsumeFailure ?? "v21:restricted_host_mismatch",
              "rte-05:lease_consumed",
            ]
          : ["v21:restricted_allow_once", "rte-05:lease_consumed"]
        : [
            "v21:restricted_allow_once",
            options.consumeAttempted
              ? "rte-05:lease_unavailable"
              : "rte-05:approval_not_consumable",
          ],
    };
  }
  const receipt: RuntimeOutcomeReceipt = {
    audit_id: `audit_outcome_${event.event_id}_${options.kind}`,
    schema_version: "0.4",
    record_type: "runtime_outcome",
    event_type: "runtime_outcome",
    runtime: "openclaw",
    trace_id: event.trace_id,
    case_id: event.case_id ?? null,
    is_malicious: event.is_malicious ?? null,
    timestamp,
    stage: released
      ? "product_gate_released"
      : deny
        ? "product_gate_blocked"
        : (options.observation ?? "after_tool_call"),
    summary: released
      ? "Product gate release recorded"
      : deny
        ? "Product action withheld"
        : "Native tool terminal observed",
    decision: evaluation.decision.decision,
    risk_score: evaluation.decision.risk_score!,
    severity: evaluation.decision.severity as RuntimeOutcomeReceipt["severity"],
    blocked: evaluation.decision.decision !== "allow",
    reason: "Product runtime action evidence",
    resource_targets: [...event.security_context.derived_paths],
    rule_hits: (evaluation.decision.rule_hits ?? [])
      .slice(0, 100)
      .map((hit) => hit.rule_id),
    latency_ms: null,
    links: {
      event_id: event.event_id,
      decision_id: evaluation.decision.decision_id!,
      policy_audit_id: evaluation.policy_audit_id!,
      action_id: productCanonicalActionId(event),
      ...(approvalId ? { approval_id: approvalId } : {}),
      ...(lease
        ? { lease_id: lease.leaseId, consumption_id: lease.consumptionId }
        : {}),
    },
    metadata: {
      agent_id: event.security_context.agent_id,
      outcome_kind: options.kind,
    },
    evidence: {
      intervention: {
        type: released
          ? "approval_gate"
          : deny
            ? "pre_execution_deny"
            : "runtime_observation",
        reason: "Product runtime action evidence",
      },
      execution: {
        status: deny
          ? "not_invoked"
          : released
            ? "unknown"
            : failed
              ? "failed"
              : "executed",
        receipt_recorded: true,
        invoked_at: null,
        completed_at: timestamp,
        error: failed ? "native_tool_failed" : null,
        tool_result_entered_context: deny ? false : null,
        persisted: deny ? false : options.persisted === true ? true : null,
      },
      side_effects: {
        measurement_status: deny ? "measured" : "not_measured",
        count: deny ? 0 : null,
        summary: deny
          ? "Action was withheld"
          : "External side effects were not measured",
      },
      result: {
        disposition:
          deny || failed
            ? "not_applicable"
            : memoryWriteConfirmed
              ? "passed_through"
              : "unknown",
        summary: memoryWriteConfirmed
          ? "Native SQLite write acknowledgement observed without modification"
          : null,
        sanitized: deny || memoryWriteConfirmed ? false : null,
      },
      approval: {
        approval_id: approvalId ?? null,
        status:
          options.approval?.status ?? (approvalId ? "unknown" : "not_required"),
        decision: options.approval?.decision ?? null,
        resolved_at: null,
      },
      ...(enforcement ? { enforcement } : {}),
    },
  };
  attachRuntimeOutcomeActivationAck(receipt, evaluation);
  return receipt;
}
