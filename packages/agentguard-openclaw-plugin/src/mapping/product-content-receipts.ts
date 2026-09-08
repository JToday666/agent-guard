import { inspect } from "node:util";
import type {
  GuardEvent,
  GuardEvaluationResponse,
  RuntimeOutcomeReceipt,
} from "../types.js";
import {
  attachRuntimeOutcomeActivationAck,
  evaluationActivationAck,
} from "../runtime/product-authority-context.js";
import {
  prepareProductReceipt,
  type ProductReceiptNamespace,
} from "../runtime/product-receipt-wire.js";
import { productActionError, freezeProductValue } from "./product-events.js";

export type ProductCheckpointRole =
  "context_assembled" | "model_output_produced" | "tool_result_produced";
const KEY = Symbol("product-content-checkpoint");
/** Opaque evidence-only object. The complete immutable receipt remains private. */
export class ProductContentCheckpoint {
  #receipt: RuntimeOutcomeReceipt;
  readonly role: ProductCheckpointRole;
  constructor(
    key: symbol,
    role: ProductCheckpointRole,
    receipt: RuntimeOutcomeReceipt,
  ) {
    if (key !== KEY) productActionError("native_checkpoint_invalid");
    this.role = role;
    this.#receipt = freezeProductValue(receipt);
    Object.freeze(this);
  }
  static read(
    value: unknown,
    namespace: ProductReceiptNamespace,
  ): { role: ProductCheckpointRole; wire: string } {
    if (typeof value !== "object" || value === null || !(#receipt in value))
      productActionError("native_checkpoint_invalid");
    return {
      role: value.role,
      wire: prepareProductReceipt(value.#receipt, namespace),
    };
  }
  toJSON(): object {
    return { type: "ProductContentCheckpoint", role: this.role };
  }
  [inspect.custom](): object {
    return this.toJSON();
  }
}

/** Validate official authority without promoting conservative ASK/DENY to ALLOW. */
export function assertProductContentAuthority(
  event: GuardEvent,
  evaluation: GuardEvaluationResponse,
): void {
  const ack = evaluationActivationAck(evaluation);
  const authority = evaluation.decision_authority;
  const directive = evaluation.approval_release_directive;
  if (
    !ack ||
    ack.identity.agent_id !== event.security_context.agent_id ||
    !evaluation.policy_audit_id ||
    !evaluation.decision.decision_id ||
    authority?.source !== "v21" ||
    authority.mode !== "active" ||
    authority.selection_basis !== "profile_all" ||
    authority.activation_ref_digest !== ack.identity.activation_ref_digest ||
    (evaluation.decision.decision === "allow" &&
      authority.legacy_floor_applied) ||
    !directive ||
    !["not_applicable", "forbidden"].includes(directive.mode) ||
    evaluation.approval != null ||
    evaluation.enforcement_binding != null
  )
    productActionError("native_content_authority_invalid");
}

export function buildProductContentReceipt(
  event: GuardEvent,
  evaluation: GuardEvaluationResponse,
  options: Readonly<{
    accepted: boolean;
    status: "not_invoked" | "executed" | "failed";
    modelTerminal?: boolean;
  }>,
): RuntimeOutcomeReceipt {
  assertProductContentAuthority(event, evaluation);
  if (
    options.accepted &&
    (evaluation.decision.decision !== "allow" || options.status !== "executed")
  )
    productActionError("native_content_receipt_invalid");
  if (options.modelTerminal !== (event.event_type === "model_input_prepared")) {
    if (options.modelTerminal || event.event_type === "model_input_prepared")
      productActionError("native_content_receipt_invalid");
  }
  const kind =
    options.status === "not_invoked"
      ? "pre_execution_deny"
      : options.status === "failed"
        ? "execution_failed"
        : options.accepted || options.modelTerminal
          ? "execution_completed"
          : "tool_result_quarantined";
  const timestamp = new Date().toISOString();
  const receipt: RuntimeOutcomeReceipt = {
    audit_id: `audit_outcome_${event.event_id}_${kind}`,
    schema_version: "0.4",
    record_type: "runtime_outcome",
    event_type: "runtime_outcome",
    runtime: "openclaw",
    trace_id: event.trace_id,
    case_id: event.case_id ?? null,
    is_malicious: event.is_malicious ?? null,
    timestamp,
    stage: options.modelTerminal
      ? "native_model_terminal"
      : `product_${event.event_type}`,
    summary: "Product native content evidence",
    reason: "Product native content boundary",
    decision: evaluation.decision.decision,
    risk_score: evaluation.decision.risk_score!,
    severity: evaluation.decision.severity as RuntimeOutcomeReceipt["severity"],
    blocked: evaluation.decision.decision !== "allow",
    resource_targets: [],
    rule_hits: (evaluation.decision.rule_hits ?? [])
      .slice(0, 100)
      .map((hit) => hit.rule_id),
    latency_ms: null,
    links: {
      event_id: event.event_id,
      decision_id: evaluation.decision.decision_id!,
      policy_audit_id: evaluation.policy_audit_id!,
      ...(["model_input_prepared", "model_output_produced"].includes(
        event.event_type,
      )
        ? { action_id: `act_${event.event_id}` }
        : {}),
      ...(event.event_type === "tool_result_produced"
        ? {
            action_id: (event.payload as { tool: { call_id: string } }).tool
              .call_id,
          }
        : {}),
    },
    metadata: { agent_id: event.security_context.agent_id, outcome_kind: kind },
    evidence: {
      intervention: {
        type: options.accepted ? "runtime_observation" : "content_isolation",
        reason: "Product content boundary",
      },
      execution: {
        status: options.status,
        receipt_recorded: true,
        invoked_at: null,
        completed_at: timestamp,
        error: options.status === "failed" ? "native_model_failed" : null,
        tool_result_entered_context: options.accepted ? null : false,
        persisted: options.accepted ? null : false,
      },
      side_effects: {
        measurement_status: "not_measured",
        count: null,
        summary: "External effects were not measured",
      },
      result: {
        disposition:
          options.status === "not_invoked" || options.status === "failed"
            ? "not_applicable"
            : options.accepted
              ? "passed_through"
              : "quarantined",
        summary: "Native content boundary completed",
        sanitized: options.accepted ? false : null,
      },
      approval: {
        approval_id: null,
        status: "not_required",
        decision: null,
        resolved_at: null,
      },
    },
  };
  attachRuntimeOutcomeActivationAck(receipt, evaluation);
  return receipt;
}
export function buildProductContentCheckpoint(
  event: GuardEvent,
  evaluation: GuardEvaluationResponse,
  accepted: boolean,
): ProductContentCheckpoint {
  if (
    ![
      "context_assembled",
      "model_output_produced",
      "tool_result_produced",
    ].includes(event.event_type)
  )
    productActionError("native_checkpoint_invalid");
  return new ProductContentCheckpoint(
    KEY,
    event.event_type as ProductCheckpointRole,
    buildProductContentReceipt(event, evaluation, {
      accepted,
      status:
        accepted || event.event_type !== "context_assembled"
          ? "executed"
          : "not_invoked",
    }),
  );
}
