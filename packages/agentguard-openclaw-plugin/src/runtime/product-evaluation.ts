import type { GuardEvaluationResponse } from "../types.js";
import type { OpenClawActivationAckHandle } from "./activation-ack-handle.js";
import { restrictedCanonicalJson } from "./canonical.js";
import { OpenClawProductActivationError } from "./product-manifest.js";

const RESIDUALS = [
  "openclaw_has_no_authoritative_invocation_start_hook",
  "openclaw_hook_cannot_atomically_replace_and_seal_final_action",
  "openclaw_message_sending_host_exception_or_timeout_can_fail_open",
  "openclaw_non_tool_memory_write_has_no_native_pre_execution_hook",
  "openclaw_sync_persistence_hooks_cannot_await_remote_decision_or_rollback",
];
const AUTHORITY_KEYS = [
  "source",
  "mode",
  "selection_basis",
  "matched_path_ids",
  "legacy_floor_applied",
  "activation_ref_digest",
  "approval_release",
];
const DIRECTIVE_KEYS = [
  "schema_version",
  "mode",
  "required_runtime_profile",
  "human_only",
  "single_use",
  "action_binding",
  "receipt_requirement",
  "activation_ref_digest",
  "scope_digest",
  "capability_digest",
  "residual_boundaries",
];
const IDENTIFIER = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,255}$/u;

/** A Product response must prove exact official authority; no compatibility fallback. */
export function readOpenClawProductEvaluation(
  value: unknown,
  ack: OpenClawActivationAckHandle,
): GuardEvaluationResponse {
  try {
    const response = object(value);
    const decision = object(response.decision);
    const authority = exactObject(response.decision_authority, AUTHORITY_KEYS);
    const directive = exactObject(
      response.approval_release_directive,
      DIRECTIVE_KEYS,
    );
    if (
      !identifier(decision.decision_id) ||
      !identifier(response.policy_audit_id) ||
      typeof decision.decision !== "string" ||
      !["allow", "deny", "ask"].includes(decision.decision) ||
      !Number.isInteger(decision.risk_score) ||
      Number(decision.risk_score) < 0 ||
      Number(decision.risk_score) > 100 ||
      typeof decision.severity !== "string" ||
      !["low", "medium", "high", "critical"].includes(decision.severity) ||
      typeof decision.reason !== "string" ||
      !Array.isArray(decision.rule_hits)
    )
      fail();
    for (const key of [
      "approval",
      "policy_audit_id",
      "decision_authority",
      "approval_release_directive",
      "enforcement_binding",
      "context_plan",
    ]) {
      if (
        Object.hasOwn(decision, key) &&
        (!Object.hasOwn(response, key) ||
          restrictedCanonicalJson(decision[key]) !==
            restrictedCanonicalJson(response[key]))
      )
        fail();
    }
    if (
      authority.source !== "v21" ||
      authority.mode !== "active" ||
      authority.selection_basis !== "profile_all" ||
      authority.legacy_floor_applied !== false ||
      !Array.isArray(authority.matched_path_ids) ||
      authority.matched_path_ids.length !== 0 ||
      authority.activation_ref_digest !== ack.identity.activation_ref_digest ||
      directive.activation_ref_digest !== ack.identity.activation_ref_digest ||
      directive.capability_digest !== ack.identity.capability_digest ||
      directive.schema_version !== "2.0" ||
      directive.human_only !== true ||
      directive.single_use !== true ||
      typeof directive.mode !== "string" ||
      typeof directive.scope_digest !== "string" ||
      !/^(?:sha256|hmac-sha256):[0-9a-f]{64}$/u.test(directive.scope_digest)
    )
      fail();
    const restricted = directive.mode === "restricted_allow_once";
    if (restricted) {
      if (
        directive.required_runtime_profile !== "C1" ||
        directive.action_binding !== "best_effort_host" ||
        directive.receipt_requirement !== "required_durable" ||
        restrictedCanonicalJson(directive.residual_boundaries) !==
          restrictedCanonicalJson(RESIDUALS)
      )
        fail();
    } else if (
      !["not_applicable", "forbidden"].includes(String(directive.mode)) ||
      directive.required_runtime_profile !== null ||
      directive.action_binding !== "none" ||
      directive.receipt_requirement !== "not_applicable" ||
      !Array.isArray(directive.residual_boundaries) ||
      directive.residual_boundaries.length !== 0
    )
      fail();
    if (
      authority.approval_release !==
      (directive.mode === "not_applicable" ? "not_applicable" : "forbidden")
    )
      fail();
    if (decision.decision === "ask") {
      if (restricted) {
        const approval = object(response.approval);
        if (
          !identifier(approval.approval_id) ||
          typeof approval.status !== "string" ||
          !["pending", "resolved", "expired"].includes(approval.status) ||
          !Array.isArray(approval.decision_options) ||
          approval.decision_options.length !== 2 ||
          !approval.decision_options.includes("allow_once") ||
          !approval.decision_options.includes("deny")
        )
          fail();
      } else if (
        !["not_applicable", "forbidden"].includes(String(directive.mode)) ||
        response.approval !== null
      )
        fail();
    } else if (
      directive.mode !== "not_applicable" ||
      response.approval !== null
    )
      fail();
    if (
      response.enforcement_binding !== undefined &&
      response.enforcement_binding !== null
    ) {
      const binding = exactObject(response.enforcement_binding, [
        "schema_version",
        "action_id",
        "authorization_fingerprint",
        "runtime_binding_id",
        "requires_execution_lease",
      ]);
      if (
        !restricted ||
        binding.schema_version !== "2.1" ||
        !identifier(binding.action_id) ||
        typeof binding.authorization_fingerprint !== "string" ||
        !/^hmac-sha256:[0-9a-f]{64}$/u.test(
          binding.authorization_fingerprint,
        ) ||
        binding.runtime_binding_id !== ack.identity.runtime_binding_id ||
        binding.requires_execution_lease !== true
      )
        fail();
    }
    // Freeze server authority and the decision identity before correlation aliases exist.
    return deepFreeze(response) as unknown as GuardEvaluationResponse;
  } catch {
    fail();
  }
}

function object(value: unknown): Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value))
    fail();
  return value as Record<string, unknown>;
}
function exactObject(value: unknown, keys: string[]): Record<string, unknown> {
  const candidate = object(value);
  if (
    Object.keys(candidate).length !== keys.length ||
    keys.some((key) => !Object.hasOwn(candidate, key))
  )
    fail();
  return candidate;
}
function identifier(value: unknown): boolean {
  return typeof value === "string" && IDENTIFIER.test(value);
}
function deepFreeze<T>(value: T): T {
  if (typeof value === "object" && value !== null && !Object.isFrozen(value)) {
    Object.freeze(value);
    for (const item of Object.values(value)) deepFreeze(item);
  }
  return value;
}
function fail(): never {
  throw new OpenClawProductActivationError("official_response_mismatch");
}
