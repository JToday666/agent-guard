import { readFileSync } from "node:fs";
import { inspect } from "node:util";
import { readOpenClawActivationAckHandle } from "../../dist/runtime/activation-ack-handle.js";
import {
  attachRuntimeOutcomeActivationAck,
  bindEvaluationActivationAck,
} from "../../dist/runtime/product-authority-context.js";

export const TOKEN = `hmac-sha256:${"a".repeat(64)}`;
export const NS = Object.freeze({
  runtime: "openclaw",
  agentId: "agent_rte_fixture",
  principalId: "principal:outbox:test",
  runtimeBindingId: "binding:outbox:test",
});
const IDENTITY = Object.freeze({
  runtime_version: "2026.7.1-2",
  plugin_version: "0.1.0-rc.1",
  agent_id: NS.agentId,
  runtime_binding_id: NS.runtimeBindingId,
  profile_id: "agentguard-openclaw-v2-restricted",
  ...Object.fromEntries(
    [
      "activation_ref_digest",
      "capability_digest",
      "host_inventory_digest",
      "plugin_inventory_digest",
      "plugin_order_inventory_digest",
      "tool_inventory_digest",
    ].map((key, i) => [key, `sha256:${String(i + 1).repeat(64)}`]),
  ),
});
export function handle(token = TOKEN) {
  return readOpenClawActivationAckHandle(
    {
      schema_version: "1.0",
      runtime: "openclaw",
      ...IDENTITY,
      issued_at: "2026-08-15T07:59:00.000000001Z",
      expires_at: "2026-08-15T08:01:00.000000001Z",
      ack_token: token,
    },
    IDENTITY,
    { nowMs: Date.parse("2026-08-15T08:00:00Z") },
  );
}
export function fixture(
  kind = "execution_completed",
  name = "one",
  ack = handle(),
  editReceipt,
) {
  const receipt = JSON.parse(
    readFileSync(
      new URL(
        `../../../../tests/fixtures/runtime_enforcement/${kind}.json`,
        import.meta.url,
      ),
      "utf8",
    ),
  );
  receipt.runtime = "openclaw";
  receipt.links.event_id = `event_${name}`;
  receipt.links.action_id = `action_${name}`;
  receipt.links.decision_id = `decision_${name}`;
  receipt.links.policy_audit_id = `policy_${name}`;
  receipt.audit_id = `audit_outcome_event_${name}_${kind}`;
  editReceipt?.(receipt);
  const evaluation = {};
  bindEvaluationActivationAck(evaluation, ack);
  attachRuntimeOutcomeActivationAck(receipt, evaluation);
  return receipt;
}
export function preparation(receipt, ack = handle()) {
  return {
    actionId: receipt.links.action_id,
    eventId: receipt.links.event_id,
    policyAuditId: receipt.links.policy_audit_id,
    decisionId: receipt.links.decision_id,
    ...(receipt.links.approval_id
      ? { approvalId: receipt.links.approval_id }
      : {}),
    activationAck: ack,
  };
}
export function ok(wire) {
  return {
    status: "recorded",
    auditId: JSON.parse(wire).audit_id,
    httpStatus: 200,
  };
}
export function deferred() {
  let resolve;
  const promise = new Promise((r) => {
    resolve = r;
  });
  return { promise, resolve };
}
export function rejects(code) {
  return (error) => error.code === code && !inspect(error).includes(TOKEN);
}
