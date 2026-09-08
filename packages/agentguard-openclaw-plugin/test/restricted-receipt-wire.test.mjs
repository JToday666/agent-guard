import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";
import { restrictedCanonicalJson } from "../dist/runtime/canonical.js";
import { readHistoricalProductReceiptWire } from "../dist/runtime/product-receipt-wire.js";

const fixture = () => JSON.parse(readFileSync(new URL("../../../tests/fixtures/runtime_enforcement/restricted_approval_release.json", import.meta.url), "utf8"));
const namespace = {runtime:"openclaw", agentId:"agent_rte_fixture", principalId:"fixture-restricted", runtimeBindingId:"binding:restricted:fixture"};
const read = (value) => readHistoricalProductReceiptWire(restrictedCanonicalJson(value), namespace);
const reject = (value) => assert.throws(() => read(value), (error) => error.code === "product_receipt_invalid" && !String(error).includes("hmac-sha256:"));

test("shared Core C1 receipt retains original historical ACK without invocation", () => {
  const value = fixture();
  const parsed = read(value);
  assert.equal(parsed.evidence.execution.invoked_at, null);
  assert.equal(parsed.evidence.enforcement.release_mode, "restricted_allow_once");
  assert.equal(parsed.evidence.enforcement.binding_check_status, "not_performed");
});
for (const [gate, reason] of [
  ["binding_failed", "v21:restricted_host_mismatch"],
  ["binding_failed", "rte-05:lease_expired"],
  ["binding_failed", "rte-05:lease_response_invalid"],
  ["timed_out", "rte-05:lease_consume_timed_out"],
]) test(`restricted postconsume deny: ${reason}`, () => {
  const value = fixture();
  value.metadata.outcome_kind = "pre_execution_deny";
  value.audit_id = `audit_outcome_${value.links.event_id}_pre_execution_deny`;
  value.evidence.execution.status = "not_invoked";
  value.evidence.result.disposition = "not_applicable";
  value.evidence.enforcement.gate_state = gate;
  value.evidence.enforcement.reason_codes.push(reason);
  read(value);
  value.evidence.enforcement.reason_codes = value.evidence.enforcement.reason_codes.filter((code) => code !== "rte-05:lease_consumed");
  reject(value);
});
for (const mutation of ["passed", "failed", "binding_exact", "no_marker", "no_mode", "null_mode", "strong_mode", "invocation", "no_ack", "langgraph", "no_lease", "no_action", "no_approval", "not_consumed", "not_allowed", "C3", "bad_released_reason"]) test(`restricted evidence rejects ${mutation}`, () => {
  const value = fixture();
  const e = value.evidence.enforcement;
  if (["passed", "failed"].includes(mutation)) e.binding_check_status = mutation;
  if (mutation === "binding_exact") e.reason_codes.push("rte-05:binding_exact");
  if (mutation === "no_marker") e.reason_codes.shift();
  if (mutation === "no_mode") delete e.release_mode;
  if (mutation === "null_mode") e.release_mode = null;
  if (mutation === "strong_mode") e.release_mode = "strong_binding";
  if (mutation === "invocation") value.evidence.execution.invoked_at = value.timestamp;
  if (mutation === "no_ack") delete value.metadata.activation_ack;
  if (mutation === "langgraph") value.runtime = "langgraph";
  if (mutation === "no_lease") delete value.links.lease_id;
  if (mutation === "no_action") delete value.links.action_id;
  if (mutation === "no_approval") delete value.links.approval_id;
  if (mutation === "not_consumed") e.lease_consume_outcome = "not_attempted";
  if (mutation === "not_allowed") Object.assign(value.evidence.approval, {status:"denied", decision:"deny"});
  if (mutation === "C3") e.C3 = true;
  if (mutation === "bad_released_reason") e.reason_codes.push("rte-05:lease_expired");
  reject(value);
});
for (const [kind, status] of [["execution_completed", "executed"], ["execution_failed", "failed"]]) test(`restricted actual after terminal: ${kind}`, () => {
  const value = fixture();
  value.metadata.outcome_kind = kind;
  value.audit_id = `audit_outcome_${value.links.event_id}_${kind}`;
  Object.assign(value.evidence.execution, {status, error: status === "failed" ? "host_failure" : null});
  value.evidence.result.disposition = status === "executed" ? "passed_through" : "unknown";
  read(value);
  value.evidence.execution.invoked_at = value.timestamp;
  reject(value);
});
