import type { RuntimeOutcomeReceipt } from "../types.js";
import { restrictedCanonicalJson } from "./canonical.js";
import {
  readHistoricalOpenClawActivationAck,
  rfc3339Nanoseconds,
} from "./activation-ack.js";
import {
  hasProductReceiptCarrier,
  runtimeOutcomeToWire,
  type RuntimeOutcomeWire,
} from "./product-authority-context.js";
import { OpenClawProductActivationError } from "./product-manifest.js";

export type ProductReceiptNamespace = Readonly<{
  runtime: "openclaw";
  agentId: string;
  principalId: string;
  runtimeBindingId: string;
}>;

export const MAX_PRODUCT_RECEIPT_WIRE_BYTES = 512 * 1024;
const SECRET = /(?:hmac-sha256|lease-v1):[0-9a-f]{64}/u;
const KINDS = [
  "pre_execution_deny",
  "approval_release",
  "tool_result_modified",
  "tool_result_quarantined",
  "execution_completed",
  "execution_failed",
];
const GATES = [
  "evaluating",
  "allowed",
  "approval_pending",
  "approval_released",
  "blocked",
  "timed_out",
  "binding_failed",
  "unknown",
];
const REASONS = [
  "binding_exact",
  "binding_invalid",
  "binding_mismatch",
  "approval_not_human",
  "approval_not_consumable",
  "approval_not_found",
  "approval_expired",
  "identity_denied",
  "approval_timed_out",
  "lease_consumed",
  "consumption_conflict",
  "lease_rejected",
  "lease_expired",
  "lease_revoked",
  "lease_unavailable",
  "lease_response_invalid",
  "lease_consume_timed_out",
  "multiple_binding_conflict",
  "correlation_capacity_exhausted",
].map((v) => `rte-05:${v}`);

/** Freeze the genuine carrier before the first asynchronous storage operation. */
export function captureProductReceiptWire(
  receipt: RuntimeOutcomeReceipt,
): string {
  try {
    assertDataTree(receipt);
    if (!hasProductReceiptCarrier(receipt)) fail();
    const wire = restrictedCanonicalJson(runtimeOutcomeToWire(receipt));
    if (Buffer.byteLength(wire, "utf8") > MAX_PRODUCT_RECEIPT_WIRE_BYTES)
      fail();
    return wire;
  } catch {
    return fail();
  }
}

/** First submission requires the genuine private receipt carrier. */
export function prepareProductReceipt(
  receipt: RuntimeOutcomeReceipt,
  namespace: ProductReceiptNamespace,
): string {
  try {
    const wire = captureProductReceiptWire(receipt);
    readHistoricalProductReceiptWire(wire, namespace);
    return wire;
  } catch {
    return fail();
  }
}

/**
 * Validate authenticated historical bytes without granting execution authority.
 * Callers retain the original string for HTTP. No current manifest, package
 * version, candidate digest, live ACK or wall clock participates in recovery.
 * The storage AAD binds principalId; only the server can check its ACK issuance.
 */
export function readHistoricalProductReceiptWire(
  wire: string,
  namespace: ProductReceiptNamespace,
): RuntimeOutcomeWire {
  try {
    if (
      typeof wire !== "string" ||
      Buffer.byteLength(wire, "utf8") > MAX_PRODUCT_RECEIPT_WIRE_BYTES
    )
      fail();
    assertDataTree(namespace);
    const ns = object(namespace, [
      "runtime",
      "agentId",
      "principalId",
      "runtimeBindingId",
    ]);
    if (SECRET.test(restrictedCanonicalJson(ns))) fail();
    equal(ns.runtime, "openclaw");
    text(ns.agentId, 1, 128);
    text(ns.principalId, 1, 256);
    text(ns.runtimeBindingId, 1, 256);
    const value: unknown = JSON.parse(wire);
    assertDataTree(value);
    // This also rejects duplicate keys, invalid Unicode, unsafe numbers and
    // extra whitespace. New records are always prepared using this profile.
    if (restrictedCanonicalJson(value) !== wire) fail();
    const receipt = object(
      value,
      [
        "audit_id",
        "schema_version",
        "record_type",
        "trace_id",
        "runtime",
        "timestamp",
        "stage",
        "event_type",
        "summary",
        "decision",
        "risk_score",
        "severity",
        "blocked",
        "resource_targets",
        "rule_hits",
        "reason",
        "links",
        "latency_ms",
        "metadata",
        "evidence",
      ],
      ["case_id", "attack_type", "is_malicious"],
    );
    equal(receipt.schema_version, "0.4");
    equal(receipt.record_type, "runtime_outcome");
    equal(receipt.event_type, "runtime_outcome");
    equal(receipt.runtime, ns.runtime);
    text(receipt.audit_id, 1, 256);
    text(receipt.trace_id, 1, 160);
    text(receipt.stage, 1, 64);
    text(receipt.summary, 1, 1000);
    text(receipt.reason, 1, 4000);
    for (const key of ["case_id", "attack_type"])
      if (key in receipt) nullableText(receipt[key]);
    if ("is_malicious" in receipt) nullableBoolean(receipt.is_malicious);
    choice(receipt.decision, ["allow", "deny", "ask"]);
    integer(receipt.risk_score, 0, 100);
    choice(receipt.severity, ["low", "medium", "high", "critical"]);
    boolean(receipt.blocked);
    strings(receipt.resource_targets);
    strings(receipt.rule_hits);
    equal(receipt.latency_ms, null);
    const occurred = timestamp(receipt.timestamp);
    const links = object(
      receipt.links,
      ["event_id", "decision_id", "policy_audit_id"],
      [
        "action_id",
        "approval_id",
        "parent_audit_id",
        "lease_id",
        "consumption_id",
      ],
    );
    for (const [key, value] of Object.entries(links))
      text(value, 1, key.endsWith("audit_id") ? 256 : 160);
    const hasLease = "lease_id" in links;
    if (hasLease !== "consumption_id" in links) fail();
    const metadata = object(receipt.metadata, [
      "agent_id",
      "outcome_kind",
      "activation_ack",
    ]);
    text(metadata.agent_id, 1, 128);
    equal(metadata.agent_id, ns.agentId);
    choice(metadata.outcome_kind, KINDS);
    equal(
      receipt.audit_id,
      `audit_outcome_${links.event_id}_${metadata.outcome_kind}`,
    );
    const ack = readHistoricalOpenClawActivationAck(metadata.activation_ack);
    equal(ack.agent_id, ns.agentId);
    equal(ack.runtime_binding_id, ns.runtimeBindingId);
    if (timestamp(ack.issued_at) > occurred) fail();
    const evidence = object(
      receipt.evidence,
      ["intervention", "execution", "side_effects", "result", "approval"],
      ["enforcement"],
    );
    const intervention = object(evidence.intervention, ["type", "reason"]);
    text(intervention.type, 1, 64);
    text(intervention.reason, 1, 2000);
    const execution = object(evidence.execution, [
      "status",
      "receipt_recorded",
      "invoked_at",
      "completed_at",
      "error",
      "tool_result_entered_context",
      "persisted",
    ]);
    choice(execution.status, ["not_invoked", "executed", "failed", "unknown"]);
    equal(execution.receipt_recorded, true);
    equal(timestamp(execution.completed_at), occurred);
    if (
      execution.invoked_at !== null &&
      timestamp(execution.invoked_at) > occurred
    )
      fail();
    nullableText(execution.error, 2000);
    if (execution.status === "failed" && !execution.error) fail();
    if (
      ["not_invoked", "executed"].includes(String(execution.status)) &&
      execution.error !== null
    )
      fail();
    nullableBoolean(execution.tool_result_entered_context);
    nullableBoolean(execution.persisted);
    const effects = object(evidence.side_effects, [
      "measurement_status",
      "count",
      "summary",
    ]);
    choice(effects.measurement_status, ["measured", "not_measured", "unknown"]);
    if (effects.measurement_status === "measured")
      integer(effects.count, 0, Number.MAX_SAFE_INTEGER);
    else equal(effects.count, null);
    nullableText(effects.summary, 2000);
    const result = object(evidence.result, [
      "disposition",
      "summary",
      "sanitized",
    ]);
    choice(result.disposition, [
      "not_applicable",
      "passed_through",
      "modified",
      "quarantined",
      "unknown",
    ]);
    nullableText(result.summary, 2000);
    nullableBoolean(result.sanitized);
    const approval = object(evidence.approval, [
      "approval_id",
      "status",
      "decision",
      "resolved_at",
    ]);
    if (approval.approval_id !== null) text(approval.approval_id, 1, 160);
    equal(approval.approval_id, links.approval_id ?? null);
    choice(approval.status, [
      "not_required",
      "pending",
      "allowed",
      "denied",
      "expired",
      "unknown",
    ]);
    choice(approval.decision, ["allow_once", "deny", null]);
    if (approval.resolved_at !== null) timestamp(approval.resolved_at);
    if (
      approval.status === "not_required" &&
      (approval.approval_id !== null || approval.decision !== null)
    )
      fail();
    if (
      ["pending", "allowed", "denied", "expired"].includes(
        String(approval.status),
      ) &&
      approval.approval_id === null
    )
      fail();
    if (approval.status === "allowed") equal(approval.decision, "allow_once");
    if (approval.status === "denied") equal(approval.decision, "deny");
    if (approval.status === "pending") equal(approval.decision, null);
    const kind = metadata.outcome_kind;
    if (kind === "pre_execution_deny") {
      equal(execution.status, "not_invoked");
      equal(result.disposition, "not_applicable");
    }
    if (kind === "approval_release") {
      equal(execution.status, "unknown");
      equal(approval.status, "allowed");
    }
    if (kind === "tool_result_modified") {
      equal(execution.status, "executed");
      equal(result.disposition, "modified");
    }
    if (kind === "tool_result_quarantined") {
      equal(execution.status, "executed");
      equal(result.disposition, "quarantined");
    }
    if (kind === "execution_completed") equal(execution.status, "executed");
    if (kind === "execution_failed") equal(execution.status, "failed");
    if ("enforcement" in evidence)
      validateEnforcement(
        evidence.enforcement,
        links,
        kind,
        execution.status,
        approval,
      );
    else if (hasLease) fail();
    const { ack_token: _secret, ...publicAck } = ack;
    if (
      SECRET.test(
        restrictedCanonicalJson({
          ...receipt,
          metadata: { ...metadata, activation_ack: publicAck },
        }),
      )
    )
      fail();
    return value as RuntimeOutcomeWire;
  } catch {
    return fail();
  }
}

function validateEnforcement(
  value: unknown,
  links: Record<string, unknown>,
  kind: unknown,
  status: unknown,
  approval: Record<string, unknown>,
): void {
  const e = object(value, [
    "gate_state",
    "binding_check_status",
    "lease_consume_outcome",
    "reason_codes",
  ]);
  choice(e.gate_state, GATES);
  choice(e.binding_check_status, [
    "not_applicable",
    "not_performed",
    "passed",
    "failed",
    "unknown",
  ]);
  choice(e.lease_consume_outcome, [
    "not_applicable",
    "not_attempted",
    "consumed",
    "expired",
    "revoked",
    "rejected",
    "unknown",
  ]);
  const reasons = strings(e.reason_codes);
  if (
    reasons.length < 1 ||
    reasons.length > 4 ||
    new Set(reasons).size !== reasons.length
  )
    fail();
  for (const reason of reasons) choice(reason, REASONS);
  const consumed = e.lease_consume_outcome === "consumed";
  const hasLease = "lease_id" in links;
  const released =
    e.gate_state === "approval_released" && e.binding_check_status === "passed";
  const deniedShapes: [string, string, string[]][] = [
    ["binding_failed", "failed", ["binding_mismatch", "lease_consumed"]],
    ["timed_out", "passed", ["binding_exact", "lease_consume_timed_out"]],
    ["binding_failed", "passed", ["binding_exact", "lease_expired"]],
    ["binding_failed", "passed", ["binding_exact", "lease_response_invalid"]],
    ["binding_failed", "failed", ["multiple_binding_conflict"]],
  ];
  const denied =
    kind === "pre_execution_deny" &&
    deniedShapes.some(
      ([gate, binding, expected]) =>
        e.gate_state === gate &&
        e.binding_check_status === binding &&
        reasons.length === expected.length &&
        expected.every((reason) => reasons.includes(`rte-05:${reason}`)),
    );
  if (
    consumed &&
    (!hasLease ||
      !("action_id" in links) ||
      !("approval_id" in links) ||
      !(released || denied) ||
      approval.status !== "allowed" ||
      approval.decision !== "allow_once")
  )
    fail();
  if (hasLease && !consumed) fail();
  if (e.gate_state === "approval_released" && !consumed) fail();
  if (["binding_failed", "timed_out", "blocked"].includes(String(e.gate_state)))
    equal(status, "not_invoked");
}

function object(
  value: unknown,
  required: string[],
  optional: string[] = [],
): Record<string, unknown> {
  if (value === null || typeof value !== "object" || Array.isArray(value))
    fail();
  const record = value as Record<string, unknown>;
  if (
    required.some((key) => !Object.hasOwn(record, key)) ||
    Object.keys(record).some(
      (key) => !required.includes(key) && !optional.includes(key),
    )
  )
    fail();
  return record;
}
function text(
  value: unknown,
  minimum = 0,
  maximum = MAX_PRODUCT_RECEIPT_WIRE_BYTES,
): asserts value is string {
  if (typeof value !== "string") fail();
  const length = Array.from(value).length;
  if (length < minimum || length > maximum) fail();
}
function nullableText(value: unknown, maximum?: number): void {
  if (value !== null) text(value, 0, maximum);
}
function boolean(value: unknown): void {
  if (typeof value !== "boolean") fail();
}
function nullableBoolean(value: unknown): void {
  if (value !== null) boolean(value);
}
function integer(value: unknown, minimum: number, maximum: number): void {
  if (
    typeof value !== "number" ||
    !Number.isSafeInteger(value) ||
    value < minimum ||
    value > maximum
  )
    fail();
}
function strings(value: unknown): string[] {
  if (!Array.isArray(value)) fail();
  for (const item of value) text(item);
  return value as string[];
}
function equal(value: unknown, expected: unknown): void {
  if (value !== expected) fail();
}
function choice(value: unknown, allowed: unknown[]): void {
  if (!allowed.includes(value)) fail();
}
function timestamp(value: unknown): bigint {
  const parsed = rfc3339Nanoseconds(value);
  if (parsed === null) fail();
  return parsed;
}
/** Reject accessors before canonicalization or carrier code can observe them. */
function assertDataTree(value: unknown): void {
  const active = new Set<object>();
  let nodes = 0;
  function visit(item: unknown, depth: number): void {
    if (++nodes > MAX_PRODUCT_RECEIPT_WIRE_BYTES || depth > 32) fail();
    if (item === null || typeof item !== "object") return;
    if (active.has(item)) fail();
    const array = Array.isArray(item);
    if (
      !array &&
      ![Object.prototype, null].includes(Object.getPrototypeOf(item))
    )
      fail();
    active.add(item);
    try {
      for (const key of Reflect.ownKeys(item)) {
        if (array && key === "length") continue;
        if (typeof key !== "string") fail();
        const descriptor = Object.getOwnPropertyDescriptor(item, key);
        if (!descriptor || !descriptor.enumerable || !("value" in descriptor))
          fail();
        visit(descriptor.value, depth + 1);
      }
    } finally {
      active.delete(item);
    }
  }
  visit(value, 0);
}
function fail(): never {
  throw new OpenClawProductActivationError("product_receipt_invalid");
}
