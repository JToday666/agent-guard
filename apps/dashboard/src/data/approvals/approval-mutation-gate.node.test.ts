import assert from "node:assert/strict";
import test from "node:test";

import {
  createDashboardDataSourceDescriptor,
  type DashboardDataSourceDescriptor,
} from "../sources/dashboard-data-source.ts";
import {
  createApprovalMutationSelector,
  type ApprovalMutationContext,
} from "./approval-mutation-gate.ts";

function descriptor(
  overrides: {
    approvalMutation?: boolean;
    dataSourceMode?: "live_api" | "mock_preview";
    runtimeSupervisionS1?: boolean;
  } = {},
): DashboardDataSourceDescriptor {
  return createDashboardDataSourceDescriptor({
    isProduction: false,
    runtimeSupervisionS1Enabled:
      overrides.approvalMutation !== false && overrides.runtimeSupervisionS1 !== false,
    viteMode: overrides.dataSourceMode === "mock_preview" ? "mock" : "test",
  });
}

function validContext(overrides: Partial<ApprovalMutationContext> = {}): ApprovalMutationContext {
  return {
    targetApprovalId: "approval_1",
    approvalId: "approval_1",
    basisApprovalId: "approval_1",
    temporalState: "following",
    readonlyOverride: false,
    sessionAuthenticated: true,
    csrfReady: true,
    approvalStatus: "pending",
    approvalUnexpired: true,
    basisCompleteness: "recorded",
    basisMissingReasons: [],
    traceId: "trace_1",
    approvalTraceId: "trace_1",
    actionTraceId: "trace_1",
    officialDecisionTraceId: "trace_1",
    basisTraceId: "trace_1",
    eventId: "event_1",
    basisEventId: "event_1",
    actionId: "action_1",
    basisActionId: "action_1",
    officialDecisionId: "decision_1",
    basisDecisionId: "decision_1",
    policyAuditId: "audit_policy_1",
    basisPolicyAuditId: "audit_policy_1",
    officialDecisionValue: "ask",
    requestedDecision: "allow_once",
    decisionOptions: ["allow_once", "deny"],
    approvalSource: "live",
    actionSource: "live",
    officialDecisionSource: "live",
    basisSource: "live",
    ...overrides,
  };
}

test("permits only a complete exact-match live approval context", () => {
  const canMutateApproval = createApprovalMutationSelector(descriptor());

  assert.equal(canMutateApproval(validContext()), true);
  assert.equal(
    canMutateApproval(validContext({ requestedDecision: "deny", decisionOptions: ["deny"] })),
    true,
  );
});

test("fails closed for every descriptor capability boundary", () => {
  assert.equal(
    createApprovalMutationSelector(descriptor({ dataSourceMode: "mock_preview" }))(validContext()),
    false,
  );
  assert.equal(
    createApprovalMutationSelector(descriptor({ approvalMutation: false }))(validContext()),
    false,
  );
  assert.equal(
    createApprovalMutationSelector(descriptor({ runtimeSupervisionS1: false }))(validContext()),
    false,
  );

  const mutableDescriptor = {
    ...descriptor(),
    capabilities: { ...descriptor().capabilities },
  } as DashboardDataSourceDescriptor;
  assert.equal(createApprovalMutationSelector(mutableDescriptor)(validContext()), false);

  const wrongOwner = Object.freeze({
    ...descriptor(),
    owner: "route_payload",
  }) as unknown as DashboardDataSourceDescriptor;
  assert.equal(createApprovalMutationSelector(wrongOwner)(validContext()), false);

  const forgedCapabilities = Object.freeze({ ...descriptor().capabilities });
  const forgedDescriptor = Object.freeze({
    ...descriptor(),
    capabilities: forgedCapabilities,
  });
  assert.equal(createApprovalMutationSelector(forgedDescriptor)(validContext()), false);
});

test("fails closed for every contextual boolean, state, authority, and decision option", () => {
  const canMutateApproval = createApprovalMutationSelector(descriptor());
  const invalidContexts: Array<Partial<ApprovalMutationContext>> = [
    { temporalState: "historical" },
    { readonlyOverride: true },
    { sessionAuthenticated: false },
    { csrfReady: false },
    { approvalStatus: "settled" },
    { approvalStatus: "unknown" },
    { approvalUnexpired: false },
    { basisCompleteness: "partial" },
    { basisCompleteness: "unavailable" },
    { basisCompleteness: "not_applicable" },
    { basisMissingReasons: ["missing_event_id"] },
    { officialDecisionValue: "allow" },
    { officialDecisionValue: "deny" },
    { officialDecisionValue: "unknown" },
    { requestedDecision: "allow_once", decisionOptions: ["deny"] },
    { requestedDecision: "deny", decisionOptions: ["allow_once"] },
    { requestedDecision: "deny", decisionOptions: [] },
  ];

  for (const overrides of invalidContexts) {
    assert.equal(canMutateApproval(validContext(overrides)), false, JSON.stringify(overrides));
  }
});

test("fails closed when any required identity is empty", () => {
  const canMutateApproval = createApprovalMutationSelector(descriptor());
  const identityKeys = [
    "targetApprovalId",
    "approvalId",
    "basisApprovalId",
    "eventId",
    "basisEventId",
    "traceId",
    "approvalTraceId",
    "actionTraceId",
    "officialDecisionTraceId",
    "basisTraceId",
    "actionId",
    "basisActionId",
    "officialDecisionId",
    "basisDecisionId",
    "policyAuditId",
    "basisPolicyAuditId",
  ] as const;

  for (const key of identityKeys) {
    assert.equal(canMutateApproval(validContext({ [key]: "" })), false, key);
    assert.equal(canMutateApproval(validContext({ [key]: "   " })), false, `${key}:whitespace`);
  }
});

test("fails closed for every cross-object identity mismatch", () => {
  const canMutateApproval = createApprovalMutationSelector(descriptor());
  const mismatches: Array<Partial<ApprovalMutationContext>> = [
    { targetApprovalId: "approval_other" },
    { basisApprovalId: "approval_other" },
    { basisEventId: "event_other" },
    { basisActionId: "action_other" },
    { basisDecisionId: "decision_other" },
    { basisPolicyAuditId: "audit_policy_other" },
    { approvalTraceId: "trace_other" },
    { actionTraceId: "trace_other" },
    { officialDecisionTraceId: "trace_other" },
    { basisTraceId: "trace_other" },
  ];

  for (const overrides of mismatches) {
    assert.equal(canMutateApproval(validContext(overrides)), false, JSON.stringify(overrides));
  }
});

test("fails closed when any evidence source is not live", () => {
  const canMutateApproval = createApprovalMutationSelector(descriptor());
  const sourceKeys = [
    "approvalSource",
    "actionSource",
    "officialDecisionSource",
    "basisSource",
  ] as const;

  for (const key of sourceKeys) {
    assert.equal(canMutateApproval(validContext({ [key]: "mock" })), false, `${key}:mock`);
    assert.equal(canMutateApproval(validContext({ [key]: "replay" })), false, `${key}:replay`);
  }
});

test("never throws when a hostile runtime value reaches the selector", () => {
  const canMutateApproval = createApprovalMutationSelector(descriptor());

  assert.doesNotThrow(() => canMutateApproval(null as unknown as ApprovalMutationContext));
  assert.equal(canMutateApproval(null as unknown as ApprovalMutationContext), false);
  assert.equal(
    canMutateApproval({ decisionOptions: null } as unknown as ApprovalMutationContext),
    false,
  );
});
