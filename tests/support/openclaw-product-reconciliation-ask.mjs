/** Actual approval/consume HTTP, synthetic transport-only cutoff, no Host invocation. */
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import path from "node:path";
import { pathToFileURL } from "node:url";

const digest = (token) =>
  `sha256:${createHash("sha256").update(token).digest("hex")}`;

export async function prepareRestrictedAsk(client, input, evaluation) {
  const entry = (relative) =>
    pathToFileURL(path.join(input.packageDirectory, relative)).href;
  const {
    evaluationActivationAck,
    consumptionActivationAck,
    runtimeOutcomeToWire,
  } = await import(entry("dist/runtime/product-authority-context.js"));
  const { productCanonicalActionId } = await import(
    entry("dist/mapping/product-events.js")
  );
  const { buildProductActionReceipt } = await import(
    entry("dist/mapping/product-receipts.js")
  );
  assert.equal(evaluation.decision.decision, "ask");
  assert.equal(
    evaluation.approval_release_directive.mode,
    "restricted_allow_once",
  );
  assert.equal(evaluation.decision_authority.source, "v21");
  assert.equal(evaluation.decision_authority.mode, "active");
  assert.equal(evaluation.decision_authority.selection_basis, "profile_all");
  const originalAck = evaluationActivationAck(evaluation);
  assert.ok(originalAck);
  const approvalId = evaluation.approval.approval_id;
  const base = new URL(input.baseUrl);
  assert.equal(base.protocol, "http:");
  assert.ok(["127.0.0.1", "[::1]"].includes(base.hostname));
  let cookies = "";
  const request = async (
    route,
    { method = "GET", body, headers = {} } = {},
  ) => {
    const response = await fetch(`${input.baseUrl}${route}`, {
      method,
      redirect: "manual",
      signal: AbortSignal.timeout(5000),
      headers: {
        ...(body === undefined ? {} : { "Content-Type": "application/json" }),
        ...(cookies ? { Cookie: cookies } : {}),
        ...headers,
      },
      ...(body === undefined ? {} : { body: JSON.stringify(body) }),
    });
    const setCookies = response.headers.getSetCookie();
    if (setCookies.length)
      cookies = setCookies.map((value) => value.split(";", 1)[0]).join("; ");
    return { status: response.status, body: await response.json() };
  };
  const launch = await request("/v1/auth/browser/launch", {
    method: "POST",
    headers: { Authorization: `Bearer ${input.controlToken}` },
  });
  assert.equal(launch.status, 200);
  const session = await request("/v1/auth/browser/exchange", {
    method: "POST",
    body: { launch_code: launch.body.launch_code },
  });
  assert.equal(session.status, 200);
  const pending = await request("/v1/approvals/pending");
  assert.equal(pending.status, 200);
  assert.ok(pending.body.some((item) => item.approval_id === approvalId));
  const route = `/v1/approvals/${encodeURIComponent(approvalId)}/resolve`;
  const wrongCsrf = await request(route, {
    method: "POST",
    body: { decision: "allow_once" },
    headers: { "X-AgentGuard-CSRF": "invalid-automated-test-csrf" },
  });
  assert.equal(wrongCsrf.status, 403);
  const stillPending = await request("/v1/approvals/pending");
  assert.ok(stillPending.body.some((item) => item.approval_id === approvalId));
  const resolved = await request(route, {
    method: "POST",
    body: { decision: "allow_once" },
    headers: { "X-AgentGuard-CSRF": session.body.csrf_token },
  });
  assert.equal(resolved.status, 200);
  const approval = await client.waitForApproval(approvalId);
  assert.equal(approval.status, "resolved");
  assert.equal(approval.decision, "allow_once");
  assert.equal(approval.resolution_source, "human"); // API field; operator is explicitly automated below.
  const consumeRequest = {
    mode: "restricted_allow_once",
    action_id: productCanonicalActionId(input.event),
  };
  const consumption = client.consumeProductExecutionLease(
    evaluation,
    consumeRequest,
    Date.now() + 20_000,
  );
  assert.equal(
    client.consumeProductExecutionLease(
      evaluation,
      consumeRequest,
      Date.now() + 20_000,
    ),
    consumption,
  );
  const lease = await consumption;
  const consumptionAck = consumptionActivationAck(evaluation);
  assert.ok(consumptionAck);
  assert.notEqual(consumptionAck.headerValue(), originalAck.headerValue());
  // This fixture supplies no native Host adapter: it withholds the action at
  // the pre-invocation boundary after real consumption, using the SDK's actual
  // restricted host-unavailable denial producer. It never calls a tool.
  const receipt = buildProductActionReceipt(input.event, evaluation, {
    kind: "pre_execution_deny",
    lease,
    approval: { status: "allowed", decision: "allow_once" },
    consumeAttempted: true,
    postConsumeFailure: "v21:restricted_host_mismatch",
  });
  assert.equal(receipt.evidence.execution.status, "not_invoked");
  assert.equal(receipt.evidence.execution.invoked_at, null);
  assert.equal(
    receipt.evidence.enforcement.binding_check_status,
    "not_performed",
  );
  assert.equal(
    runtimeOutcomeToWire(receipt).metadata.activation_ack.ack_token,
    consumptionAck.headerValue(),
  );
  return {
    receipt,
    consumptionAck,
    leaseId: lease.leaseId,
    consumptionId: lease.consumptionId,
    approvalId,
    evaluationAckDigest: digest(originalAck.headerValue()),
    consumptionAckDigest: digest(consumptionAck.headerValue()),
    approvalEvidence: {
      operatorKind: "automated_test_operator",
      browserUiAcceptance: false,
      wrongCsrfStatus: wrongCsrf.status,
      resolutionStatus: resolved.status,
      decision: "allow_once",
      apiResolutionSource: approval.resolution_source,
      controlledPreInvocationCutoff:
        "no native Host execution adapter in transport-only fixture",
      hostInvocationCount: 0,
    },
  };
}
