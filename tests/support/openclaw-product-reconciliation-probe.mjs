/** Real SDK/HTTP process. Synthetic TEST identity; no native Host or Provider. */
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { writeFile } from "node:fs/promises";
import path from "node:path";
import { pathToFileURL } from "node:url";

const hash = (value) => createHash("sha256").update(value).digest("hex");
const evidence = () => ({
  pid: process.pid,
  syntheticTestEvidence: true,
  nativeHostEvidence: false,
});

async function run(input) {
  const result = evidence();
  const entry = (relative) => pathToFileURL(path.join(input.packageDirectory, relative)).href;
  if (input.stage !== "prepare") {
    const { OpenClawProductEnvelopeStore, OpenClawProductEnvelopeStoreError } = await import(entry("dist/runtime/product-envelope-store.js"));
    const originalReplace = OpenClawProductEnvelopeStore.prototype.replace;
    let faultCount = 0;
    if (input.fault) {
      OpenClawProductEnvelopeStore.prototype.replace = function(recordId, payload, options) {
        const record = JSON.parse(payload);
        const selected = (input.fault === "confirmation_persist" && record.type === "tombstone") ||
          (input.fault === "prepared_persist" && record.type !== "tombstone" && record.reconciliation?.attempts?.at(-1)?.status === "inflight");
        if (selected) { faultCount += 1; throw new OpenClawProductEnvelopeStoreError("write_failed"); }
        return originalReplace.call(this, recordId, payload, options);
      };
    }
    // The installed public recovery entry has no Host/model/session bootstrap.
    const { openOpenClawProductReceiptRecovery } = await import(entry("product-runtime/receipt-recovery.mjs"));
    const recovery = await openOpenClawProductReceiptRecovery({
      guardApiBaseUrl: input.baseUrlOverride ?? input.baseUrl,
      adapterToken: input.token,
      agentId: input.agentId,
      principalId: input.principalId,
      runtimeBindingId: input.runtimeBindingId,
      productReceiptDirectory: input.directory,
      productReceiptKeyPath: input.keyPath,
      requestTimeoutMs: 3000,
    });
    try {
      result.before = recovery.status();
      if (input.stage === "reconcile_close") {
        const promise = recovery.reconcileRejectedReceipt({auditId: input.auditId, expectedWireDigest: input.wireDigest});
        const deadline = Date.now() + 5000;
        while (!recovery.status().reconciliations.some((item) => item.auditId === input.auditId && item.attempts.at(-1)?.status === "inflight")) {
          assert.ok(Date.now() < deadline);
          await new Promise((resolve) => setTimeout(resolve, 5));
        }
        result.closeDuringSend = await recovery.closeWithin(1);
        assert.deepEqual(result.closeDuringSend, {status: "pending", ownerHeld: true});
        await writeFile(input.closeMarker, JSON.stringify({closing: true}), {mode: 0o600, flag: "wx"});
        result.delivered = await promise;
      } else if (input.stage === "reconcile") {
        result.delivered = await recovery.reconcileRejectedReceipt({auditId: input.auditId, expectedWireDigest: input.wireDigest});
      } else if (input.stage === "drain") {
        result.delivered = await recovery.drain();
      } else assert.equal(input.stage, "status");
      result.status = recovery.status();
      result.faultCount = faultCount;
      return result;
    } finally {
      await recovery.close();
      OpenClawProductEnvelopeStore.prototype.replace = originalReplace;
    }
  }

  // Preparation uses the actual built SDK in a fresh, explicit TEST package.
  const { createSyntheticProductPackage } = await import("./openclaw-product-transport-package.mjs");
  await createSyntheticProductPackage({directory: input.packageDirectory, sourcePackageRoot: input.sourcePackageRoot});
  const { GuardApiClient, buildPluginConfig } = await import(entry("dist/guard-api-client.js"));
  const { readOpenClawProductRuntimeObservation } = await import(entry("dist/runtime/product-manifest.js"));
  const { OpenClawProductEnvelopeStore } = await import(entry("dist/runtime/product-envelope-store.js"));
  const { OpenClawProductReceiptOutbox } = await import(entry("dist/runtime/product-receipt-outbox.js"));
  const { productTransportBindingDigest } = await import(entry("dist/runtime/product-transport.js"));
  const { receiptEvaluation } = await import(entry("dist/runtime/state.js"));
  const { buildRuntimeOutcomeAuditEvent } = await import(entry("dist/mapping/audit-outcomes.js"));
  const { prepareProductReceipt } = await import(entry("dist/runtime/product-receipt-wire.js"));
  const config = {
    ...buildPluginConfig({guardApiBaseUrl: input.baseUrl, adapterToken: input.token, agentId: input.agentId, runtimeBindingId: input.runtimeBindingId, requestTimeoutMs: 3000, diagnosticLogging: false}),
    officialProfileId: "agentguard-openclaw-v2-restricted",
    officialProfileDigest: input.profileDigest,
    productManifestPath: input.manifestPath,
  };
  const client = new GuardApiClient({config});
  let outbox;
  try {
    const originalAck = await client.startProductSession(() => readOpenClawProductRuntimeObservation(input.observation));
    const {evaluation, activationAck} = await client.evaluateProductEvent(input.event);
    assert.equal(evaluation.decision.decision, input.decisionKind ?? "deny");
    assert.equal(evaluation.decision_authority.source, "v21");
    assert.equal(evaluation.decision_authority.mode, "active");
    assert.equal(evaluation.decision_authority.selection_basis, "profile_all");
    assert.equal(activationAck.headerValue(), originalAck.headerValue());
    let receipt;
    let receiptAck = originalAck;
    if (input.decisionKind === "ask") {
      const { prepareRestrictedAsk } = await import("./openclaw-product-reconciliation-ask.mjs");
      const {receipt: askReceipt, consumptionAck, ...fields} = await prepareRestrictedAsk(client, input, evaluation);
      receipt = askReceipt;
      receiptAck = consumptionAck;
      Object.assign(result, fields);
    } else {
      receipt = buildRuntimeOutcomeAuditEvent(input.event, receiptEvaluation(evaluation), "pre_execution_deny");
    }
    const namespace = {runtime: "openclaw", agentId: input.agentId, principalId: input.principalId, runtimeBindingId: input.runtimeBindingId};
    const wire = prepareProductReceipt(receipt, namespace);
    await writeFile(input.wirePath, wire, {mode: 0o600, flag: "wx"});
    const store = await OpenClawProductEnvelopeStore.open({directory: input.directory, keyPath: input.keyPath, namespace});
    outbox = new OpenClawProductReceiptOutbox({
      store,
      sendReceipt: (body) => client.submitProductReceiptWire(body),
      transportBindingDigest: productTransportBindingDigest(config.guardApiBaseUrl, store.namespace),
      retryBaseMs: 1, retryMaxMs: 1,
    });
    result.delivered = await outbox.submit(receipt);
    const fresh = await client.refreshProductAck();
    assert.notEqual(fresh.headerValue(), originalAck.headerValue());
    assert.notEqual(fresh.headerValue(), receiptAck.headerValue());
    Object.assign(result, {auditId: receipt.audit_id, policyAuditId: evaluation.policy_audit_id, wireDigest: hash(wire), originalAckDigest: `sha256:${hash(receiptAck.headerValue())}`, evaluationAckDigest: `sha256:${hash(originalAck.headerValue())}`, refreshedAckDigest: `sha256:${hash(fresh.headerValue())}`, expiresAt: receiptAck.expires_at, status: outbox.status()});
    assert.equal(JSON.stringify(result).includes(originalAck.headerValue()), false);
    return result;
  } finally {
    client.closeProductSession();
    if (outbox) await outbox.close();
  }
}

let result;
try {
  let input = "";
  for await (const chunk of process.stdin) input += chunk;
  result = await run(JSON.parse(input));
} catch (error) {
  result = {...evidence(), errorType: error?.name ?? "Error", errorCode: error?.code ?? null};
}
process.stdout.write(JSON.stringify(result));
