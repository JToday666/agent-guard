/** Real SDK / local Core delivery contracts. No native Host or provider calls. */
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import path from "node:path";
import { pathToFileURL } from "node:url";
import { inspect } from "node:util";
import { createSyntheticProductPackage } from "./openclaw-product-transport-package.mjs";

const hash = (value) => createHash("sha256").update(value).digest("hex");
let phase = "input";

async function run(input) {
  const endpoint = new URL(input.baseUrl);
  assert.equal(endpoint.protocol, "http:");
  assert.equal(endpoint.hostname, "127.0.0.1");
  const preparing = input.stage === "prepare";
  assert.ok(preparing || input.stage === "drain");
  phase = "private-test-package";
  const fixture = preparing
    ? await createSyntheticProductPackage({
        directory: input.packageDirectory,
        sourcePackageRoot: input.sourcePackageRoot,
      })
    : null;
  const moduleUrl = (relative) =>
    pathToFileURL(path.join(input.packageDirectory, "dist", relative)).href;
  const { GuardApiClient, buildPluginConfig } = await import(
    moduleUrl("guard-api-client.js")
  );
  const { OpenClawProductEnvelopeStore, OpenClawProductEnvelopeStoreError } =
    await import(moduleUrl("runtime/product-envelope-store.js"));
  const { OpenClawProductReceiptOutbox } = await import(
    moduleUrl("runtime/product-receipt-outbox.js")
  );
  const config = {
    ...buildPluginConfig({
      guardApiBaseUrl: input.baseUrl,
      adapterToken: input.token,
      agentId: input.namespace.agentId,
      runtimeBindingId: input.namespace.runtimeBindingId,
      requestTimeoutMs: 3000,
      diagnosticLogging: false,
    }),
    officialProfileId: "agentguard-openclaw-v2-restricted",
    officialProfileDigest: input.profileDigest,
    productManifestPath: input.manifestPath,
    ...(input.scenario === "client-dispatch"
      ? {
          productReceiptDirectory: input.directory,
          productReceiptKeyPath: input.keyPath,
        }
      : {}),
  };
  const client = new GuardApiClient({ config });
  let outbox;
  let store;
  try {
    phase = "open-encrypted-store";
    const useClientDelivery = [
      "client-dispatch",
      "client-missing-paths",
    ].includes(input.scenario);
    if (!useClientDelivery) {
      store = await OpenClawProductEnvelopeStore.open({
        directory: input.directory,
        keyPath: input.keyPath,
        namespace: input.namespace,
      });
      outbox = new OpenClawProductReceiptOutbox({
        store,
        sendReceipt: (wire) => client.submitProductReceiptWire(wire),
        retryBaseMs: 10,
        retryMaxMs: 40,
        now: () => Date.now() + (input.clockAdvanceMs ?? 0),
      });
    }
    if (!preparing) {
      phase = "restart-without-session";
      const before = outbox.status();
      let readyRejected = false;
      try {
        outbox.assertReady();
      } catch {
        readyRejected = true;
      }
      const delivered = await outbox.drain();
      return {
        ok: true,
        stage: "drain",
        pid: process.pid,
        before,
        delivered,
        status: outbox.status(),
        readyRejected,
        sessionStarted: false,
      };
    }
    phase = "start-and-evaluate";
    const { readOpenClawProductRuntimeObservation } = await import(
      moduleUrl("runtime/product-manifest.js")
    );
    const observed = readOpenClawProductRuntimeObservation(input.observation);
    phase = "start-session";
    const originalAck = await client.startProductSession(() => observed);
    phase = "evaluate-denied-event";
    const { evaluation, activationAck } = await client.evaluateProductEvent(
      input.event,
    );
    assert.equal(evaluation.decision.decision, "deny");
    assert.equal(evaluation.decision_authority.source, "v21");
    assert.equal(evaluation.decision_authority.mode, "active");
    assert.equal(evaluation.decision_authority.selection_basis, "profile_all");
    assert.equal(evaluation.decision_authority.legacy_floor_applied, false);
    assert.equal(activationAck.headerValue(), originalAck.headerValue());
    const { receiptEvaluation } = await import(moduleUrl("runtime/state.js"));
    const { buildRuntimeOutcomeAuditEvent } = await import(
      moduleUrl("mapping/audit-outcomes.js")
    );
    const { prepareProductReceipt } = await import(
      moduleUrl("runtime/product-receipt-wire.js")
    );
    phase = "build-denied-receipt";
    // A real policy denial is observed. No executable-looking fixture runs.
    const receipt = buildRuntimeOutcomeAuditEvent(
      input.event,
      receiptEvaluation(evaluation),
      "pre_execution_deny",
    );
    const wire = prepareProductReceipt(receipt, input.namespace);
    const token = originalAck.headerValue();
    assert.equal(JSON.stringify(receipt).includes(token), false);
    assert.equal(inspect(receipt, { depth: 8 }).includes(token), false);
    const result = {
      ok: true,
      stage: "prepare",
      pid: process.pid,
      sourceVersion: fixture.sourceVersion,
      syntheticVersion: fixture.syntheticVersion,
      syntheticMetadata: true,
      candidateAdmissionEvidence: false,
      originalAckHash: hash(token),
      wireHash: hash(wire),
      auditId: receipt.audit_id,
      policyAuditId: evaluation.policy_audit_id,
      eventId: input.event.event_id,
      actionId: receipt.links.action_id,
    };
    phase = "persist-before-delivery";
    if (input.scenario === "disk-failure") {
      store.create = () => {
        throw new OpenClawProductEnvelopeStoreError("write_failed");
      };
      store.replace = () => {
        throw new OpenClawProductEnvelopeStoreError("write_failed");
      };
    }
    if (useClientDelivery) {
      result.delivered = await client.submitProductReceipt(receipt);
      if (input.scenario === "client-dispatch")
        outbox = await client.openProductDelivery();
    } else if (
      ["unknown-prepared", "unknown-released", "terminal-outage"].includes(
        input.scenario,
      )
    ) {
      const ticket = outbox.prepareAction({
        actionId: receipt.links.action_id,
        eventId: receipt.links.event_id,
        decisionId: receipt.links.decision_id,
        policyAuditId: receipt.links.policy_audit_id,
        activationAck: originalAck,
      });
      if (input.scenario !== "unknown-prepared") outbox.releaseAction(ticket);
      if (input.scenario === "terminal-outage") {
        result.delivered = await outbox.finishAction(ticket, receipt);
        assert.throws(() => outbox.assertReady());
        result.nextActionBlocked = true;
      }
    } else {
      result.delivered = await outbox.submit(receipt);
    }
    phase = "refresh-expiry-and-close";
    const refreshed = await client.refreshProductAck();
    assert.notEqual(refreshed.headerValue(), token);
    result.refreshedAckHash = hash(refreshed.headerValue());
    assert.throws(() =>
      originalAck.assertFresh(Date.parse(originalAck.expires_at) + 1),
    );
    result.originalAckExpiredAtTestClock = true;
    client.closeProductSession();
    result.sessionClosed = true;
    result.status = outbox?.status() ?? null;
    assert.equal(JSON.stringify(result).includes(token), false);
    return result;
  } finally {
    client.closeProductSession();
    await client.closeProductDelivery();
    if (outbox) await outbox.close();
    else if (store) await store.close();
  }
}

try {
  let input = "";
  for await (const chunk of process.stdin) input += chunk;
  const result = await run(JSON.parse(input));
  process.stdout.write(JSON.stringify(result));
} catch (error) {
  // No exception body, payload, credential or raw ACK reaches diagnostics.
  process.stdout.write(
    JSON.stringify({
      ok: false,
      phase,
      errorType: [
        "AssertionError",
        "TypeError",
        "OpenClawProductActivationError",
        "OpenClawProductEnvelopeStoreError",
      ].includes(error?.name)
        ? error.name
        : "Error",
    }),
  );
  process.exitCode = 1;
}
