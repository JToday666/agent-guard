/** Actual Node SDK / localhost API transport tests. No Host tool or provider runs. */
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFile, readdir, writeFile } from "node:fs/promises";
import path from "node:path";
import { pathToFileURL } from "node:url";
import { inspect } from "node:util";

import { createSyntheticProductPackage } from "./openclaw-product-transport-package.mjs";

const hash = (value) => createHash("sha256").update(value).digest("hex");
let phase = "input";

async function sdkTreeDigest(root) {
  const entries = [];
  async function visit(relative) {
    for (const entry of await readdir(path.join(root, relative), {
      withFileTypes: true,
    })) {
      const name = path.posix.join(relative, entry.name);
      if (entry.isDirectory()) await visit(name);
      else {
        assert.equal(entry.isFile(), true);
        const bytes = await readFile(path.join(root, name));
        entries.push([name, bytes.length, hash(bytes)]);
      }
    }
  }
  await visit("");
  entries.sort((a, b) => a[0].localeCompare(b[0], "en"));
  assert.ok(entries.length > 0);
  return hash(JSON.stringify(entries));
}

async function rejection(callback) {
  let rejected;
  await assert.rejects(callback, (error) => {
    assert.ok(
      ["OpenClawProductActivationError", "GuardApiError"].includes(error.name),
    );
    rejected = error;
    return true;
  });
  return {
    errorType: rejected.name,
    errorCode: rejected.code ?? rejected.failure ?? null,
  };
}

async function run(input) {
  const url = new URL(input.baseUrl);
  assert.equal(url.protocol, "http:");
  assert.equal(url.hostname, "127.0.0.1");
  phase = "test-package";
  const fixturePackage = await createSyntheticProductPackage({
    directory: input.packageDirectory,
    sourcePackageRoot: input.sourcePackageRoot,
  });
  const packageRoot = fixturePackage.packageRoot;
  let betaIdentity;
  if (input.scenario === "beta-rejected") {
    // Exercise installed beta identity rejection with the actual current SDK
    // code. This is a negative fixture, never a historical Beta artifact claim.
    const installedMetadata = path.join(packageRoot, "package.json");
    const metadata = JSON.parse(await readFile(installedMetadata, "utf8"));
    const betaVersion = "0.1.0-beta.1";
    await writeFile(
      installedMetadata,
      JSON.stringify({ ...metadata, version: betaVersion }),
    );
    const sourceSdkDigest = await sdkTreeDigest(
      path.join(input.sourcePackageRoot, "dist"),
    );
    const copiedSdkDigest = await sdkTreeDigest(path.join(packageRoot, "dist"));
    assert.equal(copiedSdkDigest, sourceSdkDigest);
    assert.equal(
      JSON.parse(await readFile(installedMetadata, "utf8")).version,
      betaVersion,
    );
    betaIdentity = {
      assumedVersion: betaVersion,
      sourceSdkDigest,
      copiedSdkDigest,
    };
  }
  const moduleUrl = (relative) =>
    pathToFileURL(path.join(packageRoot, "dist", relative)).href;
  const { GuardApiClient, buildPluginConfig } = await import(
    moduleUrl("guard-api-client.js")
  );
  const { readOpenClawProductRuntimeObservation } = await import(
    moduleUrl("runtime/product-manifest.js")
  );
  const config = {
    ...buildPluginConfig({
      guardApiBaseUrl: input.baseUrl,
      adapterToken: input.token,
      agentId: input.observation.capability_report.agent_id,
      runtimeBindingId: input.observation.capability_report.runtime_binding_id,
      requestTimeoutMs: 3000,
      diagnosticLogging: false,
    }),
    officialProfileId: "agentguard-openclaw-v2-restricted",
    officialProfileDigest: input.profileDigest,
    productManifestPath: input.manifestPath,
    productReceiptDirectory: path.join(
      path.dirname(input.manifestPath),
      "receipts",
    ),
    productReceiptKeyPath: path.join(
      path.dirname(input.manifestPath),
      "keys",
      "receipt.key",
    ),
  };
  const observed = readOpenClawProductRuntimeObservation(input.observation);
  const observe = () => observed;
  let client;
  try {
    phase = "construct-client";
    if (input.scenario === "missing-manifest") {
      delete config.productManifestPath;
      const rejected = await rejection(async () => {
        client = new GuardApiClient({ config });
        await client.evaluateProductEvent(input.event);
      });
      return { ok: true, rejected: true, ...rejected };
    }
    client = new GuardApiClient({ config });
    if (input.scenario === "unstarted") {
      return {
        ok: true,
        rejected: true,
        ...(await rejection(() => client.evaluateProductEvent(input.event))),
      };
    }
    phase = "start-session";
    if (input.scenario === "beta-rejected") {
      return {
        ok: true,
        rejected: true,
        syntheticPackageMetadata: true,
        sourceVersion: fixturePackage.sourceVersion,
        actualHostVersion: fixturePackage.actualHostVersion,
        ...betaIdentity,
        ...(await rejection(() => client.startProductSession(observe))),
      };
    }
    const originalAck = await client.startProductSession(observe);
    const snapshot = await client.snapshotProductAck();
    assert.equal(snapshot, originalAck);
    const originalToken = originalAck.headerValue();
    assert.equal(JSON.stringify(originalAck).includes(originalToken), false);
    assert.equal(
      inspect(originalAck, { depth: 5 }).includes(originalToken),
      false,
    );

    if (input.scenario === "peer-drift") {
      phase = "drift-peer";
      const drift = await fetch(
        `${input.baseUrl}/v1/adapters/langgraph/heartbeat`,
        {
          method: "POST",
          headers: {
            Authorization: `Bearer ${input.peerToken}`,
            "Content-Type": "application/json",
          },
          body: JSON.stringify({
            ...input.peerHeartbeat,
            host_inventory_digest: `sha256:${"0".repeat(64)}`,
          }),
        },
      );
      assert.equal(drift.status, 503);
      phase = "evaluate-after-peer-drift";
      const rejected = await rejection(() =>
        client.evaluateProductEvent(input.event),
      );
      return {
        ok: true,
        rejected: true,
        originalAckHash: hash(originalToken),
        ...rejected,
      };
    }

    phase = "evaluate";
    const { evaluation, activationAck } = await client.evaluateProductEvent(
      input.event,
    );
    assert.equal(activationAck.headerValue(), originalToken);
    assert.equal(evaluation.decision_authority.source, "v21");
    assert.equal(evaluation.decision_authority.mode, "active");
    assert.equal(evaluation.decision_authority.selection_basis, "profile_all");
    assert.equal(JSON.stringify(evaluation).includes(originalToken), false);
    assert.equal(
      inspect(evaluation, { depth: 5 }).includes(originalToken),
      false,
    );
    const result = {
      ok: true,
      syntheticPackageMetadata: true,
      sourceVersion: fixturePackage.sourceVersion,
      assumedVersion: fixturePackage.syntheticVersion,
      actualHostVersion: fixturePackage.actualHostVersion,
      decisionId: evaluation.decision.decision_id,
      decision: evaluation.decision.decision,
      policyAuditId: evaluation.policy_audit_id,
      authority: evaluation.decision_authority,
      directive: evaluation.approval_release_directive,
      originalAckHash: hash(originalToken),
    };
    if (input.scenario !== "historical-receipt") return result;

    assert.equal(evaluation.decision.decision, "deny");
    phase = "refresh-before-receipt";
    const freshAck = await client.refreshProductAck();
    assert.notEqual(freshAck.headerValue(), originalToken);
    const { receiptEvaluation } = await import(moduleUrl("runtime/state.js"));
    const { buildRuntimeOutcomeAuditEvent } = await import(
      moduleUrl("mapping/audit-outcomes.js")
    );
    // A real policy denial is the only runtime fact here. Never claim invocation
    // or completion of the executable-looking fixture supplied for evaluation.
    const receipt = buildRuntimeOutcomeAuditEvent(
      {
        ...input.event,
        security_context: {
          ...input.event.security_context,
          derived_paths: input.event.security_context.derived_paths ?? [],
        },
      },
      receiptEvaluation(evaluation),
      "pre_execution_deny",
    );
    assert.equal(JSON.stringify(receipt).includes(originalToken), false);
    assert.equal(inspect(receipt, { depth: 6 }).includes(originalToken), false);
    client.closeProductSession();
    phase = "historical-receipt-submit";
    const submitted = await client.submitRuntimeOutcome(receipt);
    assert.equal(submitted.ok, true);
    assert.equal(submitted.audit_id, receipt.audit_id);
    return {
      ...result,
      receiptAuditId: receipt.audit_id,
      receiptRecorded: true,
      freshAckHash: hash(freshAck.headerValue()),
      sessionClosedBeforeReceipt: true,
    };
  } finally {
    client?.closeProductSession();
    await client?.closeProductDelivery();
  }
}

try {
  let text = "";
  for await (const chunk of process.stdin) text += chunk;
  const result = await run(JSON.parse(text));
  process.stdout.write(JSON.stringify(result));
} catch (error) {
  // Keep failures useful without echoing request bodies or test credentials.
  process.stdout.write(
    JSON.stringify({
      ok: false,
      phase,
      errorType: error.name,
      errorCode: error.code ?? error.failure ?? null,
    }),
  );
  process.exitCode = 1;
}
