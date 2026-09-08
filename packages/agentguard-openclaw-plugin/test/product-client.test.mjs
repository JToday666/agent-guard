// Synthetic RC package metadata is a transport-test assumption, not candidate evidence.
import assert from "node:assert/strict";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { pathToFileURL } from "node:url";
import { inspect } from "node:util";
import test, { after } from "node:test";

import { createSyntheticProductPackage } from "../../../tests/support/openclaw-product-transport-package.mjs";

const directory = await mkdtemp(join(tmpdir(), "agentguard-product-client-"));
const synthetic = await createSyntheticProductPackage({
  directory: join(directory, "synthetic-package"),
});
const moduleUrl = (relative) =>
  pathToFileURL(join(synthetic.packageRoot, "dist", relative)).href;
const { GuardApiClient, buildPluginConfig, validateProductReceiptPaths } =
  await import(synthetic.clientModuleUrl);
const { OpenClawProductManifest, readOpenClawProductRuntimeObservation } =
  await import(synthetic.manifestModuleUrl);
const { readOpenClawProductEvaluation } = await import(
  moduleUrl("runtime/product-evaluation.js")
);
const { readOpenClawActivationAckHandle } = await import(
  synthetic.ackHandleModuleUrl
);
const { buildRuntimeOutcomeAuditEvent } = await import(
  moduleUrl("mapping/audit-outcomes.js")
);
const { runtimeOutcomeToWire } = await import(
  moduleUrl("runtime/product-authority-context.js")
);
const { restrictedCanonicalJson } = await import(
  moduleUrl("runtime/canonical.js")
);
const golden = JSON.parse(
  await readFile(
    new URL(
      "../../../tests/fixtures/product_activation_v2_golden.json",
      import.meta.url,
    ),
    "utf8",
  ),
);
const TOKEN_A = `hmac-sha256:${"a".repeat(64)}`;
const TOKEN_B = `hmac-sha256:${"b".repeat(64)}`;
const FINGERPRINT = `hmac-sha256:${"c".repeat(64)}`;
const DRIFT_CODES = [
  "V21_PRODUCT_ACTIVATION_NOT_CURRENT",
  "V21_PRODUCT_RUNTIME_IDENTITY_MISMATCH",
  "V21_PRODUCT_RUNTIME_OBSERVATION_MISMATCH",
];
after(() => rm(directory, { recursive: true, force: true }));

function payload() {
  const ack = golden.activation_ack_signature_payload.ack;
  return {
    schema_version: "1.0",
    runtime: "openclaw",
    runtime_version: "2026.7.1-2",
    plugin_version: "0.1.0-rc.1",
    principal_id: "cred_openclaw_main",
    agent_id: "main",
    runtime_binding_id: "binding:openclaw:main",
    profile_id: "agentguard-openclaw-v2-restricted",
    profile_digest: `sha256:${"1".repeat(64)}`,
    activation_ref_digest: ack.activation_ref_digest,
    adapter_artifact_digest: `sha256:${"0".repeat(64)}`,
    capability_report_digest: golden.openclaw_capability_digest,
    host_inventory_digest: ack.host_inventory_digest,
    plugin_inventory_digest: ack.plugin_inventory_digest,
    plugin_order_inventory_digest: ack.plugin_order_inventory_digest,
    tool_inventory_digest: ack.tool_inventory_digest,
  };
}

function observation() {
  const data = payload();
  return {
    runtime: "openclaw",
    runtime_version: "2026.7.1-2",
    plugin_version: "0.1.0-rc.1",
    loaded: true,
    enforcement_mode: "enforce",
    adapter_artifact_digest: data.adapter_artifact_digest,
    host_inventory_digest: data.host_inventory_digest,
    plugin_inventory_digest: data.plugin_inventory_digest,
    plugin_order_inventory_digest: data.plugin_order_inventory_digest,
    tool_inventory_digest: data.tool_inventory_digest,
    capability_report: {
      ...structuredClone(golden.openclaw_capability_projection),
      report_digest: golden.openclaw_capability_digest,
    },
  };
}

function wire(manifest, token = TOKEN_A) {
  const now = Date.now();
  return {
    schema_version: "1.0",
    runtime: "openclaw",
    ...manifest.expectedAckIdentity,
    issued_at: new Date(now).toISOString(),
    expires_at: new Date(now + 120_000).toISOString(),
    ack_token: token,
  };
}

function official(decision = "deny") {
  const data = payload();
  const ask = decision === "ask";
  return {
    decision: {
      decision_id: "decision_product_client",
      decision,
      risk_score: ask ? 70 : decision === "deny" ? 90 : 10,
      severity: decision === "allow" ? "low" : "high",
      reason: "transport fixture",
      rule_hits: [],
    },
    approval: ask
      ? {
          approval_id: "approval_product_client",
          status: "pending",
          decision_options: ["allow_once", "deny"],
        }
      : null,
    policy_audit_id: "policy_product_client",
    decision_authority: {
      source: "v21",
      mode: "active",
      selection_basis: "profile_all",
      matched_path_ids: [],
      legacy_floor_applied: false,
      activation_ref_digest: data.activation_ref_digest,
      approval_release: ask ? "forbidden" : "not_applicable",
    },
    approval_release_directive: {
      schema_version: "2.0",
      mode: ask ? "restricted_allow_once" : "not_applicable",
      required_runtime_profile: ask ? "C1" : null,
      human_only: true,
      single_use: true,
      action_binding: ask ? "best_effort_host" : "none",
      receipt_requirement: ask ? "required_durable" : "not_applicable",
      activation_ref_digest: data.activation_ref_digest,
      scope_digest: `sha256:${"7".repeat(64)}`,
      capability_digest: golden.openclaw_capability_digest,
      residual_boundaries: ask
        ? [...golden.openclaw_capability_projection.residual_boundaries]
        : [],
    },
    ...(ask ? { enforcement_binding: binding() } : {}),
  };
}

function event() {
  return {
    event_id: "event_product_client",
    schema_version: "0.4",
    record_type: "guard_event",
    event_type: "tool_call_proposed",
    runtime: "openclaw",
    trace_id: "trace_product_client",
    timestamp: new Date().toISOString(),
    pre_execution: true,
    security_context: {
      agent_id: "main",
      user_task: "transport fixture",
      source_type: "tool",
      source_trust: "untrusted",
      run_id: "run_product_client",
      current_step: "tool_call",
      context_sources: [],
      derived_paths: [],
      metadata: {},
    },
    payload: {
      tool: { name: "read", call_id: "action_product_client" },
      arguments: {},
      derived_resources: [],
    },
    metadata: {},
  };
}

function binding() {
  return {
    schema_version: "2.1",
    action_id: "action_product_client",
    authorization_fingerprint: FINGERPRINT,
    runtime_binding_id: "binding:openclaw:main",
    requires_execution_lease: true,
  };
}

function lease() {
  return {
    lease_id: "lease_product_client",
    consumption_id: "consume_product_client",
    lease_token: `lease-v1:${"d".repeat(64)}`,
    expires_at: new Date(Date.now() + 60_000).toISOString(),
  };
}

function json(body, status = 200) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json" },
  });
}

function deferred() {
  let resolve;
  const promise = new Promise((done) => {
    resolve = done;
  });
  return { promise, resolve };
}

function code(expected) {
  return (error) => {
    assert.equal(error.code, expected);
    assert.equal(inspect(error, { showHidden: true }).includes(TOKEN_A), false);
    assert.equal(inspect(error, { showHidden: true }).includes(TOKEN_B), false);
    return true;
  };
}

async function bounded(promise) {
  let timer;
  try {
    return await Promise.race([
      promise,
      new Promise((_, reject) => {
        timer = setTimeout(
          () => reject(new Error("test operation timed out")),
          2_000,
        );
      }),
    ]);
  } finally {
    clearTimeout(timer);
  }
}

async function fixture(t, handler = () => undefined) {
  const root = await mkdtemp(join(directory, "manifest-"));
  const path = join(root, "manifest.json");
  await writeFile(path, restrictedCanonicalJson(payload()), { mode: 0o600 });
  const manifest = await OpenClawProductManifest.fromFile(path);
  const config = {
    guardApiBaseUrl: "https://guard.test",
    adapterToken: "original-adapter-token",
    enforcementMode: "enforce",
    requestTimeoutMs: 500,
    approvalPollIntervalMs: 1,
    approvalTimeoutMs: 1_000,
    strongApprovalBindingEnabled: false,
    officialProfileId: payload().profile_id,
    officialProfileDigest: payload().profile_digest,
    productManifestPath: path,
    productReceiptDirectory: join(root, "receipts"),
    productReceiptKeyPath: join(root, "keys", "receipt.key"),
    restrictedAskReleaseEnabled: false,
    activationAckMaxAgeMs: 120_000,
    runtimeBindingId: payload().runtime_binding_id,
    diagnosticLogging: false,
    agentId: "main",
  };
  const requests = [];
  let heartbeatCount = 0;
  const client = new GuardApiClient({
    config,
    fetchImpl: async (url, init) => {
      const request = {
        url,
        path: new URL(url).pathname,
        init,
        body: init.body ? JSON.parse(init.body) : undefined,
        signalAbortedAtSend: init.signal?.aborted,
      };
      requests.push(request);
      const intercepted = await handler(request);
      if (intercepted !== undefined) return intercepted;
      if (request.path.endsWith("/heartbeat")) {
        heartbeatCount += 1;
        return json({
          runtime_status: {
            ...request.body,
            runtime: "openclaw",
            principal_id: manifest.data.principal_id,
          },
          activation_ack: wire(
            manifest,
            heartbeatCount === 1 ? TOKEN_A : TOKEN_B,
          ),
        });
      }
      if (request.path === "/v1/guard/evaluate") return json(official());
      if (request.path.endsWith("/consume")) return json(lease());
      if (request.path.endsWith("/wait"))
        return json({
          status: "resolved",
          decision: "allow_once",
          resolution_source: "human",
        });
      if (request.path === "/v1/audit/events")
        return json({
          ok: true,
          audit_id: request.body.audit_id,
          created: true,
        });
      assert.fail("Unexpected transport fixture route");
    },
  });
  t.after(async () => {
    client.closeProductSession();
    await client.closeProductDelivery();
  });
  const observed = readOpenClawProductRuntimeObservation(observation());
  return {
    client,
    config,
    manifest,
    path,
    requests,
    start: () => client.startProductSession(() => observed),
  };
}

test("official client rejects invalid Product configuration before any HTTP and never falls back", async (t) => {
  const { config } = await fixture(t);
  for (const changes of [
    { enforcementMode: "observe" },
    { strongApprovalBindingEnabled: true },
    { officialProfileId: "current" },
    { officialProfileDigest: "bad" },
    { productManifestPath: undefined },
    { runtimeBindingId: "" },
  ]) {
    const client = new GuardApiClient({
      config: { ...config, ...changes },
      fetchImpl: async () =>
        assert.fail("invalid Product config made HTTP request"),
    });
    assert.equal(client.productEnabled, true);
    await assert.rejects(
      client.evaluate(event()),
      code("product_configuration_invalid"),
    );
  }
});

test("official parser only accepts active profile_all with trusted ACK identity and complete release shape", async (t) => {
  const { manifest } = await fixture(t);
  const ack = readOpenClawActivationAckHandle(
    wire(manifest),
    manifest.expectedAckIdentity,
    { nowMs: Date.now() },
  );
  for (const decision of ["allow", "deny", "ask"]) {
    const accepted = readOpenClawProductEvaluation(official(decision), ack);
    assert.equal(accepted.decision_authority.source, "v21");
    assert.equal(Object.isFrozen(accepted), true);
    assert.equal(Object.isFrozen(accepted.decision), true);
  }
  for (const status of ["resolved", "expired"]) {
    const replay = official("ask");
    replay.approval.status = status;
    replay.approval.decision_options.reverse();
    assert.equal(
      readOpenClawProductEvaluation(replay, ack).approval.status,
      status,
    );
  }
  const mutations = [
    (x) => {
      x.decision_authority.source = "current";
    },
    (x) => {
      x.decision_authority.mode = "shadow";
    },
    (x) => {
      x.decision_authority.mode = "limited_enable";
    },
    (x) => {
      x.decision_authority.selection_basis = "path_allowlist";
    },
    (x) => {
      x.decision_authority.matched_path_ids = ["some-path"];
    },
    (x) => {
      x.decision_authority.legacy_floor_applied = true;
    },
    (x) => {
      x.decision_authority.activation_ref_digest = `sha256:${"f".repeat(64)}`;
    },
    (x) => {
      x.approval_release_directive.capability_digest = `sha256:${"f".repeat(64)}`;
    },
    (x) => {
      x.approval_release_directive.activation_ref_digest = `sha256:${"f".repeat(64)}`;
    },
    (x) => {
      x.approval_release_directive.human_only = false;
    },
    (x) => {
      x.approval_release_directive.mode = ["not_applicable"];
    },
    (x) => {
      delete x.decision.decision_id;
    },
    (x) => {
      delete x.policy_audit_id;
    },
    (x) => {
      x.decision.decision = ["deny"];
    },
    (x) => {
      x.decision.severity = ["high"];
    },
    (x) => {
      x.decision.policy_audit_id = "conflicting-policy";
    },
    (x) => {
      x.decision.decision_authority = {
        ...x.decision_authority,
        mode: "shadow",
      };
    },
    (x) => {
      x.decision.approval_release_directive = {
        ...x.approval_release_directive,
        human_only: false,
      };
    },
  ];
  for (const mutate of mutations) {
    const value = official();
    mutate(value);
    assert.throws(
      () => readOpenClawProductEvaluation(value, ack),
      code("official_response_mismatch"),
    );
  }
  for (const mutate of [
    (x) => {
      x.approval.decision_options = ["deny"];
    },
    (x) => {
      x.approval.status = "unknown-status";
    },
    (x) => {
      x.approval.decision_options = ["allow_once", "allow_once"];
    },
    (x) => {
      x.approval_release_directive.required_runtime_profile = "C3";
    },
    (x) => {
      x.approval_release_directive.action_binding = "exact";
    },
    (x) => {
      x.approval_release_directive.residual_boundaries.pop();
    },
    (x) => {
      x.enforcement_binding.runtime_binding_id = "different";
    },
  ]) {
    const value = official("ask");
    mutate(value);
    assert.throws(
      () => readOpenClawProductEvaluation(value, ack),
      code("official_response_mismatch"),
    );
  }
});

test("a nonofficial evaluate result permanently closes the client without a legacy retry", async (t) => {
  const env = await fixture(t, ({ path }) => {
    if (path !== "/v1/guard/evaluate") return;
    const value = official();
    value.decision_authority.mode = "shadow";
    return json(value);
  });
  await env.start();
  await assert.rejects(
    env.client.evaluate(event()),
    code("official_response_mismatch"),
  );
  const count = env.requests.length;
  await assert.rejects(env.client.evaluate(event()), code("session_closed"));
  assert.equal(env.requests.length, count);
});

for (const phase of ["heartbeat", "evaluate", "consume"]) {
  for (const driftCode of DRIFT_CODES) {
    test(`server ${driftCode} at ${phase} closes authority and makes zero subsequent requests`, async (t) => {
      let active = false;
      const env = await fixture(t, ({ path }) => {
        if (
          active &&
          ((phase === "heartbeat" && path.endsWith("/heartbeat")) ||
            (phase === "evaluate" && path === "/v1/guard/evaluate") ||
            (phase === "consume" && path.endsWith("/consume")))
        ) {
          return json({ error: { code: driftCode, message: TOKEN_A } }, 409);
        }
        if (path === "/v1/guard/evaluate") return json(official("ask"));
      });
      await env.start();
      const evaluated =
        phase === "consume"
          ? await env.client.evaluateProductEvent(event())
          : undefined;
      active = true;
      const operation =
        phase === "heartbeat"
          ? env.client.refreshProductAck()
          : phase === "evaluate"
            ? env.client.evaluate(event())
            : env.client.consumeProductExecutionLease(
                evaluated.evaluation,
                evaluated.evaluation.enforcement_binding,
                Date.now() + 1_000,
              );
      await assert.rejects(operation, (error) => {
        assert.ok(error.code === driftCode || error.code === "session_closed");
        assert.equal(inspect(error).includes(TOKEN_A), false);
        return true;
      });
      const count = env.requests.length;
      await assert.rejects(
        env.client.evaluate(event()),
        code("session_closed"),
      );
      await assert.rejects(
        env.client.refreshProductAck(),
        code("session_closed"),
      );
      assert.equal(env.requests.length, count);
    });
  }
}

test("consume retries and duplicate method calls preserve the exact request body and consumption ACK", async (t) => {
  let consumes = 0;
  const env = await fixture(t, ({ path }) => {
    if (path === "/v1/guard/evaluate") return json(official("ask"));
    if (path.endsWith("/consume"))
      return ++consumes === 1
        ? json({ error: { code: "EXECUTION_LEASE_UNAVAILABLE" } }, 503)
        : json(lease());
  });
  await env.start();
  const { evaluation } = await env.client.evaluateProductEvent(event());
  const first = env.client.consumeProductExecutionLease(
    evaluation,
    evaluation.enforcement_binding,
    Date.now() + 1_000,
  );
  const duplicate = env.client.consumeProductExecutionLease(
    evaluation,
    evaluation.enforcement_binding,
    Date.now() + 2_000,
  );
  assert.equal(duplicate, first);
  const result = await first;
  assert.deepEqual(
    await env.client.consumeProductExecutionLease(
      evaluation,
      evaluation.enforcement_binding,
      Date.now() + 3_000,
    ),
    result,
  );
  assert.equal(Object.hasOwn(result, "lease_token"), false);
  const attempts = env.requests.filter((x) => x.path.endsWith("/consume"));
  assert.equal(attempts.length, 2);
  assert.equal(attempts[0].init.body, attempts[1].init.body);
  assert.equal(
    attempts[0].init.headers["X-AgentGuard-Activation-Ack"],
    TOKEN_B,
  );
  assert.deepEqual(attempts[0].init.headers, attempts[1].init.headers);
  assert.equal(
    env.requests.filter((x) => x.path.endsWith("/heartbeat")).length,
    2,
  );
  const outcome = buildRuntimeOutcomeAuditEvent(
    event(),
    evaluation,
    "pre_execution_deny",
    {
      lease: { leaseId: result.leaseId, consumptionId: result.consumptionId },
      enforcement: {
        gate_state: "binding_failed",
        binding_check_status: "failed",
        lease_consume_outcome: "consumed",
        reason_codes: ["rte-05:binding_mismatch", "rte-05:lease_consumed"],
      },
    },
  );
  assert.equal(
    runtimeOutcomeToWire(outcome).metadata.activation_ack.ack_token,
    TOKEN_B,
  );
  assert.throws(
    () =>
      env.client.consumeProductExecutionLease(
        evaluation,
        { ...evaluation.enforcement_binding, action_id: "changed" },
        Date.now() + 1_000,
      ),
    code("consumption_request_conflict"),
  );
});

test("an exhausted uncertain consumption stays cached and cannot refresh ACK to try the action again", async (t) => {
  const env = await fixture(t, ({ path }) => {
    if (path === "/v1/guard/evaluate") return json(official("ask"));
    if (path.endsWith("/consume"))
      return json({ error: { code: "EXECUTION_LEASE_UNAVAILABLE" } }, 503);
  });
  await env.start();
  const { evaluation } = await env.client.evaluateProductEvent(event());
  const first = env.client.consumeProductExecutionLease(
    evaluation,
    evaluation.enforcement_binding,
    Date.now() + 1_000,
  );
  await assert.rejects(first, (error) => error.failure === "lease_unavailable");
  const count = env.requests.length;
  const duplicate = env.client.consumeProductExecutionLease(
    evaluation,
    evaluation.enforcement_binding,
    Date.now() + 2_000,
  );
  assert.equal(duplicate, first);
  await assert.rejects(
    duplicate,
    (error) => error.failure === "lease_unavailable",
  );
  assert.equal(env.requests.length, count);
  const attempts = env.requests.filter((x) => x.path.endsWith("/consume"));
  assert.equal(attempts.length, 5);
  for (const request of attempts) {
    assert.equal(request.init.body, attempts[0].init.body);
    assert.equal(request.init.headers["X-AgentGuard-Activation-Ack"], TOKEN_B);
  }
});

test("close aborts a pending evaluate and rejects a late successful response", async (t) => {
  const entered = deferred();
  const late = deferred();
  let signal;
  const env = await fixture(t, ({ path, init }) => {
    if (path !== "/v1/guard/evaluate") return;
    signal = init.signal;
    entered.resolve();
    return late.promise;
  });
  await env.start();
  const pending = env.client.evaluate(event());
  const rejected = assert.rejects(pending);
  await bounded(entered.promise);
  env.client.closeProductSession();
  assert.equal(signal.aborted, true);
  late.resolve(json(official("allow")));
  await bounded(rejected);
  const count = env.requests.length;
  await assert.rejects(env.client.evaluate(event()), code("session_closed"));
  assert.equal(env.requests.length, count);
});

test("close during an uncertain consume stops retries and never returns a release", async (t) => {
  const entered = deferred();
  const late = deferred();
  let signal;
  const env = await fixture(t, ({ path, init }) => {
    if (path === "/v1/guard/evaluate") return json(official("ask"));
    if (path.endsWith("/consume")) {
      signal = init.signal;
      entered.resolve();
      return late.promise;
    }
  });
  await env.start();
  const { evaluation } = await env.client.evaluateProductEvent(event());
  const pending = env.client.consumeProductExecutionLease(
    evaluation,
    evaluation.enforcement_binding,
    Date.now() + 1_000,
  );
  const rejected = assert.rejects(pending);
  await bounded(entered.promise);
  env.client.closeProductSession();
  assert.equal(signal.aborted, true);
  late.resolve(json({ error: { code: "EXECUTION_LEASE_UNAVAILABLE" } }, 503));
  await bounded(rejected);
  assert.equal(
    env.requests.filter((x) => x.path.endsWith("/consume")).length,
    1,
  );
});

test("close cancels approval waiting even if its transport ignores abort", async (t) => {
  const entered = deferred();
  const late = deferred();
  let signal;
  const env = await fixture(t, ({ path, init }) => {
    if (path.endsWith("/wait")) {
      signal = init.signal;
      entered.resolve();
      return late.promise;
    }
  });
  await env.start();
  const rejected = assert.rejects(
    env.client.waitForApproval("approval_product_client", Date.now() + 1_000),
  );
  await bounded(entered.promise);
  env.client.closeProductSession();
  assert.equal(signal.aborted, true);
  await bounded(rejected);
  late.resolve(
    json({
      status: "resolved",
      decision: "allow_once",
      resolution_source: "human",
    }),
  );
  assert.equal(env.requests.filter((x) => x.path.endsWith("/wait")).length, 1);
});

test("local manifest drift between consume attempts stops retrying the old decision", async (t) => {
  let env;
  env = await fixture(t, async ({ path }) => {
    if (path === "/v1/guard/evaluate") return json(official("ask"));
    if (path.endsWith("/consume")) {
      await writeFile(env.path, `${JSON.stringify(payload())}\n`, {
        mode: 0o600,
      });
      return json({ error: { code: "EXECUTION_LEASE_UNAVAILABLE" } }, 503);
    }
  });
  await env.start();
  const { evaluation } = await env.client.evaluateProductEvent(event());
  await assert.rejects(
    env.client.consumeProductExecutionLease(
      evaluation,
      evaluation.enforcement_binding,
      Date.now() + 1_000,
    ),
    code("manifest_changed"),
  );
  assert.equal(
    env.requests.filter((x) => x.path.endsWith("/consume")).length,
    1,
  );
  const count = env.requests.length;
  await assert.rejects(env.client.evaluate(event()));
  assert.equal(env.requests.length, count);
});

test("frozen original transport preserves historical ACK after refresh, config mutation and close", async (t) => {
  const env = await fixture(t);
  await env.start();
  const input = event();
  const { evaluation, activationAck } =
    await env.client.evaluateProductEvent(input);
  const receipt = buildRuntimeOutcomeAuditEvent(
    input,
    evaluation,
    "pre_execution_deny",
  );
  assert.equal(activationAck.headerValue(), TOKEN_A);
  await env.client.refreshProductAck();
  Object.assign(env.config, {
    guardApiBaseUrl: "https://changed.test",
    adapterToken: "changed-adapter-token",
    enforcementMode: "disabled",
    officialProfileId: "",
    officialProfileDigest: "",
    productManifestPath: undefined,
    runtimeBindingId: "changed",
  });
  env.client.closeProductSession();
  assert.equal(env.client.productEnabled, true);
  assert.equal(JSON.stringify(receipt).includes(TOKEN_A), false);
  const result = await env.client.submitRuntimeOutcome(receipt);
  assert.equal(result.ok, true);
  const request = env.requests.at(-1);
  assert.equal(request.url, "https://guard.test/v1/audit/events");
  assert.equal(
    request.init.headers.Authorization,
    "Bearer original-adapter-token",
  );
  assert.equal(request.body.metadata.activation_ack.ack_token, TOKEN_A);
  assert.equal(request.signalAbortedAtSend, false);
  assert.deepEqual(
    request.body.metadata.activation_ack,
    runtimeOutcomeToWire(receipt).metadata.activation_ack,
  );
  assert.equal(receipt.evidence.execution.status, "not_invoked");
});

test("official submit rejects missing private history before any HTTP", async (t) => {
  const env = await fixture(t);
  await env.start();
  const { evaluation } = await env.client.evaluateProductEvent(event());
  const receipt = buildRuntimeOutcomeAuditEvent(
    event(),
    evaluation,
    "pre_execution_deny",
  );
  const count = env.requests.length;
  await assert.rejects(
    env.client.submitRuntimeOutcome(JSON.parse(JSON.stringify(receipt))),
    code("receipt_ack_context_missing"),
  );
  const missing = {
    ...receipt,
    metadata: { agent_id: "main", outcome_kind: "pre_execution_deny" },
  };
  await assert.rejects(
    env.client.submitRuntimeOutcome(missing),
    code("receipt_ack_context_missing"),
  );
  assert.equal(env.requests.length, count);
});

test("Product submission freezes original wire before async queue initialization", async (t) => {
  const env = await fixture(t);
  await env.start();
  const input = event();
  const { evaluation } = await env.client.evaluateProductEvent(input);
  const receipt = buildRuntimeOutcomeAuditEvent(
    input,
    evaluation,
    "pre_execution_deny",
  );
  const original = restrictedCanonicalJson(runtimeOutcomeToWire(receipt));
  const pending = env.client.submitRuntimeOutcome(receipt);
  receipt.reason = "mutated while opening queue";
  const result = await pending;
  assert.equal(result.ok, true);
  assert.equal(result.delivery_status, "recorded");
  assert.equal(env.requests.at(-1).init.body, original);
});

test("Product without required durable paths returns failed and makes no audit HTTP", async (t) => {
  const env = await fixture(t);
  await env.start();
  const input = event();
  const { evaluation } = await env.client.evaluateProductEvent(input);
  const receipt = buildRuntimeOutcomeAuditEvent(
    input,
    evaluation,
    "pre_execution_deny",
  );
  const config = { ...env.config };
  delete config.productReceiptDirectory;
  delete config.productReceiptKeyPath;
  let calls = 0;
  const client = new GuardApiClient({
    config,
    fetchImpl: async () => {
      calls++;
      throw new Error();
    },
  });
  t.after(() => client.closeProductDelivery());
  const result = await client.submitRuntimeOutcome(receipt);
  assert.equal(result.ok, false);
  assert.equal(result.delivery_status, "failed");
  assert.equal(calls, 0);
});

for (const [status, body, expected] of [
  [200, "confirmed", "recorded"],
  [201, "confirmed", "recorded"],
  [204, null, "failed"],
  [200, { ok: false }, "failed"],
  [200, { ok: true, audit_id: "wrong" }, "failed"],
  [200, { ok: "true" }, "failed"],
  [200, "skipped", "failed"],
  [200, "malformed", "failed"],
  [200, "oversized", "failed"],
  [301, "malformed", "permanent_rejected"],
  [401, "malformed", "permanent_rejected"],
  [403, "malformed", "permanent_rejected"],
  [409, "malformed", "permanent_rejected"],
  [422, "oversized", "permanent_rejected"],
  [408, "malformed", "retryable"],
  [429, "malformed", "retryable"],
  [503, "oversized", "retryable"],
]) {
  test(`Product typed audit transport classifies ${status}/${body?.ok ?? body}`, async (t) => {
    const env = await fixture(t, (request) => {
      if (request.path !== "/v1/audit/events") return;
      const responseBody =
        body === "confirmed"
          ? JSON.stringify({ ok: true, audit_id: request.body.audit_id })
          : body === "skipped"
            ? JSON.stringify({
                ok: true,
                audit_id: request.body.audit_id,
                skipped: false,
              })
            : body === "malformed"
              ? "not JSON"
              : body === "oversized"
                ? "x".repeat(1024 * 1024 + 1)
                : body === null
                  ? null
                  : JSON.stringify(body);
      return new Response(responseBody, { status });
    });
    await env.start();
    const input = event();
    const { evaluation } = await env.client.evaluateProductEvent(input);
    const receipt = buildRuntimeOutcomeAuditEvent(
      input,
      evaluation,
      "pre_execution_deny",
    );
    const original = restrictedCanonicalJson(runtimeOutcomeToWire(receipt));
    const count = env.requests.length;
    env.client.closeProductSession();
    const result = await env.client.submitProductReceiptWire(original);
    assert.equal(result.status, expected);
    assert.equal(result.auditId, receipt.audit_id);
    assert.equal(result.httpStatus, status);
    assert.equal(env.requests.length, count + 1);
    const request = env.requests.at(-1);
    assert.equal(request.init.body, original);
    assert.equal(request.init.redirect, "manual");
    assert.equal(request.signalAbortedAtSend, false);
    assert.equal(
      request.init.headers["X-AgentGuard-Activation-Ack"],
      undefined,
    );
    assert.equal(JSON.stringify(result).includes(TOKEN_A), false);
    assert.equal(JSON.stringify(result).includes("not JSON"), false);
  });
}

for (const fault of ["network", "timeout", "unexpected"]) {
  test(`Product typed audit transport is bounded and private: ${fault}`, async (t) => {
    const env = await fixture(t, (request) => {
      if (request.path !== "/v1/audit/events") return;
      if (fault === "network") throw new TypeError(`network ${TOKEN_A}`);
      if (fault === "unexpected") throw new Error(`unexpected ${TOKEN_A}`);
      return new Promise(() => {});
    });
    await env.start();
    const input = event();
    const { evaluation } = await env.client.evaluateProductEvent(input);
    const receipt = buildRuntimeOutcomeAuditEvent(
      input,
      evaluation,
      "pre_execution_deny",
    );
    const result = await bounded(
      env.client.submitProductReceiptWire(
        restrictedCanonicalJson(runtimeOutcomeToWire(receipt)),
      ),
    );
    assert.equal(
      result.status,
      fault === "unexpected" ? "failed" : "retryable",
    );
    assert.equal(
      env.requests.filter((request) => request.path === "/v1/audit/events")
        .length,
      1,
    );
    assert.equal(inspect(result).includes(TOKEN_A), false);
  });
}

test("Product receipt paths are paired, absolute, separate and keep registration fused", () => {
  validateProductReceiptPaths({});
  validateProductReceiptPaths(
    {
      productReceiptDirectory: "/tmp/queue",
      productReceiptKeyPath: "/tmp/keys/receipt.key",
    },
    true,
  );
  for (const paths of [
    {},
    { productReceiptDirectory: "/tmp/queue" },
    { productReceiptKeyPath: "/tmp/key" },
    { productReceiptDirectory: "queue", productReceiptKeyPath: "/tmp/key" },
    {
      productReceiptDirectory: "/tmp/queue",
      productReceiptKeyPath: "/tmp/queue/key",
    },
    {
      productReceiptDirectory: "/tmp/queue",
      productReceiptKeyPath: "/tmp/queue",
    },
    { productReceiptDirectory: null, productReceiptKeyPath: "/tmp/key" },
  ])
    assert.throws(() => validateProductReceiptPaths(paths, true));
  assert.throws(
    () =>
      buildPluginConfig({
        adapterToken: "test-secret",
        officialProfileId: payload().profile_id,
        officialProfileDigest: payload().profile_digest,
        productManifestPath: "/tmp/manifest.json",
        runtimeBindingId: payload().runtime_binding_id,
        productReceiptDirectory: "/tmp/queue",
        productReceiptKeyPath: "/tmp/keys/key",
      }),
    /activation is not available/u,
  );
  assert.throws(
    () =>
      buildPluginConfig({
        adapterToken: "test-secret",
        strongApprovalBindingEnabled: false,
        productReceiptDirectory: "/tmp/queue",
        productReceiptKeyPath: "/tmp/key",
      }),
    /cannot be combined/u,
  );
});
