import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import {
  chmod,
  link,
  mkdtemp,
  readFile,
  rename,
  rm,
  symlink,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { inspect } from "node:util";
import test, { after } from "node:test";

import { restrictedCanonicalJson } from "../dist/runtime/canonical.js";
import { OpenClawProductManifest as ActualManifest } from "../dist/runtime/product-manifest.js";
import { OpenClawActivationSession as ActualSession } from "../dist/runtime/activation-session.js";
import { createSyntheticProductPackage } from "../../../tests/support/openclaw-product-transport-package.mjs";

const root = await mkdtemp(join(tmpdir(), "agentguard-openclaw-session-"));
const synthetic = await createSyntheticProductPackage({
  directory: join(root, "synthetic-package"),
});
const {
  OpenClawProductManifest,
  OpenClawProductActivationError,
  readOpenClawProductRuntimeObservation,
} = await import(synthetic.manifestModuleUrl);
const { ActivationAckReadError } = await import(
  new URL("./activation-ack.js", synthetic.ackHandleModuleUrl).href
);
const { OpenClawActivationSession } = await import(synthetic.sessionModuleUrl);
const {
  OpenClawActivationAckHandle,
  readOpenClawActivationAckHandle,
  isOpenClawActivationAckHandle,
} = await import(synthetic.ackHandleModuleUrl);
const golden = JSON.parse(
  await readFile(
    new URL(
      "../../../tests/fixtures/product_activation_v2_golden.json",
      import.meta.url,
    ),
    "utf8",
  ),
);
const TOKEN = `hmac-sha256:${"a".repeat(64)}`;
const NOW = Date.parse("2026-09-08T12:00:00Z");
after(async () => {
  await rm(root, { recursive: true, force: true });
});

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
function wire(manifest, now = Date.now(), token = TOKEN) {
  return {
    schema_version: "1.0",
    runtime: "openclaw",
    ...manifest.expectedAckIdentity,
    issued_at: new Date(now).toISOString(),
    expires_at: new Date(now + 120_000).toISOString(),
    ack_token: token,
  };
}
function response(manifest, body, token = TOKEN) {
  return {
    runtime_status: {
      ...body,
      runtime: "openclaw",
      principal_id: manifest.data.principal_id,
      last_heartbeat_at: new Date().toISOString(),
    },
    activation_ack: wire(manifest, Date.now(), token),
  };
}
async function fixture(t, Manifest = OpenClawProductManifest) {
  const directory = await mkdtemp(join(root, "manifest-"));
  await chmod(directory, 0o700);
  const path = join(directory, "manifest.json");
  await writeFile(path, restrictedCanonicalJson(payload()), { mode: 0o600 });
  const manifest = await Manifest.fromFile(path);
  const observed = readOpenClawProductRuntimeObservation(observation());
  return { directory, path, manifest, observed };
}
function deferred() {
  let resolve;
  const promise = new Promise((done) => {
    resolve = done;
  });
  return { promise, resolve };
}
async function bounded(promise) {
  let timer;
  try {
    return await Promise.race([
      promise,
      new Promise((_, reject) => {
        timer = setTimeout(
          () => reject(new Error("test operation timed out")),
          3000,
        );
      }),
    ]);
  } finally {
    clearTimeout(timer);
  }
}
function hasCode(code) {
  return (error) => {
    assert.equal(error.code, code);
    assert.equal(String(error).includes(TOKEN), false);
    assert.equal(Object.hasOwn(error, "cause"), false);
    return true;
  };
}

test("ACK handle is genuinely branded, immutable and secret-safe in generic projections", async (t) => {
  const { manifest } = await fixture(t);
  const raw = wire(manifest, NOW);
  const ack = readOpenClawActivationAckHandle(
    raw,
    manifest.expectedAckIdentity,
    { nowMs: NOW },
  );
  assert.equal(isOpenClawActivationAckHandle(ack), true);
  for (const fake of [
    { ...ack },
    Object.create(Object.getPrototypeOf(ack)),
    new Proxy(ack, {}),
    { headerValue: () => TOKEN },
  ]) {
    assert.equal(isOpenClawActivationAckHandle(fake), false);
  }
  assert.throws(
    () =>
      new OpenClawActivationAckHandle({}, raw, manifest.expectedAckIdentity),
    /Invalid activation ACK handle/u,
  );
  for (const publicText of [
    inspect(ack),
    JSON.stringify(ack),
    inspect({ ...ack }),
    inspect(ack.identity),
  ])
    assert.equal(publicText.includes(TOKEN), false);
  assert.equal(Object.isFrozen(ack), true);
  assert.equal(Object.isFrozen(ack.identity), true);
  assert.equal(ack.headerValue(), TOKEN);
  assert.deepEqual(ack.toWire(), raw);
  raw.agent_id = "changed";
  assert.equal(ack.identity.agent_id, "main");
  const snapshot = ack.toWire();
  snapshot.ack_token = "changed";
  assert.equal(ack.headerValue(), TOKEN);
  assert.equal(ack.assertFresh(NOW + 30_000), 90_000);
  assert.throws(() => ack.assertFresh(NOW + 120_000), /expired/u);
  // History stays serializable after expiry, without asking for current authority.
  assert.equal(ack.toWire().ack_token, TOKEN);
});

test("ACK handle reuses strict validation and preserves sub-millisecond expiry", async (t) => {
  const { manifest } = await fixture(t);
  const raw = wire(manifest, NOW);
  raw.expires_at = "2026-09-08T12:00:00.000000001Z";
  const ack = readOpenClawActivationAckHandle(
    raw,
    manifest.expectedAckIdentity,
    { nowMs: NOW },
  );
  assert.equal(ack.assertFresh(NOW), 0.000001);
  assert.throws(
    () =>
      readOpenClawActivationAckHandle(
        { ...raw, agent_id: "other" },
        manifest.expectedAckIdentity,
        { nowMs: NOW },
      ),
    /identity_mismatch/u,
  );
  let getterCalls = 0;
  Object.defineProperty(raw, "ack_token", {
    enumerable: true,
    get() {
      getterCalls += 1;
      throw new Error(TOKEN);
    },
  });
  assert.throws(
    () =>
      readOpenClawActivationAckHandle(raw, manifest.expectedAckIdentity, {
        nowMs: NOW,
      }),
    /invalid_response/u,
  );
  assert.equal(getterCalls, 0);
});

test("manifest and independent observation preserve frozen restricted capabilities", async (t) => {
  const { manifest, observed } = await fixture(t);
  await manifest.assertUnchanged();
  await manifest.assertInstalledVersions();
  assert.equal(synthetic.sourceVersion, "0.1.0-rc.1");
  assert.equal(synthetic.actualHostVersion, "2026.7.1-2");
  assert.equal(manifest.data.plugin_version, synthetic.syntheticVersion);
  assert.equal(Object.isFrozen(manifest.data), true);
  assert.equal(
    Object.isFrozen(observed.capability_report.events[1].residual_boundaries),
    true,
  );
  const body = manifest.makeHeartbeat(observed);
  assert.equal(
    body.reported_activation_ref_digest,
    manifest.data.activation_ref_digest,
  );
  assert.equal(body.capability_report.c3_atomic_replace_and_seal, false);
  assert.deepEqual(
    body.capability_report.residual_boundaries,
    golden.openclaw_capability_projection.residual_boundaries,
  );
  assert.equal(JSON.stringify(manifest).includes("manifest.json"), false);
  assert.throws(
    () => new OpenClawProductManifest(),
    /manifest_not_file_backed/u,
  );
  assert.equal(
    OpenClawProductManifest.isManifest(
      Object.create(OpenClawProductManifest.prototype),
    ),
    false,
  );
});

for (const change of [
  "agent_id",
  "runtime_binding_id",
  "loaded",
  "enforcement_mode",
  "runtime_version",
  "plugin_version",
  "adapter_artifact_digest",
  "host_inventory_digest",
  "plugin_inventory_digest",
  "plugin_order_inventory_digest",
  "tool_inventory_digest",
  "c3",
  "missing_event",
  "residual",
  "event_enforcement",
  "digest",
  "extra",
  "getter",
]) {
  test(`independent observation refuses changed or malformed ${change}`, async (t) => {
    const { manifest } = await fixture(t);
    const raw = observation();
    if (change === "agent_id" || change === "runtime_binding_id")
      raw.capability_report[change] = "different";
    else if (change === "loaded") raw.loaded = false;
    else if (change === "enforcement_mode") raw.enforcement_mode = "observe";
    else if (change === "c3")
      raw.capability_report.c3_atomic_replace_and_seal = true;
    else if (change === "missing_event") raw.capability_report.events.pop();
    else if (change === "residual")
      raw.capability_report.residual_boundaries = [];
    else if (change === "event_enforcement")
      raw.capability_report.events[1].enforcement = "pre_execution_c3";
    else if (change === "digest")
      raw.capability_report.report_digest = `sha256:${"f".repeat(64)}`;
    else if (change === "extra") raw.extra = TOKEN;
    else if (change === "getter")
      Object.defineProperty(raw, "loaded", {
        enumerable: true,
        get() {
          assert.fail("observer getters must not run");
        },
      });
    else
      raw[change] = change.endsWith("version")
        ? "wrong"
        : `sha256:${"f".repeat(64)}`;
    assert.throws(
      () => manifest.makeHeartbeat(raw),
      (error) => {
        assert.match(error.code, /^observation_(?:invalid|drift)$/u);
        assert.equal(String(error).includes(TOKEN), false);
        return true;
      },
    );
  });
}

for (const change of [
  "mode",
  "parent_mode",
  "hardlink",
  "symlink",
  "parent_symlink",
  "fifo",
  "oversize",
  "duplicate",
  "extra",
  "whitespace",
  "unsorted",
  "two_newlines",
  "bom",
  "invalid_utf8",
  "relative",
]) {
  test(`protected manifest rejects ${change} without exposing paths`, async (t) => {
    const { directory, path } = await fixture(t);
    let target = path;
    if (change === "mode") await chmod(path, 0o644);
    else if (change === "parent_mode") await chmod(directory, 0o755);
    else if (change === "hardlink")
      await link(path, join(directory, "hardlink"));
    else if (change === "symlink") {
      target = join(directory, "link");
      await symlink(path, target);
    } else if (change === "parent_symlink") {
      target = join(root, "symlink-parent");
      await symlink(directory, target);
      target = join(target, "manifest.json");
    } else if (change === "fifo") {
      await rm(path);
      execFileSync("mkfifo", ["-m", "600", path]);
    } else if (change === "oversize")
      await writeFile(path, " ".repeat(128 * 1024 + 1));
    else if (change === "duplicate")
      await writeFile(path, '{"schema_version":"1.0","schema_version":"1.0"}');
    else if (change === "extra")
      await writeFile(
        path,
        restrictedCanonicalJson({ ...payload(), ack_token: TOKEN }),
      );
    else if (change === "whitespace")
      await writeFile(path, ` ${restrictedCanonicalJson(payload())}`);
    else if (change === "unsorted")
      await writeFile(path, JSON.stringify(payload()));
    else if (change === "two_newlines")
      await writeFile(path, `${restrictedCanonicalJson(payload())}\n\n`);
    else if (change === "bom")
      await writeFile(path, `\ufeff${restrictedCanonicalJson(payload())}`);
    else if (change === "invalid_utf8")
      await writeFile(path, Buffer.from([0xff, 0x7b]));
    else target = "relative.json";
    await assert.rejects(
      bounded(OpenClawProductManifest.fromFile(target)),
      (error) => {
        assert.match(error.code, /^(?:manifest_|invalid_data)/u);
        assert.equal(String(error).includes(directory), false);
        assert.equal(String(error).includes(TOKEN), false);
        return true;
      },
    );
  });
}

test("canonical manifest accepts one LF and detects identical atomic replacement", async (t) => {
  const { directory, path, manifest } = await fixture(t);
  await writeFile(path, `${restrictedCanonicalJson(payload())}\n`);
  const withLf = await OpenClawProductManifest.fromFile(path);
  await assert.rejects(manifest.assertUnchanged(), hasCode("manifest_changed"));
  await writeFile(
    join(directory, "replacement"),
    `${restrictedCanonicalJson(payload())}\n`,
    { mode: 0o600 },
  );
  await rename(join(directory, "replacement"), path);
  await assert.rejects(withLf.assertUnchanged(), hasCode("manifest_changed"));
});

test("the actual rc1 package verifies its version but cannot start without a heartbeat ACK", async (t) => {
  const { manifest, observed } = await fixture(t, ActualManifest);
  let observations = 0,
    requests = 0;
  const session = new ActualSession({
    manifest,
    observe: () => {
      observations += 1;
      return observed;
    },
    sendHeartbeat: async () => {
      requests += 1;
      throw new Error(TOKEN);
    },
  });
  t.after(() => session.close());
  await assert.rejects(session.start(), hasCode("heartbeat_unavailable"));
  await assert.rejects(session.refresh(), hasCode("heartbeat_unavailable"));
  await assert.rejects(session.snapshot(), hasCode("heartbeat_unavailable"));
  assert.equal(observations, 2);
  assert.equal(requests, 2);
});

for (const field of ["refreshIntervalMs", "maxAckAgeMs"]) {
  for (const value of [true, 0, -1, NaN, Infinity, 120_001]) {
    test(`session rejects invalid ${field}=${String(value)}`, async (t) => {
      const { manifest, observed } = await fixture(t);
      assert.throws(
        () =>
          new OpenClawActivationSession({
            manifest,
            observe: () => observed,
            sendHeartbeat: async () => ({}),
            [field]: value,
          }),
        /invalid_(?:refresh_interval|max_age)/u,
      );
    });
  }
}

test("one millisecond maximum age permits an equally bounded timer", async (t) => {
  const { manifest, observed } = await fixture(t);
  const session = new OpenClawActivationSession({
    manifest,
    observe: () => observed,
    sendHeartbeat: async () => ({}),
    maxAckAgeMs: 1,
    refreshIntervalMs: 1,
  });
  session.close();
  assert.throws(
    () =>
      new OpenClawActivationSession({
        manifest,
        observe: () => observed,
        sendHeartbeat: async () => ({}),
        refreshIntervalMs: 30_001,
      }),
    /invalid_refresh_interval/u,
  );
});

test("snapshot observes locally without sending and failed refresh blocks until recovery", async (t) => {
  const { manifest, observed } = await fixture(t);
  let requests = 0,
    fail = false;
  const session = new OpenClawActivationSession({
    manifest,
    observe: () => observed,
    sendHeartbeat: async (body) => {
      requests += 1;
      if (fail) throw new Error(TOKEN);
      return response(
        manifest,
        body,
        `hmac-sha256:${requests.toString(16).padStart(64, "0")}`,
      );
    },
  });
  t.after(() => session.close());
  await assert.rejects(session.snapshot(), hasCode("session_not_started"));
  const original = await session.start();
  const originalWire = original.toWire();
  assert.equal(await session.snapshot(), original);
  assert.equal(await session.start(), original);
  assert.equal(requests, 1);
  fail = true;
  await assert.rejects(session.refresh(), hasCode("heartbeat_unavailable"));
  await assert.rejects(session.snapshot(), hasCode("heartbeat_unavailable"));
  assert.deepEqual(original.toWire(), originalWire);
  fail = false;
  const recovered = await session.refresh();
  assert.notEqual(recovered, original);
  assert.equal(await session.snapshot(), recovered);
  assert.deepEqual(original.toWire(), originalWire);
});

test("concurrent refresh shares one send and exactly one branded handle", async (t) => {
  const { manifest, observed } = await fixture(t);
  let requests = 0;
  const entered = deferred(),
    release = deferred();
  const session = new OpenClawActivationSession({
    manifest,
    observe: () => observed,
    sendHeartbeat: async (body) => {
      requests += 1;
      if (requests > 1) {
        entered.resolve();
        await release.promise;
      }
      return response(manifest, body);
    },
  });
  t.after(() => session.close());
  await session.start();
  const leader = session.refresh();
  await bounded(entered.promise);
  const followers = Array.from({ length: 5 }, () => session.refresh());
  release.resolve();
  const [first, ...others] = await bounded(Promise.all([leader, ...followers]));
  assert.ok(others.every((ack) => ack === first));
  assert.equal(requests, 2);
});

for (const operation of ["refresh", "snapshot", "start"]) {
  test(`close cancels blocked ${operation}, signals callback and discards late completion`, async (t) => {
    const { manifest, observed } = await fixture(t);
    const entered = deferred(),
      release = deferred();
    let block = false,
      signal;
    const session = new OpenClawActivationSession({
      manifest,
      observe: async (currentSignal) => {
        signal = currentSignal;
        if (block) {
          entered.resolve();
          await release.promise;
        }
        return observed;
      },
      sendHeartbeat: async (body) => response(manifest, body),
    });
    t.after(() => {
      release.resolve();
      session.close();
    });
    await session.start();
    block = true;
    const pending = session[operation]();
    await bounded(entered.promise);
    session.close();
    assert.equal(signal.aborted, true);
    await assert.rejects(bounded(pending), hasCode("session_closed"));
    release.resolve();
    await assert.rejects(session.refresh(), hasCode("session_closed"));
    await assert.rejects(session.snapshot(), hasCode("session_closed"));
  });
}

test("close cancels all in-flight heartbeat followers even when sender ignores signal", async (t) => {
  const { manifest, observed } = await fixture(t);
  const entered = deferred(),
    release = deferred();
  let requests = 0,
    signal;
  const session = new OpenClawActivationSession({
    manifest,
    observe: () => observed,
    sendHeartbeat: async (body, options) => {
      signal = options.signal;
      requests += 1;
      if (requests > 1) {
        entered.resolve();
        await release.promise;
      }
      return response(manifest, body);
    },
  });
  t.after(() => {
    release.resolve();
    session.close();
  });
  const historical = await session.start();
  const leader = session.refresh();
  await bounded(entered.promise);
  const follower = session.refresh();
  session.close();
  assert.equal(signal.aborted, true);
  await bounded(
    Promise.all([
      assert.rejects(leader, hasCode("session_closed")),
      assert.rejects(follower, hasCode("session_closed")),
    ]),
  );
  release.resolve();
  assert.equal(historical.toWire().ack_token, TOKEN);
});

for (const change of ["close", "failed_refresh", "successful_refresh"]) {
  test(`snapshot checks current availability after concurrent ${change}`, async (t) => {
    const { manifest, observed } = await fixture(t);
    const entered = deferred(),
      release = deferred();
    let blockOnce = false,
      fail = false;
    const session = new OpenClawActivationSession({
      manifest,
      observe: async () => {
        if (blockOnce) {
          blockOnce = false;
          entered.resolve();
          await release.promise;
        }
        return observed;
      },
      sendHeartbeat: async (body) => {
        if (fail) throw new Error(TOKEN);
        return response(manifest, body);
      },
    });
    t.after(() => {
      release.resolve();
      session.close();
    });
    const old = await session.start();
    blockOnce = true;
    const pending = session.snapshot();
    const failed =
      change === "successful_refresh"
        ? undefined
        : assert.rejects(
            pending,
            hasCode(
              change === "close" ? "session_closed" : "heartbeat_unavailable",
            ),
          );
    await bounded(entered.promise);
    let current;
    if (change === "close") session.close();
    else if (change === "failed_refresh") {
      fail = true;
      await assert.rejects(session.refresh(), hasCode("heartbeat_unavailable"));
    } else current = await session.refresh();
    release.resolve();
    if (current) {
      assert.notEqual(current, old);
      assert.equal(await bounded(pending), current);
    } else await bounded(failed);
  });
}

test("observed inventory drift remains locked even after observation is restored", async (t) => {
  const { manifest, observed } = await fixture(t);
  let actual = observed,
    requests = 0;
  const session = new OpenClawActivationSession({
    manifest,
    observe: () => actual,
    sendHeartbeat: async (body) => {
      requests += 1;
      return response(manifest, body);
    },
  });
  t.after(() => session.close());
  await session.start();
  actual = { ...observed, host_inventory_digest: `sha256:${"f".repeat(64)}` };
  await assert.rejects(session.snapshot(), hasCode("observation_drift"));
  actual = observed;
  await assert.rejects(session.refresh(), hasCode("observation_drift"));
  assert.equal(requests, 1);
});

test("local drift during heartbeat prevents installing its otherwise valid ACK", async (t) => {
  const { manifest, observed } = await fixture(t);
  let actual = observed;
  const session = new OpenClawActivationSession({
    manifest,
    observe: () => actual,
    sendHeartbeat: async (body) => {
      actual = { ...observed, loaded: false };
      return response(manifest, body);
    },
  });
  t.after(() => session.close());
  await assert.rejects(session.start(), hasCode("observation_drift"));
  actual = observed;
  await assert.rejects(session.refresh(), hasCode("observation_drift"));
});

for (const field of [
  "principal_id",
  "capability_report",
  "reported_activation_ref_digest",
]) {
  test(`heartbeat echo cannot rebind ${field}`, async (t) => {
    const { manifest, observed } = await fixture(t);
    const session = new OpenClawActivationSession({
      manifest,
      observe: () => observed,
      sendHeartbeat: async (body) => {
        const result = response(manifest, body);
        result.runtime_status[field] = "wrong";
        return result;
      },
    });
    t.after(() => session.close());
    await assert.rejects(
      session.start(),
      hasCode("heartbeat_identity_mismatch"),
    );
    await assert.rejects(
      session.refresh(),
      hasCode("heartbeat_identity_mismatch"),
    );
  });
}

for (const origin of ["observe", "sendHeartbeat"]) {
  for (const ErrorType of [
    OpenClawProductActivationError,
    ActivationAckReadError,
  ]) {
    test(`unknown ${ErrorType.name} codes from ${origin} cannot escape diagnostics`, async (t) => {
      const { manifest, observed } = await fixture(t);
      const session = new OpenClawActivationSession({
        manifest,
        observe: () => {
          if (origin === "observe") throw new ErrorType(TOKEN);
          return observed;
        },
        sendHeartbeat: async () => {
          throw new ErrorType(TOKEN);
        },
      });
      t.after(() => session.close());
      const code =
        origin === "observe"
          ? "observation_unavailable"
          : "heartbeat_unavailable";
      await assert.rejects(session.start(), hasCode(code));
      await assert.rejects(session.snapshot(), hasCode(code));
    });
  }
}

test("initial transient startup failure recovers with a running background timer", async (t) => {
  const { manifest, observed } = await fixture(t);
  const refreshed = deferred();
  let requests = 0;
  const session = new OpenClawActivationSession({
    manifest,
    observe: () => observed,
    refreshIntervalMs: 10,
    sendHeartbeat: async (body) => {
      requests += 1;
      if (requests === 1) throw new Error(TOKEN);
      if (requests === 3) refreshed.resolve();
      return response(manifest, body);
    },
  });
  t.after(() => session.close());
  await assert.rejects(session.start(), hasCode("heartbeat_unavailable"));
  await session.refresh();
  await bounded(refreshed.promise);
  session.close();
  await assert.rejects(session.snapshot(), hasCode("session_closed"));
});
