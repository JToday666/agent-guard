import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import fs, {
  chmodSync,
  linkSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  renameSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { createRequire, syncBuiltinESMExports } from "node:module";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";
import { pathToFileURL } from "node:url";
import {
  createProductRuntimeProfile,
  loadProductRuntimeProfileSync,
  assertProductRuntimeAssets,
  PRODUCT_TOOL_IDS,
} from "../packages/agentguard-openclaw-plugin/product-runtime/profile.mjs";
import { createProductFixturePlugin } from "../packages/agentguard-openclaw-plugin/product-runtime/factory.mjs";
import { createMessagePermitBridge } from "../packages/agentguard-openclaw-plugin/product-runtime/message-permits.mjs";
import { createFixtureMemory } from "../packages/agentguard-openclaw-plugin/product-runtime/memory.mjs";

import { PRODUCT_INBOX_TARGET } from "../packages/agentguard-openclaw-plugin/product-runtime/inbox.mjs";

const requireHost = createRequire(
  new URL(
    "../packages/agentguard-openclaw-plugin/package.json",
    import.meta.url,
  ),
);
const { OpenClawSchema } = await import(
  pathToFileURL(requireHost.resolve("openclaw/plugin-sdk/config-schema")).href
);
const provider = {
  id: "agentguard-acceptance",
  modelId: "local",
  baseUrl: "http://127.0.0.1:43124/v1",
  apiKey: { source: "env", provider: "default", id: "AGENTGUARD_TEST_KEY" },
};
function rootFor(t) {
  const root = mkdtempSync(path.join(tmpdir(), "agentguard-b09-assets-"));
  t.after(() => rmSync(root, { recursive: true, force: true }));
  return root;
}
async function fixture(t) {
  const root = rootFor(t);
  return createProductRuntimeProfile({
    root,
    inboxUrl: "http://127.0.0.1:43123/inbox",
    provider,
    runManifestPath: path.join(root, "run.json"),
  });
}

test("installable Product profile passes actual SDK schema and binds private session and credentials by reference", async (t) => {
  const profile = await fixture(t);
  const parsed = OpenClawSchema.safeParse(profile.config);
  assert.equal(
    parsed.success,
    true,
    parsed.success
      ? undefined
      : JSON.stringify(
          parsed.error.issues.map((i) => ({ path: i.path, code: i.code })),
        ),
  );
  assert.equal(profile.scopeSessionId, profile.sessionKey);
  assert.equal(profile.inboxTarget, PRODUCT_INBOX_TARGET);
  assert.equal(profile.toolOptions.messageTo, PRODUCT_INBOX_TARGET);
  assert.equal(profile.config.agents.defaults.envelopeTimestamp, "off");
  assert.deepEqual(profile.config.agents.defaults.model.fallbacks, []);
  assert.deepEqual(profile.config.tools.allow, [...PRODUCT_TOOL_IDS]);
  assert.equal(profile.config.tools.exec.security, "allowlist");
  assert.deepEqual(profile.config.tools.exec.safeBins, []);
  assert.equal(
    profile.config.plugins.entries["agentguard-product-runtime-fixture"].hooks
      .allowConversationAccess,
    true,
  );
  assert.deepEqual(
    profile.config.models.providers[profile.providerId].apiKey,
    provider.apiKey,
  );
  assert.equal(
    profile.config.plugins.load.paths[0].includes("tests/support"),
    false,
  );
  assert.deepEqual(profile.env.PATH.split(path.delimiter), [
    ...new Set([
      path.dirname(profile.nodePath),
      path.dirname(profile.shellPath),
    ]),
  ]);
  assert.equal(profile.env.HOME, undefined);
  assert.equal(profile.env.NODE_OPTIONS, undefined);
  assert.equal(profile.env.OPENCLAW_AGENT_DIR, profile.agentDir);
  assertProductRuntimeAssets(profile);
  const reloaded = loadProductRuntimeProfileSync(profile.configPath);
  assert.equal(reloaded.sessionKey, profile.sessionKey);
  assert.deepEqual(reloaded.assetCommitments, profile.assetCommitments);
  assert.throws(
    () => assertProductRuntimeAssets(JSON.parse(JSON.stringify(profile))),
    /product_assets_invalid/,
  );
});

test("Product memory reads the actual complete key/value and rejects missing/overwriting across new instances", (t) => {
  const root = rootFor(t);
  const memory = createFixtureMemory(root, { productMode: true });
  assert.throws(() => memory.read({ key: "note" }), /memory_key_missing/);
  assert.deepEqual(memory.write({ key: "note", value: "真实模型写值" }), {
    key: "note",
    written: true,
  });
  assert.throws(
    () =>
      createFixtureMemory(root, { productMode: true }).write({
        key: "note",
        value: "changed",
      }),
    /memory_key_exists/,
  );
  assert.deepEqual(
    createFixtureMemory(root, { productMode: true }).read({ key: "note" }),
    { key: "note", value: "真实模型写值" },
  );
  // The explicit baseline retains its original behavior, without another storage implementation.
  createFixtureMemory(root).write({ key: "note", value: "baseline" });
  assert.deepEqual(createFixtureMemory(root).read({ key: "note" }), {
    key: "note",
    found: true,
    value: "baseline",
  });
});

test("profile input rejects raw credentials, proxies and coercion hooks before creating state", async (t) => {
  const root = rootFor(t);
  let calls = 0;
  const input = {
    root,
    inboxUrl: "http://127.0.0.1:43123/inbox",
    provider,
    runManifestPath: path.join(root, "run.json"),
  };
  for (const badProvider of [
    { ...provider, apiKey: "private-token-value" },
    {
      ...provider,
      baseUrl: {
        toString() {
          calls++;
          return provider.baseUrl;
        },
      },
    },
    new Proxy(provider, {
      ownKeys() {
        calls++;
        return Object.keys(provider);
      },
    }),
    {
      ...provider,
      apiKey: {
        source: "env",
        provider: "default",
        get id() {
          calls++;
          return "PRIVATE";
        },
      },
    },
  ])
    await assert.rejects(
      createProductRuntimeProfile({ ...input, provider: badProvider }),
      { message: "Product runtime fixture: product_profile_unavailable" },
    );
  assert.equal(calls, 0);
});

test("fixture full registration witness contains the actual stable factories and channel callbacks", async (t) => {
  const profile = await fixture(t);
  const bridge = createMessagePermitBridge({ sessionKey: profile.sessionKey });
  t.after(() => bridge.close());
  assert.throws(
    () =>
      createProductFixturePlugin({
        profile,
        messagePermitBridge: { authorize() {}, close() {} },
      }),
    /product_fixture_assembly_invalid/,
  );
  const fixturePlugin = createProductFixturePlugin({
    profile,
    messagePermitBridge: bridge,
  });
  assert.equal(fixturePlugin.plugin.version, "0.1.0-rc.1");
  const rows = [],
    channels = [];
  const api = {
    registrationMode: "tool-discovery",
    pluginConfig: { runManifestPath: profile.runManifestPath },
    registerTool(factory, options) {
      rows.push({ factory, options });
    },
    registerChannel({ plugin }) {
      channels.push(plugin);
    },
  };
  fixturePlugin.plugin.register(api);
  assert.equal(channels.length, 0);
  assert.throws(
    () => fixturePlugin.registrationWitness(),
    /product_fixture_registration_missing/,
  );
  rows.length = 0;
  fixturePlugin.plugin.register({ ...api, registrationMode: "full" });
  const witness = fixturePlugin.registrationWitness();
  assert.deepEqual(
    rows.map((r) => r.options.name),
    ["agentguard_memory_read", "agentguard_memory_write"],
  );
  assert.equal(witness.memoryFactories[0], rows[0].factory);
  const firstTool = rows[0].factory({}),
    secondTool = rows[0].factory({});
  assert.notEqual(firstTool, secondTool);
  assert.equal(firstTool.execute, witness.memoryTools[0].execute);
  assert.equal(firstTool.parameters, witness.memoryTools[0].parameters);
  assert.equal(
    Object.getOwnPropertyDescriptor(firstTool, "execute").configurable,
    true,
  );
  firstTool.name = "changed-shell";
  assert.equal(secondTool.name, "agentguard_memory_read");
  assert.equal(witness.channel, channels[0]);
  assert.equal(
    witness.outbound.prepareSendPayload,
    channels[0].actions.prepareSendPayload,
  );
  assert.equal(witness.outbound.sendPayload, channels[0].outbound.sendPayload);
  assert.throws(
    () => fixturePlugin.plugin.register({ ...api, registrationMode: "full" }),
    /already_registered/,
  );
  const write = witness.memoryTools[1],
    read = witness.memoryTools[0];
  const acknowledged = await write.execute("write-1", {
    key: "native",
    value: "native SQLite",
  });
  assert.deepEqual(acknowledged.details, { entryId: "native", written: true });
  assert.deepEqual(JSON.parse(acknowledged.content[0].text), {
    key: "native",
    written: true,
  });
  const result = await read.execute("read-1", { key: "native" });
  assert.deepEqual(JSON.parse(result.content[0].text), {
    key: "native",
    value: "native SQLite",
  });
  assert.deepEqual(result.details, {
    entryId: "native",
    value: "native SQLite",
  });
});

test("every release asset check rejects modified marker, config, profile, approvals and private root", async (t) => {
  const profile = await fixture(t);
  for (const filename of [
    path.join(profile.workspaceDir, "marker.mjs"),
    profile.configPath,
    profile.profilePath,
    path.join(profile.stateDir, "exec-approvals.json"),
  ]) {
    const bytes = readFileSync(filename);
    writeFileSync(filename, Buffer.concat([bytes, Buffer.from(" ")]));
    assert.throws(
      () => assertProductRuntimeAssets(profile),
      /product_assets_invalid/,
    );
    writeFileSync(filename, bytes);
    assertProductRuntimeAssets(profile);
  }
  chmodSync(profile.workspaceDir, 0o755);
  assert.throws(
    () => assertProductRuntimeAssets(profile),
    /product_assets_invalid/,
  );
  chmodSync(profile.workspaceDir, 0o700);
  assertProductRuntimeAssets(profile);
});

test("profile loader rejects duplicate JSON keys, links, named pipes, and hardlinks without blocking", async (t) => {
  const profile = await fixture(t);
  const original = readFileSync(profile.profilePath);
  writeFileSync(
    profile.profilePath,
    original
      .toString()
      .replace('"schemaVersion":1', '"schemaVersion":1,"schemaVersion":1'),
  );
  assert.throws(
    () => loadProductRuntimeProfileSync(profile.configPath),
    /product_profile_unavailable/,
  );
  writeFileSync(profile.profilePath, original);
  const backup = path.join(profile.stateDir, "backup.json");
  writeFileSync(backup, original, { mode: 0o600 });
  rmSync(profile.profilePath);
  symlinkSync(backup, profile.profilePath);
  assert.throws(
    () => loadProductRuntimeProfileSync(profile.configPath),
    /product_profile_unavailable/,
  );
  rmSync(profile.profilePath);
  linkSync(backup, profile.profilePath);
  assert.throws(
    () => loadProductRuntimeProfileSync(profile.configPath),
    /product_profile_unavailable/,
  );
  rmSync(profile.profilePath);
  execFileSync("mkfifo", ["-m", "600", profile.profilePath]);
  assert.throws(
    () => loadProductRuntimeProfileSync(profile.configPath),
    /product_profile_unavailable/,
  );
});

test("asset capture rejects same-inode changes after its final descriptor snapshot", async (t) => {
  const profile = await fixture(t);
  const original = readFileSync(profile.profilePath);
  const originalFstat = fs.fstatSync;
  let snapshots = 0;
  fs.fstatSync = function (fd, options) {
    const stat = originalFstat(fd, options);
    if (
      fs.readlinkSync(`/proc/self/fd/${fd}`) === profile.profilePath &&
      ++snapshots === 2
    ) {
      const changed = Buffer.from(original);
      changed[0] ^= 1;
      writeFileSync(profile.profilePath, changed);
      // Make the same-size named-file timestamp difference deterministic.
      fs.utimesSync(
        profile.profilePath,
        new Date(),
        new Date(Date.now() + 10000),
      );
    }
    return stat;
  };
  syncBuiltinESMExports();
  try {
    assert.throws(
      () => assertProductRuntimeAssets(profile),
      /product_assets_invalid/,
    );
    assert.equal(snapshots, 2);
  } finally {
    fs.fstatSync = originalFstat;
    syncBuiltinESMExports();
    writeFileSync(profile.profilePath, original);
  }
  assertProductRuntimeAssets(profile);
});

test("asset capture bounds a file that grows after its admitted size snapshot", async (t) => {
  const profile = await fixture(t);
  const original = readFileSync(profile.profilePath);
  const originalFstat = fs.fstatSync,
    originalRead = fs.readSync;
  let injected = false,
    bytesRead = 0;
  fs.fstatSync = function (fd, options) {
    const stat = originalFstat(fd, options);
    if (
      !injected &&
      fs.readlinkSync(`/proc/self/fd/${fd}`) === profile.profilePath
    ) {
      injected = true;
      writeFileSync(profile.profilePath, Buffer.alloc(256 * 1024, 32));
    }
    return stat;
  };
  fs.readSync = function (fd, ...args) {
    const count = originalRead(fd, ...args);
    if (fs.readlinkSync(`/proc/self/fd/${fd}`) === profile.profilePath)
      bytesRead += count;
    return count;
  };
  syncBuiltinESMExports();
  try {
    assert.throws(
      () => assertProductRuntimeAssets(profile),
      /product_assets_invalid/,
    );
    assert.equal(injected, true);
    assert.equal(bytesRead, original.length + 1);
  } finally {
    fs.fstatSync = originalFstat;
    fs.readSync = originalRead;
    syncBuiltinESMExports();
    writeFileSync(profile.profilePath, original);
  }
  assertProductRuntimeAssets(profile);
});

test("asset capture rechecks directory identity after reading all files", async (t) => {
  const profile = await fixture(t);
  const approvals = path.join(profile.stateDir, "exec-approvals.json");
  const moved = profile.agentDir + ".previous";
  const originalFstat = fs.fstatSync;
  let injected = false;
  fs.fstatSync = function (fd, options) {
    const stat = originalFstat(fd, options);
    if (!injected && fs.readlinkSync(`/proc/self/fd/${fd}`) === approvals) {
      injected = true;
      renameSync(profile.agentDir, moved);
      mkdirSync(profile.agentDir, { mode: 0o700 });
    }
    return stat;
  };
  syncBuiltinESMExports();
  try {
    assert.throws(
      () => assertProductRuntimeAssets(profile),
      /product_assets_invalid/,
    );
    assert.equal(injected, true);
  } finally {
    fs.fstatSync = originalFstat;
    syncBuiltinESMExports();
    if (injected) {
      rmSync(profile.agentDir, { recursive: true });
      renameSync(moved, profile.agentDir);
    }
  }
  assertProductRuntimeAssets(profile);
});

test("Host session subdirectories may grow without permitting directory replacement", async (t) => {
  const profile = await fixture(t);
  mkdirSync(path.join(profile.stateDir, "agents", "main", "sessions"), {
    mode: 0o700,
  });
  mkdirSync(path.join(profile.agentDir, "sessions"), { mode: 0o700 });
  assertProductRuntimeAssets(profile);
  const moved = profile.agentDir + ".previous";
  renameSync(profile.agentDir, moved);
  mkdirSync(profile.agentDir, { mode: 0o700 });
  try {
    assert.throws(
      () => assertProductRuntimeAssets(profile),
      /product_assets_invalid/,
    );
  } finally {
    rmSync(profile.agentDir, { recursive: true });
    renameSync(moved, profile.agentDir);
  }
  assertProductRuntimeAssets(profile);
});

test("SDK approval usage updates and atomic replacement preserve only the same exact policy", async (t) => {
  const profile = await fixture(t);
  const filename = path.join(profile.stateDir, "exec-approvals.json");
  const file = JSON.parse(readFileSync(filename, "utf8"));
  Object.assign(file.agents.main.allowlist[0], {
    lastUsedAt: Date.now(),
    lastUsedCommand: "node marker.mjs",
    lastResolvedPath: profile.nodePath,
  });
  const replacement = filename + ".next";
  writeFileSync(replacement, JSON.stringify(file, null, 2) + "\n", {
    mode: 0o600,
  });
  renameSync(replacement, filename);
  assertProductRuntimeAssets(profile);
  assert.equal(
    loadProductRuntimeProfileSync(profile.configPath).assetCommitments
      .execApprovalsDigest,
    profile.assetCommitments.execApprovalsDigest,
  );
  for (const field of [
    "lastUsedCommand",
    "lastResolvedPath",
    "pattern",
    "source",
  ]) {
    const saved = file.agents.main.allowlist[0][field];
    file.agents.main.allowlist[0][field] = "unapproved";
    writeFileSync(filename, JSON.stringify(file, null, 2) + "\n");
    assert.throws(
      () => assertProductRuntimeAssets(profile),
      /product_assets_invalid/,
    );
    file.agents.main.allowlist[0][field] = saved;
  }
});

test("fixed command output permits owned regular results and rejects links or unsafe permissions", async (t) => {
  const profile = await fixture(t);
  const output = path.join(profile.workspaceDir, "command-marker.txt");
  const other = path.join(profile.workspaceDir, "other.txt");
  assertProductRuntimeAssets(profile);
  writeFileSync(output, "isolated command executed\n", { mode: 0o600 });
  assertProductRuntimeAssets(profile);
  chmodSync(output, 0o644);
  assert.throws(
    () => assertProductRuntimeAssets(profile),
    /product_assets_invalid/,
  );
  chmodSync(output, 0o600);
  linkSync(output, other);
  assert.throws(
    () => assertProductRuntimeAssets(profile),
    /product_assets_invalid/,
  );
  rmSync(output);
  symlinkSync(other, output);
  assert.throws(
    () => assertProductRuntimeAssets(profile),
    /product_assets_invalid/,
  );
});

test("actual pinned exec factory runs only the approved marker command", async (t) => {
  const profile = await fixture(t);
  // Run the unchanged actual SDK factory in a dedicated process so no personal env/state is mutated.
  const program = `
    import fs from 'node:fs';
    const {loadProductRuntimeProfileSync,assertProductRuntimeAssets}=await import(process.argv[1]);
    const {createOpenClawCodingTools}=await import(process.argv[2]);
    const p=loadProductRuntimeProfileSync(process.argv[3]);
    assertProductRuntimeAssets(p);
    // This resource test intentionally exercises the unwrapped actual SDK tools.
    // Complete Product registration/ACK authority is verified by the agent-loop suite.
    const tools=createOpenClawCodingTools({...p.toolOptions,config:{...p.config,plugins:{enabled:false}}});
    const exec=tools.find(t=>t.name==='exec');
    if(!exec) throw new Error('actual_exec_missing');
    const result=await exec.execute('real-marker-1',{command:'node marker.mjs'});
    if(result.details?.exitCode!==0) throw new Error('actual_exec_failed');
    let rejected=false;
    try{await exec.execute('rejected-marker-2',{command:'node other.mjs'});}catch{rejected=true;}
    if(!rejected) throw new Error('unapproved_command_not_rejected');
    assertProductRuntimeAssets(p);
    await tools.find(t=>t.name==='process').execute('real-process-3',{action:'list'});
    const read=await tools.find(t=>t.name==='read').execute('real-read-4',{path:'command-marker.txt'});
    if(!read.content.some(c=>c.type==='text'&&c.text.includes('isolated command executed'))) throw new Error('actual_read_failed');
    const text=fs.readFileSync(p.workspaceDir+'/command-marker.txt','utf8');
    if(text!=='isolated command executed\\n') throw new Error('unexpected_marker_count');
    process.stdout.write('product_actual_exec_passed\\n');
  `;
  const output = execFileSync(
    process.execPath,
    [
      "--input-type=module",
      "-e",
      program,
      new URL(
        "../packages/agentguard-openclaw-plugin/product-runtime/profile.mjs",
        import.meta.url,
      ).href,
      pathToFileURL(requireHost.resolve("openclaw/plugin-sdk/agent-harness"))
        .href,
      profile.configPath,
    ],
    {
      env: { ...profile.env },
      encoding: "utf8",
      timeout: 30000,
      maxBuffer: 16384,
    },
  );
  assert.ok(output.includes("product_actual_exec_passed"));
  assert.equal(
    readFileSync(path.join(profile.workspaceDir, "command-marker.txt"), "utf8"),
    "isolated command executed\n",
  );
});

test(
  "actual npm tgz installs its profile and assets without repository test modules",
  { timeout: 60000 },
  async (t) => {
    const root = rootFor(t);
    const sourceRoot = new URL(
      "../packages/agentguard-openclaw-plugin/",
      import.meta.url,
    );
    const packed = JSON.parse(
      execFileSync(
        "npm",
        [
          "pack",
          "--ignore-scripts",
          "--offline",
          "--json",
          "--pack-destination",
          root,
        ],
        {
          cwd: sourceRoot,
          env: {
            ...process.env,
            npm_config_cache: path.join(root, "npm-cache"),
          },
          encoding: "utf8",
          timeout: 30000,
          maxBuffer: 1024 * 1024,
        },
      ),
    );
    assert.equal(packed.length, 1);
    for (const name of [
      "profile.mjs",
      "profile.d.mts",
      "receipt-recovery.mjs",
      "receipt-recovery.d.mts",
      "factory.mjs",
      "factory.d.mts",
      "memory.mjs",
      "inbox.mjs",
      "message-permits.mjs",
      "marker.mjs",
    ])
      assert.ok(
        packed[0].files.some((f) => f.path === `product-runtime/${name}`),
      );
    execFileSync("tar", [
      "-xzf",
      path.join(root, packed[0].filename),
      "--no-same-owner",
      "-C",
      root,
    ]);
    const installed = path.join(root, "package");
    const recoveryImport = execFileSync(
      process.execPath,
      [
        "--input-type=module",
        "-e",
        `
      const entry = await import(${JSON.stringify(pathToFileURL(path.join(root, "package/product-runtime/receipt-recovery.mjs")).href)});
      if (Object.keys(entry).join() !== "openOpenClawProductReceiptRecovery") process.exitCode = 1;
      else process.stdout.write("receipts-only-import");
    `,
      ],
      { encoding: "utf8", timeout: 30000 },
    );
    assert.equal(recoveryImport, "receipts-only-import");
    for (const relative of [
      "package.json",
      "openclaw.plugin.json",
      "product-runtime/product/package.json",
      "product-runtime/product/openclaw.plugin.json",
    ])
      assert.equal(
        JSON.parse(readFileSync(path.join(installed, relative), "utf8"))
          .version,
        "0.1.0-rc.1",
      );
    mkdirSync(path.join(installed, "node_modules"));
    const hostRoot = path.dirname(
      path.dirname(
        path.dirname(requireHost.resolve("openclaw/plugin-sdk/agent-harness")),
      ),
    );
    assert.equal(
      JSON.parse(readFileSync(path.join(hostRoot, "package.json"), "utf8"))
        .name,
      "openclaw",
    );
    symlinkSync(
      hostRoot,
      path.join(installed, "node_modules", "openclaw"),
      "dir",
    );
    const production = await import(
      pathToFileURL(path.join(installed, "product-runtime", "profile.mjs")).href
    );
    const runRoot = path.join(root, "isolated-run");
    mkdirSync(runRoot, { mode: 0o700 });
    const profile = await production.createProductRuntimeProfile({
      root: runRoot,
      inboxUrl: "http://127.0.0.1:43123/inbox",
      provider,
      runManifestPath: path.join(runRoot, "run.json"),
    });
    production.assertProductRuntimeAssets(profile);
    assert.ok(
      profile.config.plugins.load.paths[0].startsWith(installed + path.sep),
    );
    assert.equal(
      profile.config.plugins.load.paths[0].includes("tests/support"),
      false,
    );
    for (const entry of packed[0].files.filter((f) =>
      /^product-runtime\/.*\.mjs$/u.test(f.path),
    ))
      assert.equal(
        readFileSync(path.join(installed, entry.path), "utf8").includes(
          "tests/support",
        ),
        false,
        entry.path,
      );
    const { createProductFixturePlugin: installedFactory } = await import(
      pathToFileURL(path.join(installed, "product-runtime", "factory.mjs")).href
    );
    const { createMessagePermitBridge: installedBridge } = await import(
      pathToFileURL(
        path.join(installed, "product-runtime", "message-permits.mjs"),
      ).href
    );
    const bridge = installedBridge({ sessionKey: profile.sessionKey });
    t.after(() => bridge.close());
    assert.ok(
      installedFactory({ profile, messagePermitBridge: bridge }).plugin,
    );
    // A profile/bridge from another module instance cannot be passed off as this installation's assembly.
    assert.throws(
      () =>
        createProductFixturePlugin({ profile, messagePermitBridge: bridge }),
      /product_fixture_assembly_invalid/,
    );
  },
);
