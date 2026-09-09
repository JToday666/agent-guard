import assert from "node:assert/strict";
import {
  mkdtempSync,
  readFileSync,
  readdirSync,
  rmSync,
  statSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { createServer } from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { DatabaseSync } from "node:sqlite";
import test from "node:test";

import plugin, {
  CHANNEL_ID,
  PLUGIN_ID,
  TOOL_NAMES,
  buildFixtureConfig,
  createFixtureChannel,
  createFixtureMemory,
  createFixtureTools,
  startFixtureInbox,
} from "../packages/agentguard-openclaw-plugin/product-runtime/index.mjs";
import {
  DEFAULT_INBOX_TARGET,
  PRODUCT_INBOX_TARGET,
  deliverInboxMessage,
  validateInboxTarget,
  validateInboxUrl,
} from "../packages/agentguard-openclaw-plugin/product-runtime/inbox.mjs";

function rootFor(t) {
  const root = mkdtempSync(join(tmpdir(), "agentguard-product-fixture-test-"));
  t.after(() => rmSync(root, { recursive: true, force: true }));
  return root;
}

function fixtureConfig(root, overrides = {}) {
  return buildFixtureConfig({
    acceptanceRoot: root,
    inboxUrl: "http://127.0.0.1:8765/inbox",
    ...overrides,
  });
}

const enabledConfig = { channels: { [CHANNEL_ID]: { enabled: true } } };

test("SQLite memory commits real rows and reads them through a new runtime instance", (t) => {
  const root = rootFor(t);
  const memory = createFixtureMemory(root);
  assert.deepEqual(memory.read({ key: "note" }), {
    key: "note",
    found: false,
    value: null,
  });
  assert.deepEqual(memory.write({ key: "note", value: "第一次写入" }), {
    key: "note",
    written: true,
  });
  memory.write({ key: "note", value: "更新后的值" });
  assert.deepEqual(createFixtureMemory(root).read({ key: "note" }), {
    key: "note",
    found: true,
    value: "更新后的值",
  });
  const database = new DatabaseSync(join(root, "memory.sqlite"), {
    readOnly: true,
  });
  try {
    assert.equal(
      database.prepare("SELECT value FROM memory WHERE key='note'").get().value,
      "更新后的值",
    );
    assert.equal(
      database.prepare("SELECT count(*) AS count FROM memory").get().count,
      1,
    );
  } finally {
    database.close();
  }
  assert.equal(statSync(join(root, "memory.sqlite")).mode & 0o777, 0o600);
});

test("memory rejects path escape, extra arguments and unbounded values without storing them", (t) => {
  const memory = createFixtureMemory(rootFor(t));
  for (const key of [
    "../escape",
    "/tmp/escape",
    "a/b",
    "",
    "x'.DROP",
    "x".repeat(129),
  ]) {
    assert.throws(
      () => memory.write({ key, value: "secret-value" }),
      /invalid_memory_parameters/u,
    );
  }
  assert.throws(
    () => memory.read({ key: "note", path: "/tmp/escape" }),
    /invalid_memory_parameters/u,
  );
  assert.throws(
    () => memory.write({ key: "note", value: "界".repeat(12000) }),
    /invalid_memory_value/u,
  );
  assert.throws(
    () => memory.write({ key: "note", value: { hidden: "secret-value" } }),
    /invalid_memory_value/u,
  );
  assert.equal(memory.read({ key: "note" }).found, false);
});

test("memory refuses database symlinks and SQLite sidecar symlinks", (t) => {
  const root = rootFor(t);
  const outside = join(rootFor(t), "sentinel");
  writeFileSync(outside, "must remain unchanged", { mode: 0o600 });
  symlinkSync(outside, join(root, "memory.sqlite"));
  assert.throws(
    () => createFixtureMemory(root).write({ key: "note", value: "new" }),
    /unsafe_database_file/u,
  );
  assert.equal(readFileSync(outside, "utf8"), "must remain unchanged");
  rmSync(join(root, "memory.sqlite"));
  symlinkSync(outside, join(root, "memory.sqlite-journal"));
  assert.throws(
    () => createFixtureMemory(root).write({ key: "note", value: "new" }),
    /unsafe_database_file/u,
  );
  assert.equal(readFileSync(outside, "utf8"), "must remain unchanged");
});

test("acceptance root must exist, be private, absolute and canonical", (t) => {
  const root = rootFor(t);
  const link = join(rootFor(t), "root-link");
  symlinkSync(root, link);
  for (const candidate of [
    "relative",
    "/",
    `${root}/../${root.split("/").at(-1)}`,
    link,
    join(root, "missing"),
  ]) {
    assert.throws(
      () => createFixtureMemory(candidate),
      /invalid_acceptance_root/u,
    );
  }
});

test("memory storage failures never expose caller data or local paths", (t) => {
  const root = rootFor(t);
  writeFileSync(join(root, "memory.sqlite"), "invalid sqlite secret database", {
    mode: 0o600,
  });
  assert.throws(
    () =>
      createFixtureMemory(root).write({
        key: "note",
        value: "private-message",
      }),
    (error) => error.message === "Product runtime fixture: storage_unavailable",
  );
});

test("fixture plugin metadata points to the native module and advertises its channel", () => {
  const manifest = JSON.parse(
    readFileSync(
      new URL(
        "../packages/agentguard-openclaw-plugin/product-runtime/baseline/openclaw.plugin.json",
        import.meta.url,
      ),
    ),
  );
  const metadata = JSON.parse(
    readFileSync(
      new URL(
        "../packages/agentguard-openclaw-plugin/product-runtime/baseline/package.json",
        import.meta.url,
      ),
    ),
  );
  assert.equal(manifest.id, PLUGIN_ID);
  assert.deepEqual(manifest.channels, [CHANNEL_ID]);
  assert.deepEqual(manifest.contracts.tools, TOOL_NAMES);
  assert.deepEqual(metadata.openclaw.extensions, ["./index.mjs"]);
  assert.equal(metadata.private, true);
});

test("setup/CLI metadata registration does not need configuration or touch storage", () => {
  for (const registrationMode of [
    "setup",
    "setup-only",
    "setup-runtime",
    "cli-metadata",
  ]) {
    plugin.register({
      registrationMode,
      get pluginConfig() {
        assert.fail("read configuration during metadata/setup");
      },
      registerTool() {
        assert.fail("registered a tool during metadata/setup");
      },
      registerChannel() {
        assert.fail("registered a channel during metadata/setup");
      },
    });
  }
});

test("pinned Host discovery modes expose real memory tools without registration side effects", async (t) => {
  for (const registrationMode of ["discovery", "tool-discovery"]) {
    const root = rootFor(t);
    const tools = [];
    const channels = [];
    plugin.register({
      registrationMode,
      pluginConfig: fixtureConfig(root),
      registerTool: (tool) => tools.push(tool),
      registerChannel: (channel) => channels.push(channel),
    });
    assert.deepEqual(
      tools.map((tool) => tool.name),
      TOOL_NAMES,
    );
    assert.equal(channels.length, registrationMode === "discovery" ? 1 : 0);
    assert.deepEqual(readdirSync(root), []);
    await tools[1].execute("discovery-call", {
      key: "note",
      value: "native-discovery-write",
    });
    assert.equal(
      (await tools[0].execute("discovery-read", { key: "note" })).details.value,
      "native-discovery-write",
    );
  }
});

test("full registration exposes two real tools and the SDK channel registration object", async (t) => {
  const tools = [];
  const channels = [];
  plugin.register({
    registrationMode: "full",
    pluginConfig: fixtureConfig(rootFor(t)),
    registerTool: (tool) => tools.push(tool),
    registerChannel: (channel) => channels.push(channel),
  });
  assert.deepEqual(
    tools.map((tool) => tool.name),
    TOOL_NAMES,
  );
  assert.equal(channels[0].plugin.id, CHANNEL_ID);
  const written = await tools[1].execute("tool-call-1", {
    key: "note",
    value: "real tool write",
  });
  assert.equal(written.details.written, true);
  const read = await tools[0].execute("tool-call-2", { key: "note" });
  assert.equal(read.details.value, "real tool write");
  assert.equal(JSON.parse(read.content[0].text).value, "real tool write");
});

test("fixture config rejects unknown fields and non-loopback inbox addresses", (t) => {
  const root = rootFor(t);
  assert.throws(
    () => fixtureConfig(root, { providerToken: "must-not-log" }),
    /invalid_fixture_config/u,
  );
  for (const inboxUrl of [
    "https://127.0.0.1:1234/inbox",
    "http://localhost:1234/inbox",
    "http://example.com:1234/inbox",
    "http://127.0.0.2:1234/inbox",
    "http://2130706433:1234/inbox",
    "http://127.0.0.1:1234/inbox?token=secret",
    "http://127.0.0.1:1234/inbox#fragment",
    "http://user:secret@127.0.0.1:1234/inbox",
    "http://127.0.0.1:1234/../inbox",
    "http://127.0.0.1:1234/other",
    "http://127.0.0.1:99999/inbox",
  ]) {
    assert.throws(
      () => fixtureConfig(root, { inboxUrl }),
      (error) =>
        error.message === "Product runtime fixture: invalid_loopback_inbox_url",
    );
  }
  assert.equal(validateInboxUrl("http://[::1]:1234/inbox").hostname, "[::1]");
});

test("inbox target validator preserves baseline names and admits only the exact Product alias", () => {
  for (const target of [
    DEFAULT_INBOX_TARGET,
    "other-fixture",
    PRODUCT_INBOX_TARGET,
  ])
    assert.equal(validateInboxTarget(target), target);
  for (const target of [
    "other@agentguard.invalid",
    "fixture-inbox@example.com",
    "Fixture-inbox@agentguard.invalid",
    "fixture-inbox@AgentGuard.invalid",
    ` ${PRODUCT_INBOX_TARGET}`,
    `${PRODUCT_INBOX_TARGET} `,
    `mailto:${PRODUCT_INBOX_TARGET}`,
    `http://${PRODUCT_INBOX_TARGET}/inbox`,
  ])
    assert.throws(() => validateInboxTarget(target), /invalid_inbox_target/u);
});

test("explicit Product alias reaches only literal loopback and remains exact in SQLite readback", async (t) => {
  const root = rootFor(t);
  const inbox = await startFixtureInbox({
    acceptanceRoot: root,
    target: PRODUCT_INBOX_TARGET,
  });
  t.after(() => inbox.close());
  assert.match(inbox.url, /^http:\/\/127\.0\.0\.1:[0-9]+\/inbox$/u);
  for (const target of [
    DEFAULT_INBOX_TARGET,
    "other@agentguard.invalid",
    ` ${PRODUCT_INBOX_TARGET}`,
  ]) {
    const response = await fetch(inbox.url, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ target, text: "must not arrive" }),
    });
    assert.equal(response.status, 400);
    await response.text();
  }
  assert.deepEqual(inbox.readMessages(), []);
  const result = await deliverInboxMessage({
    inboxUrl: inbox.url,
    inboxTarget: PRODUCT_INBOX_TARGET,
    to: PRODUCT_INBOX_TARGET,
    text: "local alias message",
  });
  assert.deepEqual(inbox.readMessages(), [
    {
      messageId: result.messageId,
      target: PRODUCT_INBOX_TARGET,
      text: "local alias message",
    },
  ]);
});

test("channel outbound sends a real HTTP message with SQLite readback after inbox restart", async (t) => {
  const root = rootFor(t);
  const inbox = await startFixtureInbox({ acceptanceRoot: root });
  let restarted;
  t.after(async () => {
    await (restarted ?? inbox).close();
  });
  const channel = createFixtureChannel(
    fixtureConfig(root, { inboxUrl: inbox.url }),
  );
  let dispatched = false;
  const result = await channel.outbound.sendText({
    cfg: enabledConfig,
    to: inbox.target,
    text: "真实的本机消息",
    onPlatformSendDispatch: async () => {
      dispatched = true;
    },
  });
  assert.equal(dispatched, true);
  assert.equal(result.channel, CHANNEL_ID);
  assert.deepEqual(inbox.readMessages(), [
    {
      messageId: result.messageId,
      target: inbox.target,
      text: "真实的本机消息",
    },
  ]);
  await inbox.close();
  restarted = await startFixtureInbox({ acceptanceRoot: root });
  assert.equal(restarted.readMessages()[0].messageId, result.messageId);
  assert.equal(statSync(join(root, "inbox.sqlite")).mode & 0o777, 0o600);
});

test("channel refuses outside recipients, disabled accounts and media without delivery", async (t) => {
  const root = rootFor(t);
  const inbox = await startFixtureInbox({ acceptanceRoot: root });
  t.after(() => inbox.close());
  const channel = createFixtureChannel(
    fixtureConfig(root, { inboxUrl: inbox.url }),
  );
  assert.deepEqual(channel.config.listAccountIds(enabledConfig), ["default"]);
  assert.equal(channel.config.resolveAccount(enabledConfig).enabled, true);
  assert.equal(channel.outbound.resolveTarget({ to: "elsewhere" }).ok, false);
  assert.equal(channel.outbound.resolveTarget({ to: inbox.target }).ok, true);
  for (const context of [
    { cfg: enabledConfig, to: "elsewhere" },
    { cfg: {}, to: inbox.target },
    { cfg: enabledConfig, to: inbox.target, accountId: "other" },
    {
      cfg: enabledConfig,
      to: inbox.target,
      mediaUrl: "http://example.com/private",
    },
    { cfg: enabledConfig, to: inbox.target, threadId: "other" },
  ]) {
    await assert.rejects(
      channel.outbound.sendText({ ...context, text: "do not send" }),
    );
  }
  assert.deepEqual(inbox.readMessages(), []);
});

test("inbox rejects wrong paths, content types, recipients, extra fields and malformed JSON", async (t) => {
  const inbox = await startFixtureInbox({ acceptanceRoot: rootFor(t) });
  t.after(() => inbox.close());
  for (const [url, type, body] of [
    [inbox.url.replace("/inbox", "/other"), "application/json", "{}"],
    [inbox.url, "text/plain", "{}"],
    [inbox.url, "application/json", "{"],
    [
      inbox.url,
      "application/json",
      JSON.stringify({ target: "outside", text: "bad" }),
    ],
    [
      inbox.url,
      "application/json",
      JSON.stringify({
        target: inbox.target,
        text: "bad",
        path: "/tmp/outside",
      }),
    ],
  ]) {
    const response = await fetch(url, {
      method: "POST",
      headers: { "Content-Type": type },
      body,
    });
    assert.equal(response.status, 400);
    await response.text();
  }
  assert.deepEqual(inbox.readMessages(), []);
});

test("outbound refuses redirects and masks response text rather than following another target", async (t) => {
  const server = createServer((_req, res) => {
    res.writeHead(302, { Location: "http://example.com/secret" });
    res.end("private remote detail");
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  t.after(() => new Promise((resolve) => server.close(resolve)));
  await assert.rejects(
    deliverInboxMessage({
      inboxUrl: `http://127.0.0.1:${server.address().port}/inbox`,
      to: "fixture-inbox",
      text: "message",
    }),
    (error) =>
      error.message === "Product runtime fixture: inbox_delivery_failed",
  );
});

test("failed dispatch callback prevents the real channel side effect", async (t) => {
  const root = rootFor(t);
  const inbox = await startFixtureInbox({ acceptanceRoot: root });
  t.after(() => inbox.close());
  const channel = createFixtureChannel(
    fixtureConfig(root, { inboxUrl: inbox.url }),
  );
  await assert.rejects(
    channel.outbound.sendText({
      cfg: enabledConfig,
      to: inbox.target,
      text: "blocked",
      onPlatformSendDispatch: async () => {
        throw new Error("dispatch cancelled");
      },
    }),
    /dispatch cancelled/u,
  );
  assert.deepEqual(inbox.readMessages(), []);
});

test("tool parameter schema names and execution reject filesystem override arguments", async (t) => {
  const tools = createFixtureTools(fixtureConfig(rootFor(t)));
  assert.deepEqual(tools[1].parameters.required, ["key", "value"]);
  await assert.rejects(
    tools[1].execute("id", {
      key: "note",
      value: "value",
      databasePath: "/tmp/escape",
    }),
    /invalid_memory_parameters/u,
  );
});

test("an already cancelled host tool call cannot commit a memory write", async (t) => {
  const root = rootFor(t);
  const tools = createFixtureTools(fixtureConfig(root));
  await assert.rejects(
    tools[1].execute(
      "cancelled",
      { key: "note", value: "not committed" },
      AbortSignal.abort(),
    ),
    /fixture_tool_cancelled/u,
  );
  assert.equal(createFixtureMemory(root).read({ key: "note" }).found, false);
});
