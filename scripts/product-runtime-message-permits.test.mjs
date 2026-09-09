import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { mkdtempSync, rmSync } from "node:fs";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { createRequire } from "node:module";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { pathToFileURL } from "node:url";
import test from "node:test";

import defaultPlugin, {
  CHANNEL_ID,
  buildFixtureConfig,
  createFixtureChannel,
  createFixturePlugin,
  createMessagePermitBridge,
  startFixtureInbox,
} from "../packages/agentguard-openclaw-plugin/product-runtime/index.mjs";
import { createBaselineRuntimeProfile as createProductRuntimeProfile } from "../packages/agentguard-openclaw-plugin/product-runtime/baseline-profile.mjs";
import {
  readNativeProductAfter,
  snapshotNativeProductResult,
} from "../packages/agentguard-openclaw-plugin/dist/mapping/product-events.js";

import { PRODUCT_INBOX_TARGET } from "../packages/agentguard-openclaw-plugin/product-runtime/inbox.mjs";

const SESSION = "agent:main:product-message-test";
const ARGS = Object.freeze({
  action: "send",
  channel: CHANNEL_ID,
  target: PRODUCT_INBOX_TARGET,
  message: "完整本机消息",
});
const canonical = (value) =>
  JSON.stringify(
    Object.fromEntries(
      Object.entries(value).sort(([a], [b]) => a.localeCompare(b, "en")),
    ),
  );
const cfg = { channels: { [CHANNEL_ID]: { enabled: true } } };

function release(overrides = {}) {
  return {
    runId: "run-1",
    toolCallId: "call-1",
    sessionKey: SESSION,
    toolName: "message",
    argumentsJson: canonical(ARGS),
    actionId: "act-1",
    assertCanSend() {},
    async assertReadyToSend() {},
    onMessageDelivered() {},
    ...overrides,
  };
}
// Pinned SDK computes this before its target normalization adds `to`.
function prepareInput(released = release(), { accountId } = {}) {
  const args = JSON.parse(released.argumentsJson);
  const preNormalized = accountId ? { ...args, accountId } : args;
  const sorted = (value) =>
    value && typeof value === "object"
      ? Object.fromEntries(
          Object.keys(value)
            .sort()
            .map((key) => [key, sorted(value[key])]),
        )
      : value;
  const fingerprint = createHash("sha256")
    .update(JSON.stringify(sorted({ action: "send", params: preNormalized })))
    .digest("base64url")
    .slice(0, 24);
  return {
    ctx: {
      channel: CHANNEL_ID,
      action: "send",
      sessionKey: released.sessionKey,
      accountId,
      dryRun: false,
      params: {
        ...preNormalized,
        to: args.target,
        presentation: undefined,
        interactive: undefined,
        idempotencyKey: `${released.runId}:message-tool:${fingerprint}:${released.toolCallId}`,
      },
    },
    to: args.target,
    payload: { text: args.message },
  };
}
function outbound(payload) {
  return {
    cfg,
    accountId: "default",
    to: ARGS.target,
    text: payload.text,
    payload,
  };
}
async function fixture(t) {
  const root = mkdtempSync(join(tmpdir(), "agentguard-message-permit-"));
  const inbox = await startFixtureInbox({
    acceptanceRoot: root,
    target: PRODUCT_INBOX_TARGET,
  });
  t.after(async () => {
    await inbox.close();
    rmSync(root, { force: true, recursive: true });
  });
  const config = buildFixtureConfig({
    acceptanceRoot: root,
    inboxUrl: inbox.url,
    inboxTarget: PRODUCT_INBOX_TARGET,
  });
  const bridge = createMessagePermitBridge({ sessionKey: SESSION });
  const channel = createFixtureChannel(config, {
    productMode: true,
    messagePermitBridge: bridge,
  });
  return { config, bridge, channel, inbox };
}

test("trusted Product factory rejects missing or JSON-impostor bridge before registration; default fixture stays non-Product", async (t) => {
  const { config, bridge } = await fixture(t);
  let registrations = 0;
  const api = {
    pluginConfig: config,
    registerTool() {
      registrations += 1;
    },
    registerChannel() {
      registrations += 1;
    },
  };
  for (const registrationMode of ["full", "discovery", "tool-discovery"]) {
    for (const messagePermitBridge of [undefined, {}, { authorize() {} }]) {
      assert.throws(
        () =>
          createFixturePlugin({
            productMode: true,
            messagePermitBridge,
          }).register({ ...api, registrationMode }),
        /fixture_message_bridge_required/u,
      );
    }
  }
  assert.equal(registrations, 0);
  const channels = [];
  const tools = [];
  createFixturePlugin({
    productMode: true,
    messagePermitBridge: bridge,
  }).register({
    ...api,
    registerTool(x) {
      tools.push(x);
    },
    registerChannel(x) {
      channels.push(x.plugin);
    },
  });
  assert.equal(tools.length, 2);
  assert.equal(channels.length, 1);
  assert.equal(typeof channels[0].actions.prepareSendPayload, "function");
  const defaults = [];
  defaultPlugin.register({
    ...api,
    registerChannel(x) {
      defaults.push(x.plugin);
    },
  });
  assert.equal(defaults[0].actions, undefined);
  assert.equal(typeof defaults[0].outbound.sendText, "function");
});

for (const target of [
  "fixture-inbox",
  "other@agentguard.invalid",
  "fixture-inbox@example.com",
  "Fixture-inbox@agentguard.invalid",
  "fixture-inbox@AgentGuard.invalid",
  ` ${PRODUCT_INBOX_TARGET}`,
  `${PRODUCT_INBOX_TARGET} `,
  `mailto:${PRODUCT_INBOX_TARGET}`,
  `http://${PRODUCT_INBOX_TARGET}/inbox`,
])
  test(`Product rejects recipient ${JSON.stringify(target)} before registration, permit or sending`, async (t) => {
    const { config, bridge, channel, inbox } = await fixture(t);
    assert.throws(
      () =>
        createMessagePermitBridge({ sessionKey: SESSION, inboxTarget: target }),
      /fixture_message_permit_invalid/u,
    );
    assert.throws(
      () =>
        createFixtureChannel(
          { ...config, inboxTarget: target },
          { productMode: true, messagePermitBridge: bridge },
        ),
      /invalid_product_inbox_target/u,
    );
    let registrations = 0;
    for (const registrationMode of ["full", "discovery", "tool-discovery"])
      assert.throws(
        () =>
          createFixturePlugin({
            productMode: true,
            messagePermitBridge: bridge,
          }).register({
            registrationMode,
            pluginConfig: { ...config, inboxTarget: target },
            registerTool() {
              registrations += 1;
            },
            registerChannel() {
              registrations += 1;
            },
          }),
        /invalid_(?:product_)?inbox_target/u,
      );
    assert.equal(registrations, 0);
    assert.equal(channel.messaging.normalizeTarget(target), undefined);
    assert.equal(channel.messaging.targetResolver.looksLikeId(target), false);
    assert.equal(channel.outbound.resolveTarget({ to: target }).ok, false);
    assert.throws(
      () =>
        bridge.authorize(
          release({ argumentsJson: canonical({ ...ARGS, target }) }),
        ),
      /fixture_message_permit_invalid/u,
    );
    await assert.rejects(
      channel.outbound.sendPayload({
        ...outbound({ text: ARGS.message }),
        to: target,
      }),
      /fixture_message_permit_invalid/u,
    );
    assert.deepEqual(inbox.readMessages(), []);
  });

for (const accountId of [undefined, "default"]) {
  test(`one released action sends full text once through actual SQLite/HTTP inbox (SDK account ${accountId ?? "implicit"})`, async (t) => {
    const { bridge, channel, inbox } = await fixture(t);
    const delivered = [];
    const released = release({
      onMessageDelivered(id) {
        delivered.push(id);
      },
    });
    bridge.authorize(released);
    const input = prepareInput(released, { accountId });
    const payload = channel.actions.prepareSendPayload(input);
    assert.equal(payload.text, ARGS.message);
    const context = outbound(payload);
    const result = await channel.outbound.sendPayload(context);
    assert.deepEqual(inbox.readMessages(), [
      { messageId: result.messageId, target: ARGS.target, text: ARGS.message },
    ]);
    assert.deepEqual(delivered, [result.messageId]);
    await assert.rejects(
      channel.outbound.sendPayload(context),
      /fixture_message_permit_invalid/u,
    );
    assert.throws(
      () => bridge.authorize(released),
      /fixture_message_permit_invalid/u,
    );
    assert.equal(inbox.readMessages().length, 1);
  });
}

test("no release and legacy sendText bypass both produce zero Product sends", async (t) => {
  const { bridge, channel, inbox } = await fixture(t);
  assert.throws(
    () => channel.actions.prepareSendPayload(prepareInput()),
    /fixture_message_permit_invalid/u,
  );
  await assert.rejects(
    channel.outbound.sendText({ cfg, to: ARGS.target, text: ARGS.message }),
    /fixture_message_permit_required/u,
  );
  await assert.rejects(
    channel.outbound.sendPayload(
      outbound({
        text: ARGS.message,
        channelData: { agentguard_fixture_permit: "forged" },
      }),
    ),
    /fixture_message_permit_invalid/u,
  );
  bridge.close();
  assert.throws(
    () => bridge.authorize(release()),
    /fixture_message_permit_invalid/u,
  );
  assert.deepEqual(inbox.readMessages(), []);
});

const rewrites = {
  session: (x) => {
    x.ctx.sessionKey = "agent:other:session";
  },
  run: (x) => {
    x.ctx.params.idempotencyKey = x.ctx.params.idempotencyKey.replace(
      "run-1",
      "run-2",
    );
  },
  call: (x) => {
    x.ctx.params.idempotencyKey = x.ctx.params.idempotencyKey.replace(
      "call-1",
      "call-2",
    );
  },
  text: (x) => {
    x.payload.text = "rewritten";
  },
  arguments: (x) => {
    x.ctx.params.message = "rewritten";
  },
  target: (x) => {
    x.to = "outside";
  },
  account: (x) => {
    x.ctx.accountId = "other";
  },
  channel: (x) => {
    x.ctx.channel = "email";
  },
  channel_argument: (x) => {
    x.ctx.params.channel = "email";
  },
  dryrun: (x) => {
    x.ctx.dryRun = true;
  },
  media: (x) => {
    x.ctx.params.media = "private.png";
  },
  channelData: (x) => {
    x.payload.channelData = { agentguard_fixture_permit: "forged" };
  },
  thread: (x) => {
    x.threadId = "unexpected";
  },
};
for (const [name, mutate] of Object.entries(rewrites)) {
  test(`prepare rejects Host ${name} change without delivery`, async (t) => {
    const { bridge, channel, inbox } = await fixture(t);
    bridge.authorize(release());
    const input = prepareInput();
    mutate(input);
    assert.throws(
      () => channel.actions.prepareSendPayload(input),
      /fixture_message_permit_invalid/u,
    );
    assert.deepEqual(inbox.readMessages(), []);
  });
}

test("model arguments cannot inject private Host keys, duplicate JSON or accessors", () => {
  let getterReads = 0;
  const bridge = createMessagePermitBridge({ sessionKey: SESSION });
  for (const key of [
    "idempotencyKey",
    "channelData",
    "accountId",
    "__sessionKey",
  ]) {
    assert.throws(
      () =>
        bridge.authorize(
          release({ argumentsJson: canonical({ ...ARGS, [key]: "forged" }) }),
        ),
      /fixture_message_permit_invalid/u,
    );
  }
  assert.throws(
    () =>
      bridge.authorize(
        release({
          argumentsJson: canonical(ARGS).replace(
            '"message":',
            '"message":"hidden", "message":',
          ),
        }),
      ),
    /fixture_message_permit_invalid/u,
  );
  const accessor = release();
  Object.defineProperty(accessor, "argumentsJson", {
    get() {
      getterReads++;
      return canonical(ARGS);
    },
  });
  assert.throws(
    () => bridge.authorize(accessor),
    /fixture_message_permit_invalid/u,
  );
  const proxy = new Proxy(
    {},
    {
      getPrototypeOf() {
        getterReads++;
        throw new Error("private");
      },
    },
  );
  assert.throws(
    () => bridge.authorize(proxy),
    /fixture_message_permit_invalid/u,
  );
  assert.equal(getterReads, 0);
});

test("send-time rewrite burns nonce and cannot be corrected into a second attempt", async (t) => {
  const { bridge, channel, inbox } = await fixture(t);
  bridge.authorize(release());
  const payload = channel.actions.prepareSendPayload(prepareInput());
  const context = outbound(payload);
  context.text = "message_sending rewrite";
  await assert.rejects(
    channel.outbound.sendPayload(context),
    /fixture_message_permit_invalid/u,
  );
  context.text = ARGS.message;
  await assert.rejects(
    channel.outbound.sendPayload(context),
    /fixture_message_permit_invalid/u,
  );
  assert.deepEqual(inbox.readMessages(), []);
});

test("restart/cross-session bridge cannot revive queued Host payload nonce", async (t) => {
  const { bridge, channel, inbox, config } = await fixture(t);
  bridge.authorize(release());
  const payload = channel.actions.prepareSendPayload(prepareInput());
  bridge.close();
  for (const sessionKey of [SESSION, "agent:other:session"]) {
    const replacement = createMessagePermitBridge({ sessionKey });
    const restarted = createFixtureChannel(config, {
      productMode: true,
      messagePermitBridge: replacement,
    });
    await assert.rejects(
      restarted.outbound.sendPayload(outbound(payload)),
      /fixture_message_permit_invalid/u,
    );
  }
  assert.deepEqual(inbox.readMessages(), []);
});

for (const phase of ["before_claim", "during_dispatch"]) {
  test(`closed coordinator at ${phase} prevents actual platform send`, async (t) => {
    const { bridge, channel, inbox } = await fixture(t);
    let closed = false;
    bridge.authorize(
      release({
        assertCanSend() {
          if (closed) throw new Error("private breaker detail");
        },
      }),
    );
    const payload = channel.actions.prepareSendPayload(prepareInput());
    if (phase === "before_claim") closed = true;
    await assert.rejects(
      channel.outbound.sendPayload({
        ...outbound(payload),
        onPlatformSendDispatch: async () => {
          closed = true;
        },
      }),
      /fixture_message_permit_invalid/u,
    );
    assert.deepEqual(inbox.readMessages(), []);
  });
}

test("async dispatch context mutation never substitutes evaluated full text or target", async (t) => {
  const { bridge, channel, inbox } = await fixture(t);
  bridge.authorize(release());
  const payload = channel.actions.prepareSendPayload(prepareInput());
  const context = outbound(payload);
  context.onPlatformSendDispatch = async () => {
    context.text = "mutated";
    context.to = "outside";
    payload.text = "mutated";
  };
  await channel.outbound.sendPayload(context);
  assert.deepEqual(
    inbox.readMessages().map(({ text, target }) => ({ text, target })),
    [{ text: ARGS.message, target: ARGS.target }],
  );
});

test("failed dispatch callback masks private details and burns the send permit", async (t) => {
  const { bridge, channel, inbox } = await fixture(t);
  bridge.authorize(release());
  const payload = channel.actions.prepareSendPayload(prepareInput());
  await assert.rejects(
    channel.outbound.sendPayload({
      ...outbound(payload),
      onPlatformSendDispatch() {
        throw new Error("private dispatch detail");
      },
    }),
    (error) =>
      error.message ===
      "Product runtime fixture: fixture_message_dispatch_failed",
  );
  await assert.rejects(
    channel.outbound.sendPayload(outbound(payload)),
    /fixture_message_permit_invalid/u,
  );
  assert.deepEqual(inbox.readMessages(), []);
});

for (const stage of ["before_dispatch", "after_dispatch"]) {
  test(`current async session rejection at ${stage} prevents actual HTTP send`, async (t) => {
    const { bridge, channel, inbox } = await fixture(t);
    let checks = 0;
    let dispatched = false;
    bridge.authorize(
      release({
        async assertReadyToSend() {
          checks++;
          if (stage === "before_dispatch" || dispatched)
            throw new Error("private runtime drift");
        },
      }),
    );
    const payload = channel.actions.prepareSendPayload(prepareInput());
    await assert.rejects(
      channel.outbound.sendPayload({
        ...outbound(payload),
        onPlatformSendDispatch: async () => {
          dispatched = true;
        },
      }),
      /fixture_message_permit_invalid/u,
    );
    assert.equal(checks, stage === "before_dispatch" ? 1 : 2);
    assert.deepEqual(inbox.readMessages(), []);
    await assert.rejects(
      channel.outbound.sendPayload(outbound(payload)),
      /fixture_message_permit_invalid/u,
    );
  });
}

test("close while awaiting fresh session observation prevents sending after a late success", async (t) => {
  const { bridge, channel, inbox } = await fixture(t);
  let resume;
  const paused = new Promise((resolve) => {
    resume = resolve;
  });
  let entered;
  const started = new Promise((resolve) => {
    entered = resolve;
  });
  bridge.authorize(
    release({
      async assertReadyToSend() {
        entered();
        await paused;
      },
    }),
  );
  const payload = channel.actions.prepareSendPayload(prepareInput());
  const pending = channel.outbound.sendPayload(outbound(payload));
  await started;
  bridge.close();
  resume();
  await assert.rejects(pending, /fixture_message_permit_invalid/u);
  assert.deepEqual(inbox.readMessages(), []);
});

for (const key of ["replyToTag", "audioAsVoice"]) {
  test(`pinned SDK ${key}=false sentinel is harmless; true remains rejected`, async (t) => {
    const { bridge, channel, inbox } = await fixture(t);
    bridge.authorize(release());
    const payload = channel.actions.prepareSendPayload(prepareInput());
    payload[key] = true;
    await assert.rejects(
      channel.outbound.sendPayload(outbound(payload)),
      /fixture_message_permit_invalid/u,
    );
    assert.deepEqual(inbox.readMessages(), []);
  });
}

test(
  "pinned SDK factory uses actually registered Product channel with synthetic release and real loopback delivery",
  { timeout: 60_000 },
  async (t) => {
    // A trusted test wrapper stands in for the later complete Host assembly. This
    // tests the real SDK factory/action runner/channel, not model/Guard authority.
    const { config, inbox } = await fixture(t);
    const root = config.acceptanceRoot;
    const fixtureUrl = new URL(
      "../packages/agentguard-openclaw-plugin/product-runtime/baseline/",
      import.meta.url,
    );
    const wrapper = join(root, "trusted-wrapper");
    await mkdir(wrapper, { mode: 0o700 });
    for (const name of ["package.json", "openclaw.plugin.json"]) {
      const metadata = JSON.parse(
        await readFile(new URL(name, fixtureUrl), "utf8"),
      );
      if (name === "openclaw.plugin.json")
        metadata.configSchema.properties.inboxTarget = {
          type: "string",
          const: PRODUCT_INBOX_TARGET,
          default: PRODUCT_INBOX_TARGET,
        };
      await writeFile(join(wrapper, name), JSON.stringify(metadata), {
        mode: 0o600,
      });
    }
    const profile = await createProductRuntimeProfile({
      root,
      inboxUrl: inbox.url,
      modelBaseUrl: "http://127.0.0.1:1/v1",
      fixturePluginPath: wrapper,
    });
    // This test explicitly promotes a baseline profile into Product assembly.
    profile.config.plugins.entries[
      "agentguard-product-runtime-fixture"
    ].config.inboxTarget = PRODUCT_INBOX_TARGET;
    profile.toolOptions.messageTo = PRODUCT_INBOX_TARGET;
    await writeFile(profile.configPath, JSON.stringify(profile.config), {
      mode: 0o600,
    });
    const synthetic = release({ sessionKey: profile.sessionKey });
    const {
      assertCanSend: _assert,
      assertReadyToSend: _ready,
      onMessageDelivered: _delivered,
      ...identity
    } = synthetic;
    await writeFile(
      join(wrapper, "index.mjs"),
      `
import {createFixturePlugin,createMessagePermitBridge} from ${JSON.stringify(new URL("index.mjs", fixtureUrl).href)};
export default {id:"agentguard-product-runtime-fixture",name:"synthetic release test wrapper",register(api){
  const bridge=createMessagePermitBridge({sessionKey:${JSON.stringify(profile.sessionKey)}});
  bridge.authorize({...${JSON.stringify(identity)},assertCanSend(){},async assertReadyToSend(){},onMessageDelivered(){}});
  createFixturePlugin({productMode:true,messagePermitBridge:bridge}).register(api);
}};`,
      { mode: 0o600 },
    );
    const env = { ...profile.env, OPENCLAW_AGENT_DIR: profile.agentDir };
    const before = Object.fromEntries(
      Object.keys(env).map((key) => [key, process.env[key]]),
    );
    t.after(() => {
      for (const [key, value] of Object.entries(before)) {
        if (value === undefined) delete process.env[key];
        else process.env[key] = value;
      }
    });
    Object.assign(process.env, env);
    const requireHost = createRequire(
      new URL(
        "../packages/agentguard-openclaw-plugin/package.json",
        import.meta.url,
      ),
    );
    const hostRoot = join(requireHost.resolve("openclaw"), "..", "..");
    assert.equal(
      JSON.parse(await readFile(join(hostRoot, "package.json"), "utf8"))
        .version,
      "2026.7.1-2",
    );
    const loader = await import(
      pathToFileURL(join(hostRoot, "dist/plugins/loader.js")).href
    );
    const registry = loader.loadOpenClawPlugins({
      config: profile.config,
      workspaceDir: profile.workspaceDir,
      env: { ...process.env },
      cache: false,
      activate: true,
      forceFullRuntimeForChannelPlugins: true,
      onlyPluginIds: ["agentguard-product-runtime-fixture"],
      throwOnLoadError: true,
    });
    assert.equal(registry.channels.length, 1);
    const sdk = await import(
      pathToFileURL(requireHost.resolve("openclaw/plugin-sdk/agent-harness"))
        .href
    );
    const tools = sdk.createOpenClawCodingTools({
      ...profile.toolOptions,
      agentAccountId: "default",
      runId: synthetic.runId,
    });
    const message = tools.find((tool) => tool.name === "message");
    assert.ok(message);
    const args = { ...ARGS };
    const result = await message.execute(synthetic.toolCallId, args);
    assert.deepEqual(args, ARGS);
    assert.equal(result.isError ?? false, false);
    assert.equal(result.details.deliveryStatus, "sent");
    // The actual pinned emitter retains this optional own undefined value, and
    // its middleware validator accepts it unchanged. Normalize only the path
    // owned by this verified message call before taking our strict snapshot.
    assert.equal(Object.hasOwn(result.details, "mediaUrls"), true);
    assert.equal(result.details.mediaUrls, undefined);
    assert.equal(result.details.mediaUrl, null);
    assert.throws(() => snapshotNativeProductResult(result));
    const { t: createActualMiddlewareRunner } = await import(
      pathToFileURL(join(hostRoot, "dist/tool-result-middleware-D2HOtSKh.js"))
        .href
    );
    let observed = false;
    const runner = createActualMiddlewareRunner({ runtime: "openclaw" }, [
      async (event) => {
        assert.equal(event.toolName, "message");
        assert.deepEqual(event.args, ARGS);
        assert.equal(Object.hasOwn(event.result.details, "mediaUrls"), true);
        assert.equal(event.result.details.mediaUrls, undefined);
        observed = true;
        return {
          result: snapshotNativeProductResult(event.result, event.toolName),
        };
      },
    ]);
    const normalized = await runner.applyToolResultMiddleware({
      toolCallId: synthetic.toolCallId,
      toolName: "message",
      args,
      isError: false,
      result,
    });
    assert.equal(observed, true);
    assert.equal(Object.hasOwn(normalized.details, "mediaUrls"), false);
    assert.equal(normalized.details.mediaUrl, null);
    assert.deepEqual(
      readNativeProductAfter({ result }, "message"),
      readNativeProductAfter({ result: normalized }, "message"),
    );
    assert.equal(Object.hasOwn(result.details, "mediaUrls"), true);
    assert.deepEqual(inbox.readMessages(), [
      {
        messageId: result.details.result.messageId,
        target: ARGS.target,
        text: ARGS.message,
      },
    ]);
    // A different Host call cannot borrow the first one-shot bridge permission.
    await assert.rejects(
      message.execute("call-other", { ...ARGS }),
      /fixture_message_permit_invalid/u,
    );
    assert.equal(inbox.readMessages().length, 1);
  },
);
