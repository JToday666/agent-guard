/** Installable isolated tools; the default entry has no Product activation. */
import {
  createFixtureMemory,
  FixtureError,
  requireAcceptanceRoot,
} from "./memory.mjs";
import {
  DEFAULT_INBOX_TARGET,
  PRODUCT_INBOX_TARGET,
  MAX_MESSAGE_BYTES,
  deliverInboxMessage,
  validateInboxTarget,
  validateInboxUrl,
} from "./inbox.mjs";

import { isMessagePermitBridge } from "./message-permits.mjs";
export { createMessagePermitBridge } from "./message-permits.mjs";

export { createFixtureMemory, FixtureError } from "./memory.mjs";
export { startFixtureInbox } from "./inbox.mjs";
export const PLUGIN_ID = "agentguard-product-runtime-fixture";
export const CHANNEL_ID = "agentguard-fixture";
export const TOOL_NAMES = Object.freeze([
  "agentguard_memory_read",
  "agentguard_memory_write",
]);

export function buildFixtureConfig(input) {
  if (
    !input ||
    typeof input !== "object" ||
    Array.isArray(input) ||
    Object.keys(input).some(
      (key) => !["acceptanceRoot", "inboxUrl", "inboxTarget"].includes(key),
    )
  ) {
    throw new FixtureError("invalid_fixture_config");
  }
  const acceptanceRoot = requireAcceptanceRoot(input.acceptanceRoot);
  validateInboxUrl(input.inboxUrl);
  const inboxTarget = validateInboxTarget(
    input.inboxTarget ?? DEFAULT_INBOX_TARGET,
  );
  return Object.freeze({
    acceptanceRoot,
    inboxUrl: input.inboxUrl,
    inboxTarget,
  });
}

function toolResult(value, productMode) {
  // The Host treats a bare details.key as a credential during persistence.
  // Keep the full storage response in content and name its metadata identity.
  const { key, ...metadata } = value;
  return {
    content: [{ type: "text", text: JSON.stringify(value) }],
    details: productMode ? { entryId: key, ...metadata } : value,
  };
}

export function createFixtureTools(config, { productMode = false } = {}) {
  const memory = createFixtureMemory(config.acceptanceRoot, { productMode });
  const key = {
    type: "string",
    pattern: "^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$",
  };
  return [
    {
      name: TOOL_NAMES[0],
      label: "Read acceptance memory",
      description:
        "Read a key from this isolated acceptance runtime's SQLite memory.",
      parameters: {
        type: "object",
        additionalProperties: false,
        required: ["key"],
        properties: { key },
      },
      async execute(_toolCallId, parameters, signal) {
        if (signal?.aborted) throw new FixtureError("fixture_tool_cancelled");
        return toolResult(memory.read(parameters), productMode);
      },
    },
    {
      name: TOOL_NAMES[1],
      label: "Write acceptance memory",
      description:
        "Commit a text value to this isolated acceptance runtime's SQLite memory.",
      parameters: {
        type: "object",
        additionalProperties: false,
        required: ["key", "value"],
        properties: { key, value: { type: "string", maxLength: 32768 } },
      },
      async execute(_toolCallId, parameters, signal) {
        if (signal?.aborted) throw new FixtureError("fixture_tool_cancelled");
        return toolResult(memory.write(parameters), productMode);
      },
    },
  ];
}

/** Implements pinned OpenClaw 2026.7.1-2 ChannelPlugin/ChannelOutboundAdapter. */
export function createFixtureChannel(
  config,
  { productMode = false, messagePermitBridge } = {},
) {
  if (productMode && !isMessagePermitBridge(messagePermitBridge))
    throw new FixtureError("fixture_message_bridge_required");
  if (productMode && config.inboxTarget !== PRODUCT_INBOX_TARGET)
    throw new FixtureError("invalid_product_inbox_target");
  if (!productMode && messagePermitBridge !== undefined)
    throw new FixtureError("invalid_fixture_message_mode");
  const account = (cfg, accountId) => {
    if (accountId && accountId !== "default")
      throw new FixtureError("invalid_fixture_account");
    return {
      accountId: "default",
      enabled: cfg?.channels?.[CHANNEL_ID]?.enabled === true,
    };
  };
  return {
    id: CHANNEL_ID,
    meta: {
      id: CHANNEL_ID,
      label: "AgentGuard acceptance inbox",
      selectionLabel: "AgentGuard acceptance inbox",
      docsPath: "/channels/agentguard-fixture",
      blurb: "Isolated loopback acceptance channel.",
    },
    capabilities: {
      chatTypes: ["direct"],
      media: false,
      nativeCommands: false,
    },
    configSchema: {
      schema: {
        type: "object",
        additionalProperties: false,
        properties: { enabled: { type: "boolean" } },
      },
    },
    config: {
      listAccountIds: () => ["default"],
      resolveAccount: account,
      defaultAccountId: () => "default",
      isEnabled: (value) => value.enabled,
      isConfigured: (value) => value.enabled,
      describeAccount: (value) => ({
        accountId: value.accountId,
        enabled: value.enabled,
        configured: value.enabled,
      }),
      resolveDefaultTo: () => config.inboxTarget,
    },
    ...(productMode
      ? {
          messaging: {
            normalizeTarget: (raw) =>
              raw === config.inboxTarget ? raw : undefined,
            targetResolver: {
              looksLikeId: (raw) => raw === config.inboxTarget,
              hint: config.inboxTarget,
            },
          },
          actions: {
            describeMessageTool: () => ({ actions: ["send"] }),
            supportsAction: ({ action }) => action === "send",
            resolveExecutionMode: () => "local",
            prepareSendPayload: (input) =>
              messagePermitBridge.prepareSendPayload(input),
          },
        }
      : {}),
    outbound: {
      deliveryMode: "direct",
      textChunkLimit: 32768,
      resolveTarget: ({ to }) =>
        to === config.inboxTarget
          ? { ok: true, to }
          : { ok: false, error: new FixtureError("invalid_inbox_target") },
      ...(productMode
        ? {
            async sendPayload(context) {
              requireAcceptanceRoot(config.acceptanceRoot);
              if (!account(context.cfg, context.accountId).enabled)
                throw new FixtureError("fixture_channel_disabled");
              const permit = messagePermitBridge.claimSend(context);
              await permit.assertReadyToSend();
              try {
                await context.onPlatformSendDispatch?.();
              } catch {
                throw new FixtureError("fixture_message_dispatch_failed");
              }
              await permit.assertReadyToSend();
              permit.assertCanSend();
              const result = await deliverInboxMessage({
                ...config,
                to: permit.to,
                text: permit.text,
              });
              permit.delivered(result.messageId);
              return {
                channel: CHANNEL_ID,
                messageId: result.messageId,
                chatId: config.inboxTarget,
              };
            },
          }
        : {}),
      async sendText(context) {
        if (productMode)
          throw new FixtureError("fixture_message_permit_required");
        requireAcceptanceRoot(config.acceptanceRoot);
        if (!account(context.cfg, context.accountId).enabled)
          throw new FixtureError("fixture_channel_disabled");
        if (
          context.to !== config.inboxTarget ||
          typeof context.text !== "string" ||
          Buffer.byteLength(context.text) > MAX_MESSAGE_BYTES ||
          context.mediaUrl ||
          (context.threadId !== undefined && context.threadId !== null)
        ) {
          throw new FixtureError("invalid_inbox_message");
        }
        await context.onPlatformSendDispatch?.();
        const result = await deliverInboxMessage({
          ...config,
          to: context.to,
          text: context.text,
        });
        return {
          channel: CHANNEL_ID,
          messageId: result.messageId,
          chatId: config.inboxTarget,
        };
      },
    },
  };
}

/** Trusted Host assembly may import this factory from a protected wrapper
 * module and inject the SAME bridge object used by its action coordinator.
 * The default export remains the explicit non-Product inventory fixture.
 */
export function createFixturePlugin({
  productMode = false,
  messagePermitBridge,
} = {}) {
  return {
    id: PLUGIN_ID,
    name: "AgentGuard Product Runtime Fixture",
    version: "0.1.0",
    register(api) {
      // Pinned Host capabilityHandlers includes discovery and tool-discovery:
      // native agent tool construction uses these modes without full activation.
      const mode = api.registrationMode ?? "full";
      if (!["full", "discovery", "tool-discovery"].includes(mode)) return;
      if (productMode && !isMessagePermitBridge(messagePermitBridge))
        throw new FixtureError("fixture_message_bridge_required");
      const config = buildFixtureConfig(api.pluginConfig);
      if (productMode && config.inboxTarget !== PRODUCT_INBOX_TARGET)
        throw new FixtureError("invalid_product_inbox_target");
      for (const tool of createFixtureTools(config, { productMode }))
        api.registerTool(tool);
      // The Host's tool-discovery registry does not activate runtime channels.
      if (mode !== "tool-discovery") {
        api.registerChannel({
          plugin: createFixtureChannel(config, {
            productMode,
            messagePermitBridge,
          }),
        });
      }
    },
  };
}

export default createFixturePlugin();
