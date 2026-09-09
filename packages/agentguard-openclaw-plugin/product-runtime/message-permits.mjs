/** Ephemeral, one-shot permits for the isolated pinned Host channel only.
 * Host correlation is best effort (C1); no C3 or invocation claim is made.
 */
import { createHash, randomBytes } from "node:crypto";
import { types } from "node:util";
import { FixtureError } from "./memory.mjs";
import { PRODUCT_INBOX_TARGET, MAX_MESSAGE_BYTES } from "./inbox.mjs";

const CHANNEL = "agentguard-fixture";
const PERMIT_KEY = "agentguard_fixture_permit";
const ID = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,255}$/u;
const BRIDGES = new WeakSet();
export const isMessagePermitBridge = (value) =>
  value !== null && typeof value === "object" && BRIDGES.has(value);

const ARGUMENT_KEYS = ["action", "channel", "target", "message"];

function fail() {
  throw new FixtureError("fixture_message_permit_invalid");
}
function record(value) {
  if (
    !value ||
    typeof value !== "object" ||
    types.isProxy(value) ||
    Array.isArray(value) ||
    ![Object.prototype, null].includes(Object.getPrototypeOf(value))
  )
    fail();
  const copy = {};
  for (const key of Reflect.ownKeys(value)) {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (typeof key !== "string" || !descriptor || !("value" in descriptor))
      fail();
    Object.defineProperty(copy, key, {
      value: descriptor.value,
      enumerable: true,
    });
  }
  return copy;
}
function exact(value, keys) {
  const copy = record(value);
  if (
    Object.keys(copy).length !== keys.length ||
    keys.some((key) => !Object.hasOwn(copy, key))
  )
    fail();
  return copy;
}
function identifier(value) {
  if (typeof value !== "string" || !ID.test(value)) fail();
  return value;
}
function noValue(value) {
  return value === undefined || value === null;
}
function boundedText(value) {
  if (
    typeof value !== "string" ||
    Buffer.byteLength(value) > MAX_MESSAGE_BYTES ||
    !value.trim()
  )
    fail();
  return value;
}
function sorted(value) {
  if (Array.isArray(value)) return value.map(sorted);
  if (!value || typeof value !== "object") return value;
  return Object.fromEntries(
    Object.keys(value)
      .sort()
      .map((key) => [key, sorted(value[key])]),
  );
}
function fingerprint(args) {
  return createHash("sha256")
    .update(JSON.stringify(sorted({ action: "send", params: args })))
    .digest("base64url")
    .slice(0, 24);
}
function assertCallback(callback) {
  try {
    if (callback() !== undefined) fail();
  } catch {
    fail();
  }
}

export function createMessagePermitBridge({
  sessionKey,
  inboxTarget = PRODUCT_INBOX_TARGET,
  accountId = "default",
}) {
  identifier(sessionKey);
  if (inboxTarget !== PRODUCT_INBOX_TARGET || accountId !== "default") fail();
  let closed = false;
  let pending;
  let busy = false;
  const used = new Set();
  const permits = new Map();
  function ready() {
    if (closed) fail();
  }

  const bridge = Object.freeze({
    authorize(released) {
      ready();
      if (busy || used.size >= 1024) fail();
      const value = exact(released, [
        "runId",
        "toolCallId",
        "sessionKey",
        "toolName",
        "argumentsJson",
        "actionId",
        "assertCanSend",
        "assertReadyToSend",
        "onMessageDelivered",
      ]);
      identifier(value.runId);
      identifier(value.toolCallId);
      identifier(value.actionId);
      if (
        value.sessionKey !== sessionKey ||
        value.toolName !== "message" ||
        typeof value.assertCanSend !== "function" ||
        typeof value.assertReadyToSend !== "function" ||
        typeof value.onMessageDelivered !== "function" ||
        typeof value.argumentsJson !== "string" ||
        Buffer.byteLength(value.argumentsJson) > MAX_MESSAGE_BYTES * 6 + 1024
      )
        fail();
      let argumentsValue;
      try {
        argumentsValue = JSON.parse(value.argumentsJson);
      } catch {
        fail();
      }
      const args = exact(argumentsValue, ARGUMENT_KEYS);
      if (
        args.action !== "send" ||
        args.channel !== CHANNEL ||
        args.target !== inboxTarget
      )
        fail();
      boundedText(args.message);
      // Require an actual canonical snapshot, refusing duplicate JSON keys.
      if (JSON.stringify(sorted(args)) !== value.argumentsJson) fail();
      const key = JSON.stringify([value.runId, value.toolCallId]);
      if (used.has(key)) fail();
      assertCallback(value.assertCanSend);
      used.add(key);
      busy = true;
      const prefix = `${value.runId}:message-tool:`;
      const suffix = `:${value.toolCallId}`;
      pending = Object.freeze({
        ...value,
        text: args.message,
        idempotencyKeys: Object.freeze([
          `${prefix}${fingerprint(args)}${suffix}`,
          `${prefix}${fingerprint({ ...args, accountId })}${suffix}`,
        ]),
      });
    },

    prepareSendPayload(input) {
      ready();
      const active = pending;
      pending = undefined;
      const value = record(input);
      const ctx = record(value.ctx);
      const params = record(ctx.params);
      if (
        !active ||
        ctx.channel !== CHANNEL ||
        ctx.action !== "send" ||
        ctx.sessionKey !== sessionKey ||
        ctx.dryRun === true ||
        (!noValue(ctx.accountId) && ctx.accountId !== accountId) ||
        value.to !== inboxTarget ||
        !noValue(value.replyToId) ||
        !noValue(value.threadId) ||
        !active.idempotencyKeys.includes(params.idempotencyKey)
      )
        fail();
      if (
        params.action !== "send" ||
        params.channel !== CHANNEL ||
        params.target !== inboxTarget ||
        params.message !== active.text ||
        (!noValue(params.to) && params.to !== inboxTarget) ||
        (!noValue(params.accountId) && params.accountId !== accountId)
      )
        fail();
      const meaningful = new Set([
        ...ARGUMENT_KEYS,
        "to",
        "accountId",
        "idempotencyKey",
        "__agentId",
        "__sessionKey",
      ]);
      const emptyOnly = new Set([
        "presentation",
        "interactive",
        "media",
        "mediaUrl",
        "mediaUrls",
        "asVoice",
        "audioAsVoice",
      ]);
      for (const [key, item] of Object.entries(params)) {
        if (meaningful.has(key)) continue;
        if (!emptyOnly.has(key) || item !== undefined) fail();
      }
      const payload = record(value.payload);
      if (
        payload.text !== active.text ||
        Object.keys(payload).some(
          (key) => key !== "text" && payload[key] !== undefined,
        )
      )
        fail();
      assertCallback(active.assertCanSend);
      const nonce = randomBytes(32).toString("base64url");
      permits.set(nonce, active);
      return { text: active.text, channelData: { [PERMIT_KEY]: nonce } };
    },

    claimSend(context) {
      ready();
      const value = record(context);
      const payload = record(value.payload);
      const data = exact(payload.channelData, [PERMIT_KEY]);
      const nonce = data[PERMIT_KEY];
      const active = typeof nonce === "string" ? permits.get(nonce) : undefined;
      if (!active) fail();
      // Burn before any validation callback or await. A rejected/uncertain send
      // never recovers permission from the Host's durable delivery replay.
      permits.delete(nonce);
      if (
        value.to !== inboxTarget ||
        value.text !== active.text ||
        payload.text !== active.text ||
        (!noValue(value.accountId) && value.accountId !== accountId) ||
        !noValue(value.mediaUrl) ||
        !noValue(value.threadId) ||
        !noValue(value.replyToId) ||
        value.audioAsVoice === true ||
        value.gifPlayback === true ||
        value.forceDocument === true ||
        Object.keys(payload).some(
          (key) =>
            !["text", "channelData"].includes(key) &&
            payload[key] !== undefined &&
            !(
              ["replyToTag", "audioAsVoice"].includes(key) &&
              payload[key] === false
            ),
        )
      )
        fail();
      let delivered = false;
      const assertCanSend = () => {
        ready();
        assertCallback(active.assertCanSend);
      };
      assertCanSend();
      return Object.freeze({
        text: active.text,
        to: inboxTarget,
        assertCanSend,
        async assertReadyToSend() {
          assertCanSend();
          try {
            if ((await active.assertReadyToSend()) !== undefined) fail();
          } catch {
            fail();
          }
          assertCanSend();
        },
        delivered(messageId) {
          if (
            delivered ||
            typeof messageId !== "string" ||
            !/^fixture:[A-Za-z0-9-]{1,128}$/u.test(messageId)
          )
            fail();
          delivered = true;
          try {
            if (active.onMessageDelivered(messageId) !== undefined) fail();
            busy = false;
          } catch {
            fail();
          }
        },
      });
    },
    close() {
      closed = true;
      pending = undefined;
      permits.clear();
    },
  });
  BRIDGES.add(bridge);
  return bridge;
}
