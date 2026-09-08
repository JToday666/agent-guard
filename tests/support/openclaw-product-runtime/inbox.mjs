/** A bounded, loopback-only HTTP inbox with SQLite readback evidence. */
import { randomUUID } from "node:crypto";
import { createServer, request } from "node:http";
import {
  FixtureError,
  requireAcceptanceRoot,
  withFixtureDatabase,
} from "./memory.mjs";

export const DEFAULT_INBOX_TARGET = "fixture-inbox";
export const MAX_MESSAGE_BYTES = 32768;

export function validateInboxTarget(target) {
  if (typeof target !== "string" || !/^[a-z][a-z0-9-]{0,63}$/u.test(target)) {
    throw new FixtureError("invalid_inbox_target");
  }
  return target;
}

export function validateInboxUrl(value) {
  try {
    if (
      typeof value !== "string" ||
      !/^http:\/\/(127\.0\.0\.1|\[::1\]):[1-9][0-9]*\/inbox$/u.test(value)
    ) {
      throw new Error();
    }
    const parsed = new URL(value);
    if (parsed.href !== value || !parsed.port) throw new Error();
    return parsed;
  } catch {
    throw new FixtureError("invalid_loopback_inbox_url");
  }
}

function validateMessage(value, target) {
  if (
    !value ||
    typeof value !== "object" ||
    Array.isArray(value) ||
    Object.keys(value).length !== 2 ||
    value.target !== target ||
    typeof value.text !== "string" ||
    Buffer.byteLength(value.text) > MAX_MESSAGE_BYTES
  ) {
    throw new FixtureError("invalid_inbox_message");
  }
}

function inboxDatabase(root, callback) {
  return withFixtureDatabase(root, "inbox.sqlite", (db) => {
    db.exec(
      "CREATE TABLE IF NOT EXISTS messages (sequence INTEGER PRIMARY KEY, message_id TEXT UNIQUE NOT NULL, target TEXT NOT NULL, text TEXT NOT NULL)",
    );
    return callback(db);
  });
}

export async function startFixtureInbox({
  acceptanceRoot,
  target = DEFAULT_INBOX_TARGET,
  port = 0,
}) {
  const root = requireAcceptanceRoot(acceptanceRoot);
  validateInboxTarget(target);
  if (!Number.isInteger(port) || port < 0 || port > 65535)
    throw new FixtureError("invalid_inbox_port");
  const server = createServer(async (req, res) => {
    const reply = (status, value) => {
      res.writeHead(status, {
        "Content-Type": "application/json",
        "Cache-Control": "no-store",
      });
      res.end(JSON.stringify(value));
    };
    if (
      req.method !== "POST" ||
      req.url !== "/inbox" ||
      req.headers["content-type"] !== "application/json"
    ) {
      reply(400, { error: "invalid_inbox_request" });
      req.resume();
      return;
    }
    try {
      const chunks = [];
      let size = 0;
      for await (const chunk of req) {
        size += chunk.length;
        // JSON escaping can enlarge a bounded text message by up to six times.
        if (size > MAX_MESSAGE_BYTES * 6 + 256)
          throw new FixtureError("inbox_request_too_large");
        chunks.push(chunk);
      }
      const message = JSON.parse(Buffer.concat(chunks).toString("utf8"));
      validateMessage(message, target);
      const messageId = `fixture:${randomUUID()}`;
      inboxDatabase(root, (db) => {
        if (
          db.prepare("SELECT count(*) AS count FROM messages").get().count >=
          1024
        ) {
          throw new FixtureError("inbox_capacity_exceeded");
        }
        db.prepare(
          "INSERT INTO messages(message_id,target,text) VALUES (?,?,?)",
        ).run(messageId, target, message.text);
      });
      reply(201, { messageId });
    } catch (error) {
      reply(
        error instanceof FixtureError && error.code === "storage_unavailable"
          ? 503
          : 400,
        { error: "inbox_message_rejected" },
      );
    }
  });
  server.requestTimeout = 3000;
  server.headersTimeout = 3000;
  server.setTimeout(3000, (socket) => socket.destroy());
  await new Promise((resolve, reject) => {
    server.once("error", () => reject(new FixtureError("inbox_listen_failed")));
    server.listen(port, "127.0.0.1", resolve);
  });
  return Object.freeze({
    url: `http://127.0.0.1:${server.address().port}/inbox`,
    target,
    readMessages() {
      return inboxDatabase(root, (db) =>
        db
          .prepare(
            "SELECT message_id AS messageId,target,text FROM messages ORDER BY sequence",
          )
          .all()
          .map((row) => ({ ...row })),
      );
    },
    close() {
      server.closeAllConnections();
      return new Promise((resolve, reject) =>
        server.close((error) => (error ? reject(error) : resolve())),
      );
    },
  });
}

export async function deliverInboxMessage({
  inboxUrl,
  inboxTarget = DEFAULT_INBOX_TARGET,
  to,
  text,
}) {
  const url = validateInboxUrl(inboxUrl);
  validateInboxTarget(inboxTarget);
  validateMessage({ target: to, text }, inboxTarget);
  const payload = JSON.stringify({ target: to, text });
  // node:http makes the literal loopback connection without proxy/DNS or redirects.
  return new Promise((resolve, reject) => {
    const fail = () => reject(new FixtureError("inbox_delivery_failed"));
    const req = request(
      {
        hostname: url.hostname.replace(/^\[|\]$/gu, ""),
        port: url.port,
        path: "/inbox",
        method: "POST",
        agent: false,
        headers: {
          "Content-Type": "application/json",
          "Content-Length": Buffer.byteLength(payload),
        },
      },
      (res) => {
        const chunks = [];
        let size = 0;
        res.on("data", (chunk) => {
          size += chunk.length;
          if (size > 4096) req.destroy();
          else chunks.push(chunk);
        });
        res.on("error", fail);
        res.on("end", () => {
          clearTimeout(timer);
          try {
            const body = JSON.parse(Buffer.concat(chunks).toString("utf8"));
            if (
              res.statusCode !== 201 ||
              typeof body.messageId !== "string" ||
              !/^fixture:[0-9a-f-]{36}$/u.test(body.messageId)
            )
              throw new Error();
            resolve({ messageId: body.messageId });
          } catch {
            fail();
          }
        });
      },
    );
    const timer = setTimeout(() => req.destroy(), 3000);
    req.on("error", () => {
      clearTimeout(timer);
      fail();
    });
    req.end(payload);
  });
}
