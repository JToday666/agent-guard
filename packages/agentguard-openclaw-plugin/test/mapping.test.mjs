import assert from "node:assert/strict";
import test from "node:test";

import {
  buildMessageSendGuardEvent,
  buildToolCallGuardEvent,
} from "../dist/mapping.js";

test("maps before_tool_call into an OpenClaw GuardEvent", () => {
  const event = buildToolCallGuardEvent(
    {
      toolName: "read_file",
      params: { path: "/private/token.txt" },
      toolKind: "code_mode_exec",
      toolInputKind: "typescript",
      toolCallId: "call_001",
      runId: "run_001",
      derivedPaths: ["/private/token.txt"],
    },
    {
      agentId: "agent-main",
      sessionId: "sess_001",
      sessionKey: "session-key",
      channelId: "cli",
    },
  );

  assert.equal(event.schema_version, "0.3");
  assert.equal(event.event_type, "tool_call_proposed");
  assert.equal(event.runtime, "openclaw");
  assert.equal(event.pre_execution, true);
  assert.equal(event.trace_id, "run_001");
  assert.equal(event.payload.tool.name, "read_file");
  assert.equal(event.payload.tool.call_id, "call_001");
  assert.equal(event.payload.tool.kind, "code_mode_exec");
  assert.deepEqual(event.payload.arguments, { path: "/private/token.txt" });
  assert.deepEqual(event.security_context.derived_paths, ["/private/token.txt"]);
  assert.equal(event.security_context.session_id, "sess_001");
  assert.equal(event.security_context.metadata.session_key, "session-key");
});

test("maps message_sending into an OpenClaw GuardEvent without relying on runId", () => {
  const event = buildMessageSendGuardEvent(
    {
      to: "user@example.com",
      content: "Send summary to user@example.com",
      threadId: "thread-1",
      metadata: { source: "reply" },
    },
    {
      channelId: "email",
      sessionKey: "session-key",
      messageId: "msg_001",
      senderId: "agent",
    },
  );

  assert.equal(event.schema_version, "0.3");
  assert.equal(event.event_type, "message_send_proposed");
  assert.equal(event.runtime, "openclaw");
  assert.equal(event.trace_id, "session-key");
  assert.equal(event.payload.channel, "email");
  assert.equal(event.payload.recipient, "user@example.com");
  assert.equal(event.payload.content_preview, "Send summary to user@example.com");
  assert.equal(event.security_context.sender_id, "agent");
  assert.equal(event.security_context.metadata.message_id, "msg_001");
});
