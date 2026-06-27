import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

import {
  buildMessageSendGuardEvent,
  buildToolCallGuardEvent,
} from "../dist/mapping.js";

const runtimeSamples = JSON.parse(
  readFileSync(new URL("./fixtures/runtime-mapping-samples.json", import.meta.url), "utf8"),
);

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

test("maps runtime task trust source fields with event precedence over context", () => {
  const sample = runtimeSamples.tool_call_event_fields_win;
  const event = buildToolCallGuardEvent(sample.event, sample.context);

  assert.equal(event.security_context.user_task, sample.event.userTask);
  assert.equal(event.security_context.source_trust, "untrusted");
  assert.equal(event.security_context.source_type, "retrieved_context");
  assert.deepEqual(event.security_context.derived_paths, ["/private/token.txt"]);
  assert.deepEqual(event.payload.derived_resources, sample.event.derivedResources);
});

test("falls back to context task trust source fields for message_sending", () => {
  const sample = runtimeSamples.message_context_fields_and_send_resource;
  const event = buildMessageSendGuardEvent(sample.event, sample.context);

  assert.equal(event.security_context.user_task, sample.context.userTask);
  assert.equal(event.security_context.source_trust, "trusted");
  assert.equal(event.security_context.source_type, "user");
  assert.deepEqual(event.payload.derived_resources, [
    {
      resource_type: "message",
      operation: "send",
      target: "reviewer@example.com",
      data_classification: null,
      direction: "outbound",
    },
  ]);
});

test("infers resource operation from real runtime tool shape when derivedResources are absent", () => {
  const api = runtimeSamples.api_post_fallback_operation;
  const memory = runtimeSamples.memory_write_fallback_operation;

  assert.deepEqual(buildToolCallGuardEvent(api.event, api.context).payload.derived_resources, [
    {
      resource_type: "api",
      operation: "POST",
      target: "https://api.example.test/collect",
      data_classification: null,
      direction: "outbound",
    },
  ]);
  assert.deepEqual(buildToolCallGuardEvent(memory.event, memory.context).payload.derived_resources, [
    {
      resource_type: "memory",
      operation: "write",
      target: "memory://profile/trusted_vendor",
      data_classification: null,
      direction: "local",
    },
  ]);
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
