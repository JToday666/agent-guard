// Deterministic transport-boundary tests. Hook approvals below are synthetic;
// the final localhost case uses the real public pinned SDK transport, not an agent loop.
import assert from "node:assert/strict";
import { createServer } from "node:http";
import { inspect } from "node:util";
import test from "node:test";
import {
  createAssistantMessageEventStream,
  streamSimple,
} from "openclaw/plugin-sdk/llm";
import {
  OpenClawProductNativeStream,
  verifyProductNativeWirePayload,
  verifyProductNativeToolArgumentText,
} from "../dist/runtime/product-native-stream.js";

const binding = {
  provider: "agentguard-acceptance",
  modelId: "inventory-probe",
  baseUrl: "http://127.0.0.1:1/v1",
  agentId: "main",
  agentDir: "/isolated/agent",
  workspaceDir: "/isolated/workspace",
  sessionId: "session:content",
};
const descriptor = {
  name: "read",
  description: "Read the isolated fixture",
  parameters: {
    type: "object",
    properties: { path: { type: "string" } },
    required: ["path"],
    additionalProperties: false,
  },
};
const model = (b = binding) => ({
  api: "openai-completions",
  provider: b.provider,
  id: b.modelId,
  name: b.modelId,
  baseUrl: b.baseUrl,
  reasoning: false,
  input: ["text"],
  cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0 },
  contextWindow: 32768,
  maxTokens: 256,
});
const context = () => ({
  systemPrompt: "Bound host instructions",
  messages: [{ role: "user", content: "Read fixture.txt", timestamp: 1 }],
  tools: [structuredClone(descriptor)],
});
const prepared = () => ({
  provider: binding.provider,
  modelId: binding.modelId,
  ...context(),
});
const message = (
  content = [{ type: "text", text: "The fixture is ready." }],
  b = binding,
) => ({
  role: "assistant",
  api: "openai-completions",
  provider: b.provider,
  model: b.modelId,
  content,
  stopReason: content.some((x) => x.type === "toolCall") ? "toolUse" : "stop",
  timestamp: 2,
  usage: {
    input: 10,
    output: 4,
    cacheRead: 0,
    cacheWrite: 0,
    totalTokens: 14,
    cost: {
      input: 0.0001,
      output: 0,
      cacheRead: 0,
      cacheWrite: 0,
      total: 0.0001,
    },
  },
});
const wire = (ctx = context(), m = model()) => ({
  model: m.id,
  stream: true,
  messages: [
    ...(ctx.systemPrompt
      ? [{ role: "system", content: ctx.systemPrompt }]
      : []),
    ...ctx.messages.map((v) => ({ role: v.role, content: v.content })),
  ],
  tools: ctx.tools.map((t) => ({
    type: "function",
    function: { ...t, parameters: t.parameters },
  })),
});
function latch() {
  let resolve;
  const promise = new Promise((done) => {
    resolve = done;
  });
  return { promise, resolve };
}

test("complete native raw arguments allow whitespace and equivalent JSON spelling", () => {
  verifyProductNativeToolArgumentText(
    String.raw` { "flags": [true, null], "pa\u0074h": "fixture.txt", "count": 1e0 } `,
    { path: "fixture.txt", count: 1, flags: [true, null] },
  );
  verifyProductNativeToolArgumentText(
    '{"max":9007199254740991.0,"min":-9007199254740991,"n":0.0100e2,"zero":0e999}',
    {
      max: Number.MAX_SAFE_INTEGER,
      min: -Number.MAX_SAFE_INTEGER,
      n: 1,
      zero: 0,
    },
  );
});

for (const [name, raw, args] of [
  ["different value", '{"path":"other.txt"}', { path: "fixture.txt" }],
  [
    "duplicate key",
    '{"path":"unchecked","path":"fixture.txt"}',
    { path: "fixture.txt" },
  ],
  [
    "escaped duplicate key",
    String.raw`{"path":"unchecked","pa\u0074h":"fixture.txt"}`,
    { path: "fixture.txt" },
  ],
  ["nested duplicate key", '{"nested":{"x":1,"x":2}}', { nested: { x: 2 } }],
  ["truncated object", '{"path":"fixture.txt"', { path: "fixture.txt" }],
  ["trailing text", '{"path":"fixture.txt"}unchecked', { path: "fixture.txt" }],
  ["trailing comma", '{"path":"fixture.txt",}', { path: "fixture.txt" }],
  ["partial number", '{"n":1.}', { n: 1 }],
  ["nonfinite number", '{"n":1e999}', { n: 1 }],
  ["rounded fraction", '{"n":1.00000000000000001}', { n: 1 }],
  [
    "rounded large fraction",
    '{"n":9007199254740990.5}',
    { n: 9007199254740990 },
  ],
  ["underflow to zero", '{"n":1e-999}', { n: 0 }],
  ["unsafe integer", '{"n":9007199254740992}', { n: 9007199254740992 }],
  ["fraction", '{"n":1.5}', { n: 1.5 }],
  ["negative decimal zero", '{"n":-0.00e999}', { n: 0 }],
  ["negative zero", '{"n":-0}', { n: 0 }],
  ["lone surrogate", String.raw`{"x":"\ud800"}`, { x: "invalid" }],
  ["overlong text", '{"x":"' + "x".repeat(65536) + '"}', { x: "small" }],
])
  test(`native raw argument text rejects ${name}`, () => {
    assert.throws(
      () => verifyProductNativeToolArgumentText(raw, args),
      /^Error: product_native_stream_failed$/,
    );
  });

test("validated native partialArgs stays in the full approved output", async () => {
  const raw = ' { "path" : "fixture.txt" } ';
  const output = message([
    {
      type: "toolCall",
      id: "native-read-1",
      name: "read",
      arguments: { path: "fixture.txt" },
      partialArgs: raw,
    },
  ]);
  let inspected;
  const f = fixture({
    async finishModelCall(_ticket, outcome) {
      inspected = outcome.message;
      return { message: outcome.message };
    },
  });
  const actual = await consume(
    await f.wrap(baseStream({ output }))(model(), context(), {}),
  );
  assert.equal(inspected.content[0].partialArgs, raw);
  assert.equal(actual.result.content[0].partialArgs, raw);
  assert.deepEqual(
    { ...actual.result.content[0].arguments },
    { path: "fixture.txt" },
  );
});
function fixture(overrides = {}, b = binding) {
  const seen = { prepared: 0, wire: 0, begin: 0, finish: [], blocked: 0 };
  const hooks = {
    async prepareInput(value) {
      seen.prepared++;
      return value;
    },
    verifyWirePayload(value, body) {
      seen.wire++;
      verifyProductNativeWirePayload(value, body);
    },
    async beginModelCall() {
      seen.begin++;
      return Object.freeze({ testTicket: true });
    },
    async finishModelCall(_ticket, outcome) {
      seen.finish.push(outcome.status);
      return { message: outcome.message };
    },
    block() {
      seen.blocked++;
    },
    ...overrides,
  };
  const wrapper = new OpenClawProductNativeStream({
    binding: b,
    hooks,
    timeoutMs: 2000,
  });
  const wrap = (base) =>
    wrapper.wrapStreamFn({ ...b, model: model(b), streamFn: base });
  return { wrapper, hooks, seen, wrap };
}
function baseStream({
  output = message(),
  mutatePayload,
  beforeDone,
  diverge = false,
} = {}) {
  return async (m, ctx, options) => {
    const payload = wire(ctx, m);
    mutatePayload?.(payload);
    await options.onPayload(payload, m);
    const stream = createAssistantMessageEventStream();
    stream.push({ type: "start", partial: { ...output, content: [] } });
    stream.push({
      type: "text_delta",
      contentIndex: 0,
      delta: "The",
      partial: output,
    });
    void (async () => {
      await beforeDone?.();
      stream.push({ type: "done", reason: output.stopReason, message: output });
      stream.end(output);
    })();
    return diverge
      ? {
          [Symbol.asyncIterator]: () => stream[Symbol.asyncIterator](),
          result: async () => message([{ type: "text", text: "different" }]),
        }
      : stream;
  };
}
async function consume(stream) {
  const events = [];
  for await (const event of stream) events.push(event);
  return { events, result: await stream.result() };
}

test("complete approved model content is held until required receipts finish", async () => {
  const done = latch(),
    entered = latch();
  const f = fixture({
    async finishModelCall(_ticket, outcome) {
      entered.resolve();
      await done.promise;
      return { message: outcome.message };
    },
  });
  let published = false;
  const pending = f
    .wrap(baseStream())(model(), context(), {})
    .then((stream) => {
      published = true;
      return consume(stream);
    });
  await entered.promise;
  assert.equal(published, false);
  assert.equal(f.seen.begin, 1);
  done.resolve();
  const actual = await pending;
  assert.deepEqual(
    actual.events.map((e) => e.type),
    ["done"],
  );
  assert.equal(actual.result.content[0].text, "The fixture is ready.");
  assert.equal(f.wrapper.status().transportCalls, 1);
});

test("input refusal calls no original transport and permanently blocks retries", async () => {
  let calls = 0;
  const f = fixture({
    async prepareInput() {
      throw new Error("private-input");
    },
  });
  const wrapped = f.wrap(() => {
    calls++;
    throw new Error("not reached");
  });
  for (let i = 0; i < 2; i++)
    await assert.rejects(
      wrapped(model(), context(), {}),
      /^Error: product_native_stream_failed$/,
    );
  assert.equal(calls, 0);
  assert.equal(f.seen.blocked, 2);
});

test("final onPayload replacement is checked before model ticket release", async () => {
  const f = fixture();
  const original = async (payload) => {
    payload.messages[1].content = "unchecked";
    return payload;
  };
  await assert.rejects(
    f.wrap(baseStream())(model(), context(), { onPayload: original }),
    /product_native_stream_failed/,
  );
  assert.equal(f.seen.begin, 0);
  assert.deepEqual(f.seen.finish, []);
});

test("same transport/auth/model options and a detached approved payload reach the base", async () => {
  const f = fixture();
  let captured, originalPayload;
  const base = async (m, ctx, options) => {
    captured = { m, options };
    assert.equal(Object.isFrozen(m), true);
    assert.equal(Object.isFrozen(m.cost), true);
    const result = await options.onPayload(wire(ctx, m), m);
    assert.equal(Object.isFrozen(result), true);
    originalPayload.messages[1].content = "late mutation";
    assert.equal(result.messages[1].content, "Read fixture.txt");
    const s = createAssistantMessageEventStream();
    const output = message();
    s.push({ type: "done", reason: "stop", message: output });
    s.end(output);
    return s;
  };
  await consume(
    await f.wrap(base)(model(), context(), {
      apiKey: "private-local-key",
      temperature: 0.3,
      headers: { "x-local": "same" },
      onPayload(payload, transportModel) {
        originalPayload = payload;
        assert.throws(() => {
          transportModel.baseUrl = "http://127.0.0.1:2/v1";
        }, TypeError);
      },
    }),
  );
  assert.equal(captured.options.apiKey, "private-local-key");
  assert.equal(captured.options.temperature, 0.3);
  assert.equal(captured.m.baseUrl, binding.baseUrl);
  assert.equal(inspect(f.wrapper).includes("private-local-key"), false);
});

test("payload retained by upstream cannot change while ticket issuance awaits", async () => {
  const entered = latch(),
    release = latch();
  let retained, delivered;
  const f = fixture({
    async beginModelCall() {
      entered.resolve();
      await release.promise;
      return Object.freeze({ testTicket: true });
    },
  });
  const base = async (m, ctx, options) => {
    delivered = await options.onPayload(wire(ctx, m), m);
    const stream = createAssistantMessageEventStream();
    const output = message();
    stream.push({ type: "done", reason: "stop", message: output });
    stream.end(output);
    return stream;
  };
  const pending = f.wrap(base)(model(), context(), {
    onPayload(payload) {
      retained = payload;
    },
  });
  await entered.promise;
  retained.messages[1].content = "private-unchecked-body";
  retained.tools[0].function.parameters.properties.path.type = "integer";
  release.resolve();
  await consume(await pending);
  assert.equal(delivered.messages[1].content, "Read fixture.txt");
  assert.equal(
    delivered.tools[0].function.parameters.properties.path.type,
    "string",
  );
  assert.equal(Object.isFrozen(delivered.messages[1]), true);
});

test("synchronous close observes the already-created rejected hook promise", async () => {
  const rejections = [];
  const rejected = (value) => rejections.push(value);
  process.on("unhandledRejection", rejected);
  try {
    const f = fixture({
      prepareInput() {
        f.wrapper.close();
        return Promise.reject(new Error("private-cancelled-hook-marker"));
      },
    });
    await assert.rejects(
      f.wrap(baseStream())(model(), context(), {}),
      /^Error: product_native_stream_failed$/,
    );
    await new Promise((resolve) => setImmediate(resolve));
    assert.deepEqual(rejections, []);
    assert.equal(f.wrapper.status().transportCalls, 0);
  } finally {
    process.removeListener("unhandledRejection", rejected);
  }
});

for (const [name, mutate] of [
  [
    "changed body",
    (w) => {
      w.messages[1].content = "different";
    },
  ],
  [
    "extra message",
    (w) => {
      w.messages.push({ role: "user", content: "extra" });
    },
  ],
  [
    "unknown content field",
    (w) => {
      w.messages[1].secret = "hidden";
    },
  ],
  [
    "extra response format prompt",
    (w) => {
      w.response_format = {
        type: "json_schema",
        schema: { description: "hidden" },
      };
    },
  ],
  [
    "different model",
    (w) => {
      w.model = "other";
    },
  ],
  [
    "extra tool",
    (w) => {
      w.tools.push(structuredClone(w.tools[0]));
    },
  ],
  [
    "changed schema",
    (w) => {
      w.tools[0].function.parameters.properties.path.type = "number";
    },
  ],
  [
    "changed tool description",
    (w) => {
      w.tools[0].function.description = "hidden prompt";
    },
  ],
  [
    "parallel calls",
    (w) => {
      w.parallel_tool_calls = true;
    },
  ],
])
  test(`wire parity rejects ${name}`, () => {
    const body = wire();
    mutate(body);
    assert.throws(
      () => verifyProductNativeWirePayload(prepared(), body),
      /^Error: product_native_stream_failed$/,
    );
  });

test("full tool-call history uses exact serialized arguments and correlation", () => {
  const p = prepared();
  const a = message([
    {
      type: "toolCall",
      id: "call:one",
      name: "read",
      arguments: { path: "fixture.txt" },
    },
  ]);
  p.messages.push(a, {
    role: "toolResult",
    toolCallId: "call:one",
    toolName: "read",
    content: [{ type: "text", text: "safe data" }],
    timestamp: 3,
    isError: false,
  });
  const w = wire();
  w.messages.push(
    {
      role: "assistant",
      content: null,
      tool_calls: [
        {
          id: "call:one",
          type: "function",
          function: { name: "read", arguments: '{"path":"fixture.txt"}' },
        },
      ],
    },
    { role: "tool", tool_call_id: "call:one", content: "safe data" },
  );
  verifyProductNativeWirePayload(p, w);
  w.messages[2].tool_calls[0].function.arguments =
    '{"path":"hidden","path":"fixture.txt"}';
  assert.throws(
    () => verifyProductNativeWirePayload(p, w),
    /product_native_stream_failed/,
  );
});

for (const [name, output] of [
  ["opaque output property", { ...message(), errorBody: "secret" }],
  ["unknown content block", message([{ type: "image", data: "hidden" }])],
  [
    "oversized full content",
    message([{ type: "text", text: "X".repeat(65537) }]),
  ],
  [
    "multiple tool calls",
    message(
      [1, 2].map((id) => ({
        type: "toolCall",
        id: `call:${id}`,
        name: "read",
        arguments: { path: "fixture.txt" },
      })),
    ),
  ],
])
  test(`buffer rejects ${name} without publishing`, async () => {
    const f = fixture();
    await assert.rejects(
      f.wrap(baseStream({ output }))(model(), context(), {}),
      /product_native_stream_failed/,
    );
    assert.deepEqual(f.seen.finish, ["failed"]);
    assert.equal(f.wrapper.status().failed, true);
  });

test("thinking is fully buffered and delivered to the coordinator", async () => {
  let observed;
  const f = fixture({
    async finishModelCall(_ticket, outcome) {
      observed = outcome.message;
      return { message: observed };
    },
  });
  const output = message([
    { type: "thinking", thinking: "full private reasoning" },
    { type: "text", text: "safe" },
  ]);
  await consume(await f.wrap(baseStream({ output }))(model(), context(), {}));
  assert.equal(observed.content[0].thinking, "full private reasoning");
});

test("iterator terminal and result must agree", async () => {
  const f = fixture();
  await assert.rejects(
    f.wrap(baseStream({ diverge: true }))(model(), context(), {}),
    /product_native_stream_failed/,
  );
  assert.deepEqual(f.seen.finish, ["failed"]);
});

test("output receipt failure cannot reclassify a returned model as a second failed invocation", async () => {
  const statuses = [];
  const f = fixture({
    async finishModelCall(_ticket, outcome) {
      statuses.push(outcome.status);
      throw new Error("private-receipt-token");
    },
  });
  await assert.rejects(
    f.wrap(baseStream())(model(), context(), {}),
    /^Error: product_native_stream_failed$/,
  );
  assert.deepEqual(statuses, ["completed"]);
});

test("close during an awaited receipt suppresses late approved output", async () => {
  const entered = latch(),
    release = latch();
  const f = fixture({
    async finishModelCall(_ticket, outcome) {
      entered.resolve();
      await release.promise;
      return { message: outcome.message };
    },
  });
  const pending = f.wrap(baseStream())(model(), context(), {});
  await entered.promise;
  f.wrapper.close();
  release.resolve();
  await assert.rejects(pending, /product_native_stream_failed/);
});

test("accessors and proxy bodies are rejected without invoking user code", async () => {
  let reads = 0;
  const f = fixture();
  const input = context();
  Object.defineProperty(input, "messages", {
    get() {
      reads++;
      return [];
    },
  });
  await assert.rejects(
    f.wrap(baseStream())(model(), input, {}),
    /product_native_stream_failed/,
  );
  assert.equal(reads, 0);
  assert.throws(
    () =>
      verifyProductNativeWirePayload(
        prepared(),
        new Proxy(
          {},
          {
            ownKeys() {
              reads++;
              return [];
            },
          },
        ),
      ),
    /product_native_stream_failed/,
  );
  assert.equal(reads, 0);
});

test("signal getters and tool-array proxies run no user code", async () => {
  let reads = 0;
  const f = fixture();
  const options = Object.defineProperty({}, "signal", {
    get() {
      reads++;
      throw new Error("private");
    },
  });
  await assert.rejects(
    f.wrap(baseStream())(model(), context(), options),
    /^Error: product_native_stream_failed$/,
  );
  const g = fixture(),
    input = context();
  input.tools = new Proxy(input.tools, {
    get() {
      reads++;
      throw new Error("private");
    },
  });
  await assert.rejects(
    g.wrap(baseStream())(model(), input, {}),
    /^Error: product_native_stream_failed$/,
  );
  assert.equal(reads, 0);
});

test("missing original transport or wrong Provider registration is sticky", () => {
  const f = fixture();
  assert.throws(
    () => f.wrapper.wrapStreamFn({ ...binding, model: model() }),
    /product_native_stream_failed/,
  );
  assert.equal(f.wrapper.status().failed, true);
  const g = fixture();
  assert.throws(
    () =>
      g.wrapper.wrapStreamFn({
        ...binding,
        provider: "other",
        model: model(),
        streamFn: baseStream(),
      }),
    /product_native_stream_failed/,
  );
});

test("actual pinned public SDK sends the exact approved body to a controlled localhost transport", async () => {
  const requests = [];
  const server = createServer(async (req, res) => {
    const chunks = [];
    for await (const chunk of req) chunks.push(chunk);
    requests.push({
      path: req.url,
      body: JSON.parse(Buffer.concat(chunks).toString()),
    });
    res.writeHead(200, { "Content-Type": "text/event-stream" });
    res.write(
      'data: {"id":"local-controlled","choices":[{"index":0,"delta":{"role":"assistant","content":"Actual local transport."},"finish_reason":null}]}\n\n',
    );
    res.write(
      'data: {"id":"local-controlled","choices":[{"index":0,"delta":{},"finish_reason":"stop"}],"usage":{"prompt_tokens":8,"completion_tokens":4,"total_tokens":12}}\n\n',
    );
    res.end("data: [DONE]\n\n");
  });
  await new Promise((resolve, reject) =>
    server.listen(0, "127.0.0.1", resolve).once("error", reject),
  );
  try {
    const b = {
      ...binding,
      baseUrl: `http://127.0.0.1:${server.address().port}/v1`,
    };
    const f = fixture({}, b);
    const actual = await consume(
      await f.wrap(streamSimple)(model(b), context(), {
        apiKey: "local-controlled-only",
      }),
    );
    assert.equal(requests.length, 1);
    assert.equal(requests[0].path, "/v1/chat/completions");
    verifyProductNativeWirePayload(prepared(), requests[0].body);
    assert.equal(actual.result.content[0].text, "Actual local transport.");
    assert.deepEqual(
      actual.events.map((e) => e.type),
      ["done"],
    );
    assert.equal(f.seen.begin, 1);
    assert.deepEqual(f.seen.finish, ["completed"]);
  } finally {
    server.closeAllConnections();
    await new Promise((resolve) => server.close(resolve));
  }
});
