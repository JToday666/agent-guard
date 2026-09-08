import { types } from "node:util";
import type { OpenClawPluginApi } from "openclaw/plugin-sdk/plugin-entry";
import {
  createAssistantMessageEventStream,
  type AssistantMessage,
  type Context,
  type Model,
} from "openclaw/plugin-sdk/llm";
import type {
  FrozenNativeModelInput,
  PreparedNativeModelInput,
  ProductNativeStreamHooks,
  OpaqueModelInvocationTicket,
} from "./product-content-types.js";
import { restrictedCanonicalJson } from "./canonical.js";

type ProviderPlugin = Parameters<OpenClawPluginApi["registerProvider"]>[0];
type WrapStream = NonNullable<ProviderPlugin["wrapStreamFn"]>;
type Stream = NonNullable<ReturnType<WrapStream>>;
type Fields = Record<string, unknown>;
const CONTENT_LIMIT = 64 * 1024;
const EVENT_LIMIT = 128 * 1024;
const ID = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,255}$/u;
const FAILURE = "product_native_stream_failed";

export type ProductNativeStreamBinding = Readonly<{
  provider: string;
  modelId: string;
  baseUrl: string;
  agentId: string;
  agentDir: string;
  workspaceDir: string;
  sessionId: string;
}>;

function fail(): never {
  throw new Error(FAILURE);
}
function fields(value: unknown): Fields {
  if (
    !value ||
    typeof value !== "object" ||
    Array.isArray(value) ||
    types.isProxy(value)
  )
    fail();
  const proto = Object.getPrototypeOf(value);
  if (proto !== Object.prototype && proto !== null) fail();
  if (Object.getOwnPropertySymbols(value).length) fail();
  const result: Fields = Object.create(null);
  for (const [key, descriptor] of Object.entries(
    Object.getOwnPropertyDescriptors(value),
  )) {
    if (!("value" in descriptor)) fail();
    result[key] = descriptor.value;
  }
  return result;
}
function arrayValues(value: unknown): unknown[] {
  if (
    !Array.isArray(value) ||
    types.isProxy(value) ||
    Object.getOwnPropertySymbols(value).length
  )
    fail();
  const descriptors = Object.getOwnPropertyDescriptors(value);
  if (
    value.length > 12000 ||
    Object.keys(descriptors).length !== value.length + 1
  )
    fail();
  const result: unknown[] = [];
  for (let i = 0; i < value.length; i++) {
    const field = descriptors[String(i)];
    if (!field || !("value" in field)) fail();
    result.push(field.value);
  }
  return result;
}
/** Native transport accounting can contain decimals; signed content remains restricted JSON. */
export function snapshotProductNativeData(
  value: unknown,
  limit = EVENT_LIMIT,
): unknown {
  if (!Number.isSafeInteger(limit) || limit < 1 || limit > EVENT_LIMIT) fail();
  let nodes = 0;
  const active = new Set<object>();
  const copy = (item: unknown, depth: number): unknown => {
    if (++nodes > 12000 || depth > 24) fail();
    if (item === null || typeof item === "boolean") return item;
    if (typeof item === "string") {
      if (Buffer.byteLength(item) > CONTENT_LIMIT) fail();
      restrictedCanonicalJson(item);
      return item;
    }
    if (typeof item === "number") {
      if (!Number.isFinite(item) || Object.is(item, -0)) fail();
      return item;
    }
    if (
      !item ||
      typeof item !== "object" ||
      types.isProxy(item) ||
      active.has(item)
    )
      fail();
    active.add(item);
    let result: unknown;
    if (Array.isArray(item)) {
      if (item.length > 12000 || Object.getOwnPropertySymbols(item).length)
        fail();
      const descriptors = Object.getOwnPropertyDescriptors(item);
      if (Object.keys(descriptors).length !== item.length + 1) fail();
      const array: unknown[] = [];
      for (let i = 0; i < item.length; i++) {
        const descriptor = descriptors[String(i)];
        if (!descriptor || !("value" in descriptor)) fail();
        array.push(copy(descriptor.value, depth + 1));
      }
      result = array;
    } else {
      const record: Fields = Object.create(null);
      for (const [key, child] of Object.entries(fields(item))) {
        restrictedCanonicalJson(key);
        // Optional native data properties set to undefined are not JSON content.
        if (child !== undefined) record[key] = copy(child, depth + 1);
      }
      result = record;
    }
    active.delete(item);
    return result;
  };
  const result = copy(value, 0);
  if (Buffer.byteLength(JSON.stringify(result)) > limit) fail();
  return result;
}
const snapshot = snapshotProductNativeData;

/** Verify a complete native raw argument transcript without discarding duplicate fields. */
export function verifyProductNativeToolArgumentText(
  raw: unknown,
  argumentsValue: unknown,
): void {
  try {
    if (typeof raw !== "string" || Buffer.byteLength(raw) > CONTENT_LIMIT)
      fail();
    restrictedCanonicalJson(raw);
    let offset = 0;
    let nodes = 0;
    const whitespace = () => {
      while (offset < raw.length && /[\u0020\t\r\n]/u.test(raw[offset]!))
        offset++;
    };
    const string = (): string => {
      if (raw[offset] !== '"') fail();
      const start = offset++;
      while (offset < raw.length) {
        const character = raw[offset++];
        if (character === '"')
          return JSON.parse(raw.slice(start, offset)) as string;
        if (character === "\\") offset++;
      }
      return fail();
    };
    const number = (token: string): number => {
      // JSON.parse rounds before the restricted canonical reader sees a value.
      // Check the decimal spelling exactly so a fractional or unsafe literal
      // cannot round into an otherwise admissible integer.
      const match = /^(-?)([0-9]+)(?:\.([0-9]+))?(?:[eE]([+-]?[0-9]+))?$/u.exec(
        token,
      );
      if (!match) return fail();
      const fraction = match[3] ?? "";
      let digits = (match[2]! + fraction).replace(/^0+/u, "");
      if (!digits) {
        if (match[1]) return fail();
        return 0;
      }
      const exponent = Number(match[4] ?? "0");
      if (!Number.isSafeInteger(exponent)) return fail();
      const shift = exponent - fraction.length;
      if (shift < 0) {
        const removed = -shift;
        if (
          removed >= digits.length ||
          !/^0+$/u.test(digits.slice(digits.length - removed))
        )
          return fail();
        digits = digits.slice(0, digits.length - removed);
      } else {
        if (digits.length + shift > 16) return fail();
        digits += "0".repeat(shift);
      }
      if (
        digits.length > 16 ||
        BigInt(digits) > BigInt(Number.MAX_SAFE_INTEGER)
      )
        return fail();
      return Number((match[1] ?? "") + digits);
    };
    const value = (depth: number): unknown => {
      if (++nodes > 12000 || depth > 24) fail();
      whitespace();
      if (raw[offset] === '"') return string();
      if (raw[offset] === "{") {
        offset++;
        whitespace();
        const result: Fields = Object.create(null);
        const keys = new Set<string>();
        if (raw[offset] === "}") {
          offset++;
          return result;
        }
        while (offset < raw.length) {
          whitespace();
          const key = string();
          if (keys.has(key)) fail();
          keys.add(key);
          whitespace();
          if (raw[offset++] !== ":") fail();
          result[key] = value(depth + 1);
          whitespace();
          const separator = raw[offset++];
          if (separator === "}") return result;
          if (separator !== ",") fail();
        }
        return fail();
      }
      if (raw[offset] === "[") {
        offset++;
        whitespace();
        const result: unknown[] = [];
        if (raw[offset] === "]") {
          offset++;
          return result;
        }
        while (offset < raw.length) {
          result.push(value(depth + 1));
          whitespace();
          const separator = raw[offset++];
          if (separator === "]") return result;
          if (separator !== ",") fail();
        }
        return fail();
      }
      const token =
        /^(?:true|false|null|-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?)/u.exec(
          raw.slice(offset),
        )?.[0];
      if (!token) fail();
      offset += token.length;
      return /^(?:true|false|null)$/u.test(token)
        ? (JSON.parse(token) as unknown)
        : number(token);
    };
    const parsed = value(0);
    whitespace();
    if (offset !== raw.length) fail();
    fields(parsed);
    const expected = snapshot(argumentsValue);
    fields(expected);
    if (
      restrictedCanonicalJson(snapshot(parsed)) !==
      restrictedCanonicalJson(expected)
    )
      fail();
  } catch {
    fail();
  }
}
function frozen<T>(value: T): T {
  if (value && typeof value === "object") {
    for (const child of Object.values(value)) frozen(child);
    Object.freeze(value);
  }
  return value;
}
function exact(
  record: Fields,
  allowed: readonly string[],
  required: readonly string[] = [],
): void {
  if (
    Object.keys(record).some((key) => !allowed.includes(key)) ||
    required.some((key) => record[key] === undefined)
  )
    fail();
}
function same(left: unknown, right: unknown): boolean {
  return restrictedCanonicalJson(left) === restrictedCanonicalJson(right);
}
function textBlocks(value: unknown): string {
  if (typeof value === "string") return value;
  if (!Array.isArray(value)) fail();
  return value
    .map((block) => {
      const item = fields(block);
      exact(item, ["type", "text"], ["type", "text"]);
      if (item.type !== "text" || typeof item.text !== "string") fail();
      return item.text;
    })
    .join("");
}

function nativeMessages(input: PreparedNativeModelInput): Fields[] {
  const result: Fields[] = [];
  if (input.systemPrompt)
    result.push({ role: "system", content: input.systemPrompt });
  for (const raw of input.messages) {
    const message = fields(raw);
    if (message.role === "user") {
      exact(
        message,
        ["role", "content", "timestamp", "runtimeContextCarrier"],
        ["content"],
      );
      result.push({ role: "user", content: textBlocks(message.content) });
    } else if (message.role === "toolResult") {
      exact(
        message,
        [
          "role",
          "toolCallId",
          "toolName",
          "content",
          "details",
          "isError",
          "timestamp",
        ],
        ["toolCallId", "toolName", "content"],
      );
      if (
        typeof message.toolCallId !== "string" ||
        typeof message.toolName !== "string"
      )
        fail();
      result.push({
        role: "tool",
        tool_call_id: message.toolCallId,
        name: message.toolName,
        content: textBlocks(message.content),
      });
    } else if (message.role === "assistant") {
      validateAssistant(message, input.provider, input.modelId);
      const blocks = message.content as Fields[];
      // Opaque thinking replay is unsupported: rejecting preserves the entire content boundary.
      if (blocks.some((block) => block.type === "thinking")) fail();
      const content = blocks
        .filter((block) => block.type === "text")
        .map((block) => block.text)
        .join("");
      const calls = blocks
        .filter((block) => block.type === "toolCall")
        .map((block) => ({
          id: block.id,
          type: "function",
          function: {
            name: block.name,
            arguments: JSON.stringify(block.arguments),
          },
        }));
      result.push({
        role: "assistant",
        content,
        ...(calls.length ? { tool_calls: calls } : {}),
      });
    } else fail();
  }
  return result;
}

/** Verify the actual, awaited OpenAI-compatible payload against the complete approved Context. */
export function verifyProductNativeWirePayload(
  input: PreparedNativeModelInput,
  payload: unknown,
): void {
  try {
    const wire = fields(snapshot(payload));
    exact(wire, [
      "model",
      "messages",
      "tools",
      "stream",
      "stream_options",
      "store",
      "max_tokens",
      "max_completion_tokens",
      "temperature",
      "top_p",
      "frequency_penalty",
      "presence_penalty",
      "seed",
      "tool_choice",
      "parallel_tool_calls",
      "enable_thinking",
      "chat_template_kwargs",
      "reasoning_effort",
      "prompt_cache_key",
      "prompt_cache_retention",
    ]);
    if (
      wire.model !== input.modelId ||
      wire.stream !== true ||
      !Array.isArray(wire.messages)
    )
      fail();
    const expected = nativeMessages(input);
    if (wire.messages.length !== expected.length) fail();
    for (let i = 0; i < expected.length; i++) {
      const actual = fields(wire.messages[i]);
      const wanted = expected[i]!;
      exact(actual, ["role", "content", "tool_call_id", "tool_calls", "name"]);
      if (actual.role === "developer" && wanted.role === "system")
        actual.role = "system";
      if (
        actual.content === null &&
        wanted.role === "assistant" &&
        wanted.content === ""
      )
        actual.content = "";
      if (Array.isArray(actual.content))
        actual.content = textBlocks(actual.content);
      if (wanted.role === "tool" && actual.name === undefined)
        delete wanted.name;
      if (!same(actual, wanted)) fail();
    }
    const tools = input.tools.map((raw) => {
      const tool = fields(raw);
      exact(
        tool,
        ["name", "description", "parameters"],
        ["name", "description", "parameters"],
      );
      if (typeof tool.name !== "string" || typeof tool.description !== "string")
        fail();
      return tool;
    });
    const actualTools = wire.tools ?? [];
    if (!Array.isArray(actualTools) || actualTools.length !== tools.length)
      fail();
    const byName = new Map(tools.map((tool) => [tool.name, tool]));
    if (byName.size !== tools.length) fail();
    const seen = new Set<string>();
    for (const raw of actualTools) {
      const tool = fields(raw);
      exact(tool, ["type", "function"], ["type", "function"]);
      const fn = fields(tool.function);
      exact(
        fn,
        ["name", "description", "parameters", "strict"],
        ["name", "description", "parameters"],
      );
      if (
        tool.type !== "function" ||
        typeof fn.name !== "string" ||
        seen.has(fn.name) ||
        (fn.strict !== undefined && fn.strict !== false)
      )
        fail();
      seen.add(fn.name);
      const wanted = byName.get(fn.name);
      if (
        !wanted ||
        fn.description !== wanted.description ||
        !same(fn.parameters, wanted.parameters)
      )
        fail();
    }
    if (
      wire.stream_options !== undefined &&
      !same(wire.stream_options, { include_usage: true })
    )
      fail();
    if (wire.store !== undefined && wire.store !== false) fail();
    if (
      wire.tool_choice !== undefined &&
      wire.tool_choice !== "auto" &&
      wire.tool_choice !== "none"
    )
      fail();
    if (
      wire.parallel_tool_calls !== undefined &&
      wire.parallel_tool_calls !== false
    )
      fail();
    if (
      wire.enable_thinking !== undefined &&
      typeof wire.enable_thinking !== "boolean"
    )
      fail();
    if (wire.chat_template_kwargs !== undefined) {
      const chat = fields(wire.chat_template_kwargs);
      exact(chat, ["enable_thinking"], ["enable_thinking"]);
      if (typeof chat.enable_thinking !== "boolean") fail();
    }
    for (const key of ["max_tokens", "max_completion_tokens"])
      if (
        wire[key] !== undefined &&
        (!Number.isSafeInteger(wire[key]) || (wire[key] as number) < 1)
      )
        fail();
    for (const key of [
      "temperature",
      "top_p",
      "frequency_penalty",
      "presence_penalty",
      "seed",
    ])
      if (wire[key] !== undefined && typeof wire[key] !== "number") fail();
    if (
      wire.reasoning_effort !== undefined &&
      !["none", "off", "minimal", "low", "medium", "high", "xhigh"].includes(
        wire.reasoning_effort as string,
      )
    )
      fail();
    for (const key of ["prompt_cache_key", "prompt_cache_retention"])
      if (wire[key] !== undefined && typeof wire[key] !== "string") fail();
  } catch {
    fail();
  }
}

function validateAssistant(
  value: unknown,
  provider: string,
  modelId: string,
): AssistantMessage {
  const message = fields(value);
  exact(
    message,
    [
      "role",
      "content",
      "api",
      "provider",
      "model",
      "responseModel",
      "responseId",
      "usage",
      "stopReason",
      "timestamp",
    ],
    [
      "role",
      "content",
      "api",
      "provider",
      "model",
      "usage",
      "stopReason",
      "timestamp",
    ],
  );
  if (
    message.role !== "assistant" ||
    message.api !== "openai-completions" ||
    message.provider !== provider ||
    message.model !== modelId ||
    !["stop", "toolUse", "length"].includes(message.stopReason as string) ||
    !Number.isSafeInteger(message.timestamp) ||
    !Array.isArray(message.content)
  )
    fail();
  let calls = 0;
  for (const raw of message.content) {
    const block = fields(raw);
    if (block.type === "text") {
      exact(block, ["type", "text"], ["text"]);
      if (typeof block.text !== "string") fail();
    } else if (block.type === "thinking") {
      exact(block, ["type", "thinking"], ["thinking"]);
      if (typeof block.thinking !== "string") fail();
    } else if (block.type === "toolCall") {
      exact(
        block,
        ["type", "id", "name", "arguments", "partialArgs"],
        ["id", "name", "arguments"],
      );
      if (
        ++calls > 1 ||
        typeof block.id !== "string" ||
        !ID.test(block.id) ||
        typeof block.name !== "string" ||
        !ID.test(block.name)
      )
        fail();
      fields(block.arguments);
      restrictedCanonicalJson(block.arguments);
      if (block.partialArgs !== undefined)
        verifyProductNativeToolArgumentText(block.partialArgs, block.arguments);
    } else fail();
  }
  if (calls > 0 !== (message.stopReason === "toolUse")) fail();
  if (
    Buffer.byteLength(restrictedCanonicalJson(message.content)) > CONTENT_LIMIT
  )
    fail();
  const usage = fields(message.usage);
  exact(
    usage,
    [
      "input",
      "output",
      "cacheRead",
      "cacheWrite",
      "totalTokens",
      "cost",
      "contextUsage",
    ],
    ["input", "output", "cacheRead", "cacheWrite", "totalTokens", "cost"],
  );
  for (const key of [
    "input",
    "output",
    "cacheRead",
    "cacheWrite",
    "totalTokens",
  ])
    if (!Number.isSafeInteger(usage[key]) || (usage[key] as number) < 0) fail();
  const cost = fields(usage.cost);
  exact(
    cost,
    ["input", "output", "cacheRead", "cacheWrite", "total", "totalOrigin"],
    ["input", "output", "cacheRead", "cacheWrite", "total"],
  );
  for (const key of ["input", "output", "cacheRead", "cacheWrite", "total"])
    if (typeof cost[key] !== "number" || (cost[key] as number) < 0) fail();
  if (cost.totalOrigin !== undefined && cost.totalOrigin !== "provider-billed")
    fail();
  if (usage.contextUsage !== undefined) {
    const ctx = fields(usage.contextUsage);
    exact(ctx, ["state", "promptTokens", "totalTokens"], ["state"]);
    if (ctx.state === "available") {
      for (const key of ["promptTokens", "totalTokens"])
        if (!Number.isSafeInteger(ctx[key]) || (ctx[key] as number) < 0) fail();
    } else if (ctx.state !== "unavailable" || Object.keys(ctx).length !== 1)
      fail();
  }
  for (const key of ["responseModel", "responseId"])
    if (message[key] !== undefined && typeof message[key] !== "string") fail();
  return value as AssistantMessage;
}

/** Private single-session composition. Public Product registration remains fused until B09. */
export class OpenClawProductNativeStream {
  #binding: ProductNativeStreamBinding;
  #hooks: ProductNativeStreamHooks;
  #abort = new AbortController();
  #busy = false;
  #failed = false;
  #closed = false;
  #calls = 0;
  #timeoutMs: number;
  #registeredBase?: Stream;
  constructor(options: {
    binding: ProductNativeStreamBinding;
    hooks: ProductNativeStreamHooks;
    timeoutMs?: number;
  }) {
    try {
      const binding = fields(snapshot(options.binding));
      exact(
        binding,
        [
          "provider",
          "modelId",
          "baseUrl",
          "agentId",
          "agentDir",
          "workspaceDir",
          "sessionId",
        ],
        [
          "provider",
          "modelId",
          "baseUrl",
          "agentId",
          "agentDir",
          "workspaceDir",
          "sessionId",
        ],
      );
      if (
        Object.values(binding).some(
          (value) => typeof value !== "string" || !value,
        )
      )
        fail();
      const url = new URL(binding.baseUrl as string);
      if (
        !["http:", "https:"].includes(url.protocol) ||
        url.username ||
        url.password ||
        url.search ||
        url.hash
      )
        fail();
      this.#binding = frozen(binding) as ProductNativeStreamBinding;
      const hooks = fields(options.hooks);
      for (const name of [
        "prepareInput",
        "verifyWirePayload",
        "beginModelCall",
        "finishModelCall",
        "block",
      ])
        if (typeof hooks[name] !== "function") fail();
      this.#hooks = Object.freeze({ ...hooks }) as ProductNativeStreamHooks;
      this.#timeoutMs = options.timeoutMs ?? 120000;
      if (
        !Number.isSafeInteger(this.#timeoutMs) ||
        this.#timeoutMs < 1 ||
        this.#timeoutMs > 120000
      )
        fail();
    } catch {
      fail();
    }
  }
  status(): Readonly<{
    closed: boolean;
    failed: boolean;
    busy: boolean;
    transportCalls: number;
  }> {
    return Object.freeze({
      closed: this.#closed,
      failed: this.#failed,
      busy: this.#busy,
      transportCalls: this.#calls,
    });
  }
  close(): void {
    this.#closed = true;
    this.#abort.abort();
  }
  #block(): void {
    this.#failed = true;
    this.#abort.abort();
    try {
      this.#hooks.block(FAILURE);
    } catch {
      /* Never echo callback errors. */
    }
  }
  #ready(signal?: AbortSignal): void {
    if (this.#closed || this.#failed || signal?.aborted) fail();
  }
  #model(value: unknown): Model {
    const model = fields(value);
    if (
      model.api !== "openai-completions" ||
      model.provider !== this.#binding.provider ||
      model.id !== this.#binding.modelId ||
      model.baseUrl !== this.#binding.baseUrl
    )
      fail();
    return frozen(snapshot(value)) as Model;
  }
  readonly wrapStreamFn: WrapStream = (context) => {
    try {
      this.#ready();
      const ctx = fields(context);
      for (const key of [
        "provider",
        "modelId",
        "agentId",
        "agentDir",
        "workspaceDir",
      ] as const)
        if (ctx[key] !== this.#binding[key]) fail();
      this.#model(ctx.model);
      if (typeof ctx.streamFn !== "function") fail();
      const base = ctx.streamFn as Stream;
      // Host may rebuild the same session transport; each wrapper still shares this breaker.
      this.#registeredBase = base;
      return (model, input, options) => this.#run(base, model, input, options);
    } catch {
      this.#block();
      return fail();
    }
  };
  async #run(
    base: Stream,
    model: Model,
    context: Context,
    options: Parameters<Stream>[2],
  ): Promise<Awaited<ReturnType<Stream>>> {
    let ticket: OpaqueModelInvocationTicket | undefined;
    let finished = false;
    let invoked = false;
    const callAbort = new AbortController();
    const timer = setTimeout(() => callAbort.abort(), this.#timeoutMs);
    let signal = AbortSignal.any([this.#abort.signal, callAbort.signal]);
    try {
      const originalOptions = options === undefined ? {} : fields(options);
      if (originalOptions.headers !== undefined) {
        originalOptions.headers = frozen(snapshot(originalOptions.headers));
      }
      const supplied = originalOptions.signal;
      if (supplied !== undefined) {
        if (types.isProxy(supplied) || !(supplied instanceof AbortSignal))
          fail();
        signal = AbortSignal.any([signal, supplied]);
      }
      this.#ready(signal);
      if (this.#busy || this.#registeredBase !== base) fail();
      this.#busy = true;
      const approvedModel = this.#model(model);
      const ctx = fields(context);
      exact(ctx, ["systemPrompt", "messages", "tools"], ["messages"]);
      if (
        ctx.systemPrompt !== undefined &&
        typeof ctx.systemPrompt !== "string"
      )
        fail();
      if (
        !Array.isArray(ctx.messages) ||
        (ctx.tools !== undefined && !Array.isArray(ctx.tools))
      )
        fail();
      const projectedTools = arrayValues(ctx.tools ?? []).map((raw) => {
        const tool = fields(raw);
        // AgentTool.execute/label are Host runtime members, never provider tool descriptors.
        return {
          name: tool.name,
          description: tool.description,
          parameters: tool.parameters,
        };
      });
      const input = frozen(
        snapshot({
          provider: this.#binding.provider,
          modelId: this.#binding.modelId,
          systemPrompt: ctx.systemPrompt ?? "",
          messages: ctx.messages,
          tools: projectedTools,
        }),
      ) as FrozenNativeModelInput;
      const prepared = await abortable(
        this.#hooks.prepareInput(input, signal),
        signal,
      );
      this.#ready(signal);
      // Validate the coordinator's complete approved shape before entering the transport.
      const actual = fields(snapshot(prepared));
      exact(
        actual,
        ["provider", "modelId", "systemPrompt", "messages", "tools"],
        ["provider", "modelId", "systemPrompt", "messages", "tools"],
      );
      if (
        actual.provider !== input.provider ||
        actual.modelId !== input.modelId ||
        typeof actual.systemPrompt !== "string" ||
        !Array.isArray(actual.messages) ||
        !Array.isArray(actual.tools) ||
        !same(actual.tools, input.tools)
      )
        fail();
      const transportContext = {
        systemPrompt: actual.systemPrompt,
        messages: actual.messages,
        tools: actual.tools,
      } as Context;
      if (
        originalOptions.sessionId !== undefined &&
        originalOptions.sessionId !== this.#binding.sessionId
      )
        fail();
      const originalPayload = originalOptions.onPayload;
      if (
        originalPayload !== undefined &&
        typeof originalPayload !== "function"
      )
        fail();
      let payloadSeen = false;
      const guardedOptions = {
        ...originalOptions,
        signal,
        onPayload: async (raw: unknown, payloadModel: Model) => {
          this.#ready(signal);
          if (payloadSeen) fail();
          payloadSeen = true;
          this.#model(payloadModel);
          let payload = snapshot(raw);
          if (typeof originalPayload === "function") {
            const changed = await abortable(
              Promise.resolve(originalPayload(payload, payloadModel)),
              signal,
            );
            if (changed !== undefined) payload = snapshot(changed);
          }
          // Neither upstream callbacks nor the async ticket issuer may mutate
          // the exact body whose full content is checked and sent.
          const approvedPayload = frozen(snapshot(payload));
          this.#ready(signal);
          verifyProductNativeWirePayload(prepared, approvedPayload);
          this.#hooks.verifyWirePayload(prepared, approvedPayload);
          ticket = await abortable(
            this.#hooks.beginModelCall(prepared, signal),
            signal,
          );
          this.#ready(signal);
          return approvedPayload;
        },
      } as Parameters<Stream>[2];
      this.#calls++;
      invoked = true;
      const inner = await abortable(
        Promise.resolve(base(approvedModel, transportContext, guardedOptions)),
        signal,
      );
      const iterator = inner[Symbol.asyncIterator]();
      let terminal: AssistantMessage | undefined;
      let events = 0;
      try {
        while (true) {
          const item = await abortable(iterator.next(), signal);
          this.#ready(signal);
          if (item.done) break;
          if (++events > 16384 || terminal) fail();
          const event = fields(item.value);
          if (event.type === "error") fail();
          if (event.type === "done") {
            terminal = validateAssistant(
              snapshot(event.message),
              this.#binding.provider,
              this.#binding.modelId,
            );
            if (event.reason !== terminal.stopReason) fail();
          } else {
            if (
              ![
                "start",
                "text_start",
                "text_delta",
                "text_end",
                "thinking_start",
                "thinking_delta",
                "thinking_end",
                "toolcall_start",
                "toolcall_delta",
                "toolcall_end",
              ].includes(event.type as string)
            )
              fail();
            // Partial native arguments may contain partialArgs; bound them without publishing them.
            snapshot(event);
          }
        }
      } finally {
        if (signal.aborted) void iterator.return?.().catch(() => undefined);
      }
      if (!payloadSeen || !ticket || !terminal) fail();
      const result = validateAssistant(
        snapshot(await abortable(inner.result(), signal)),
        this.#binding.provider,
        this.#binding.modelId,
      );
      if (JSON.stringify(result) !== JSON.stringify(terminal)) fail();
      this.#ready(signal);
      finished = true;
      const approved = await abortable(
        this.#hooks.finishModelCall(
          ticket,
          { status: "completed", message: frozen(result) },
          signal,
        ),
        signal,
      );
      this.#ready(signal);
      const output = fields(approved);
      exact(output, ["message"], ["message"]);
      const safeMessage = validateAssistant(
        snapshot(output.message),
        this.#binding.provider,
        this.#binding.modelId,
      );
      // Approval is for this exact full output; sanitization requires a separately evaluated output.
      if (JSON.stringify(safeMessage) !== JSON.stringify(result)) fail();
      const stream = createAssistantMessageEventStream();
      stream.push({
        type: "done",
        reason: safeMessage.stopReason as "stop" | "length" | "toolUse",
        message: safeMessage,
      });
      stream.end(safeMessage);
      return stream;
    } catch {
      this.#block();
      if (ticket && invoked && !finished) {
        // A transport was entered; never claim not_invoked after an uncertain return.
        try {
          const cleanup = AbortSignal.timeout(1000);
          await abortable(
            this.#hooks.finishModelCall(ticket, { status: "failed" }, cleanup),
            cleanup,
          );
        } catch {
          /* Durable coordinator owns recovery. */
        }
      }
      return fail();
    } finally {
      clearTimeout(timer);
      this.#busy = false;
    }
  }
}

async function abortable<T>(
  promise: Promise<T>,
  signal: AbortSignal,
): Promise<T> {
  if (signal.aborted) {
    // The argument was evaluated before this check. Observe its rejection even
    // when a synchronous callback closed the stream before returning it.
    void promise.catch(() => undefined);
    fail();
  }
  return await new Promise<T>((resolve, reject) => {
    const aborted = () => reject(new Error(FAILURE));
    signal.addEventListener("abort", aborted, { once: true });
    promise
      .then(resolve, () => reject(new Error(FAILURE)))
      .finally(() => signal.removeEventListener("abort", aborted));
  });
}
