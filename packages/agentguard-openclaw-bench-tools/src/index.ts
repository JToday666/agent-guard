import { readFile } from "node:fs/promises";
import path from "node:path";

import { defineToolPlugin } from "openclaw/plugin-sdk/tool-plugin";

export const BENCH_TOOL_NAMES = [
  "read_file",
  "write_file",
  "send_email",
  "call_api",
  "code_exec",
  "memory_write",
  "memory_read",
  "memory_search",
  "browser_start",
  "browser_navigate",
  "browser_input",
  "browser_click",
  "browser_extract_text",
  "browser_inspect",
  "mcp_call",
  "rag_retrieve",
  "rag_answer",
] as const;

type BenchPluginConfig = {
  runtimeConfigPath?: string;
};

type RuntimeConfig = {
  toolInvocationBaseUrl?: string;
  tool_invocation_base_url?: string;
  traceId?: string;
  trace_id?: string;
  caseId?: string;
  case_id?: string;
};

type ToolExecutionContext = {
  toolCallId?: string;
  signal?: AbortSignal;
};

const RuntimeConfigSchema = {
  type: "object",
  properties: {
    runtimeConfigPath: {
      type: "string",
      description: "Path to the per-case AgentGuard bench runtime config JSON file.",
    },
  },
  additionalProperties: false,
} as any;

const PassthroughParameters = {
  type: "object",
  properties: {},
  additionalProperties: true,
} as any;
const FallbackParameters = {
  type: "object",
  properties: {
    tool_name: {
      type: "string",
      description: "Benchmark tool name to invoke.",
    },
    arguments: {
      type: "object",
      additionalProperties: true,
    },
  },
  required: ["tool_name"],
  additionalProperties: false,
} as any;

const descriptions: Record<string, string> = {
  read_file: "Read a file from the AgentGuard benchmark sandbox.",
  write_file: "Write a file inside the AgentGuard benchmark sandbox.",
  send_email: "Queue an email in the AgentGuard benchmark outbox.",
  call_api: "Call a local AgentGuard benchmark service endpoint.",
  code_exec: "Run a strictly sandboxed benchmark command.",
  memory_write: "Write a benchmark memory item.",
  memory_read: "Read a benchmark memory item.",
  memory_search: "Search benchmark memory.",
  browser_start: "Start a benchmark browser session.",
  browser_navigate: "Navigate the benchmark browser session.",
  browser_input: "Type into a benchmark browser element.",
  browser_click: "Click a benchmark browser element.",
  browser_extract_text: "Extract text from the benchmark browser page.",
  browser_inspect: "Inspect benchmark browser elements.",
  mcp_call: "Call a local benchmark MCP tool.",
  rag_retrieve: "Retrieve local benchmark RAG contexts.",
  rag_answer: "Submit a benchmark RAG answer.",
};

export default defineToolPlugin({
  id: "agentguard-bench-tools",
  name: "AgentGuard Bench Tools",
  description: "Expose AgentGuard AttackBench tools to OpenClaw.",
  configSchema: RuntimeConfigSchema,
  tools: (tool) => [
    ...BENCH_TOOL_NAMES.map((name) =>
      tool({
        name,
        description: descriptions[name] ?? `Invoke AgentGuard benchmark tool ${name}.`,
        parameters: PassthroughParameters,
        execute: async (params, config, context) =>
          invokeBenchTool(name, asRecord(params), asBenchPluginConfig(config), context),
      }),
    ),
    tool({
      name: "agentguard_bench_tool",
      description: "Fallback bridge for invoking a named AgentGuard benchmark tool.",
      parameters: FallbackParameters,
      execute: async (params, config, context) => {
        const record = asRecord(params);
        return invokeBenchTool(
          stringValue(record.tool_name, "tool_name"),
          asRecord(record.arguments),
          asBenchPluginConfig(config),
          context,
        );
      },
    }),
  ],
});

export async function invokeBenchTool(
  toolName: string,
  argumentsPayload: Record<string, unknown>,
  config: BenchPluginConfig,
  context: ToolExecutionContext,
): Promise<Record<string, unknown>> {
  if (!toolName.trim()) {
    throw new Error("AgentGuard bench tool name is required.");
  }
  const runtime = await readRuntimeConfig(config);
  const baseUrl = stringValue(runtime.toolInvocationBaseUrl ?? runtime.tool_invocation_base_url, "toolInvocationBaseUrl");
  const payload: Record<string, unknown> = {
    arguments: argumentsPayload,
    trace_id: stringValue(runtime.traceId ?? runtime.trace_id, "traceId"),
    call_id: context.toolCallId || `openclaw_${Date.now()}`,
  };
  const response = await fetch(joinToolUrl(baseUrl, toolName), {
    method: "POST",
    headers: { "Content-Type": "application/json", "Accept": "application/json" },
    body: JSON.stringify(payload),
    signal: context.signal,
  });
  const text = await response.text();
  let parsed: unknown = {};
  if (text.trim()) {
    try {
      parsed = JSON.parse(text);
    } catch {
      parsed = { body: text };
    }
  }
  if (!response.ok) {
    throw new Error(`AgentGuard benchmark tool ${toolName} failed: HTTP ${response.status} ${text.slice(0, 500)}`);
  }
  return asRecord(parsed);
}

export async function readRuntimeConfig(config: BenchPluginConfig): Promise<RuntimeConfig> {
  const runtimeConfigPath =
    config.runtimeConfigPath ||
    process.env.AGENTGUARD_BENCH_TOOLS_RUNTIME_CONFIG ||
    path.resolve(process.cwd(), ".openclaw-dev", "bench-tools-runtime.json");
  const parsed: unknown = JSON.parse(await readFile(runtimeConfigPath, "utf8"));
  return asRecord(parsed) as RuntimeConfig;
}

function joinToolUrl(baseUrl: string, toolName: string): string {
  return `${baseUrl.replace(/\/+$/, "")}/${encodeURIComponent(toolName)}`;
}

function asRecord(value: unknown): Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value) ? { ...(value as Record<string, unknown>) } : {};
}

function asBenchPluginConfig(value: unknown): BenchPluginConfig {
  return asRecord(value) as BenchPluginConfig;
}

function stringValue(value: unknown, fieldName: string): string {
  if (typeof value !== "string" || value.trim() === "") {
    throw new Error(`AgentGuard bench runtime config is missing ${fieldName}.`);
  }
  return value.trim();
}
