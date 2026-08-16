import { createHash } from "node:crypto";
import { readFile, realpath } from "node:fs/promises";
import { basename, resolve } from "node:path";
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { CallToolRequestSchema, ListToolsRequestSchema } from "@modelcontextprotocol/sdk/types.js";
import { imageDimensions, imageMime, isContained, type JsonObject } from "./image.js";

type ToolDescriptor = { name: string; description?: string; input_schema?: JsonObject };

const toolServerUrl = requiredEnv("AGENTGUARD_BENCH_TOOL_SERVER_URL").replace(/\/$/, "");
const caseId = requiredEnv("AGENTGUARD_BENCH_CASE_ID");
const traceId = requiredEnv("AGENTGUARD_BENCH_TRACE_ID");
const sandboxDir = await realpath(resolve(requiredEnv("AGENTGUARD_BENCH_SANDBOX_DIR")));
const maxImageBytes = Number(process.env.AGENTGUARD_BENCH_MAX_IMAGE_BYTES ?? 4 * 1024 * 1024);

const descriptors = await loadDescriptors();
const server = new Server(
  { name: "agentguard_bench", version: "0.1.0" },
  { capabilities: { tools: {} } },
);

server.setRequestHandler(ListToolsRequestSchema, async () => ({
  tools: descriptors.map((tool) => ({
    name: tool.name,
    description: tool.description,
    inputSchema: tool.input_schema ?? { type: "object", additionalProperties: true },
  })),
}));

server.setRequestHandler(CallToolRequestSchema, async (request) => {
  const name = request.params.name;
  if (!descriptors.some((tool) => tool.name === name)) {
    return { isError: true, content: [{ type: "text", text: `Unknown benchmark tool: ${name}` }] };
  }
  const callId = `claude_code_${Date.now()}_${Math.random().toString(36).slice(2, 10)}`;
  const response = await fetch(`${toolServerUrl}/tools/${encodeURIComponent(name)}`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      case_id: caseId,
      trace_id: traceId,
      call_id: callId,
      arguments: (request.params.arguments ?? {}) as JsonObject,
    }),
  });
  if (!response.ok) {
    return { isError: true, content: [{ type: "text", text: `Tool server HTTP ${response.status}` }] };
  }
  const payload = (await response.json()) as JsonObject;
  const imageDelivery = await collectImages(payload);
  await recordBridgeEvent(callId, imageDelivery);
  const visiblePayload = stripImageBinary(payload) as JsonObject;
  const imageSummary = imageDelivery.map(({ data: _data, ...summary }) => summary);
  const content: Array<Record<string, unknown>> = [
    { type: "text", text: JSON.stringify({ ...visiblePayload, image_delivery: imageSummary }, null, 2) },
  ];
  for (const image of imageDelivery) {
    if (image.delivered && typeof image.data === "string" && typeof image.mime_type === "string") {
      content.push({ type: "image", data: image.data, mimeType: image.mime_type });
    }
  }
  return { isError: payload.ok === false, content, structuredContent: { ...visiblePayload, image_delivery: imageSummary } };
});

await server.connect(new StdioServerTransport());

async function loadDescriptors(): Promise<ToolDescriptor[]> {
  const response = await fetch(`${toolServerUrl}/tools`);
  if (!response.ok) throw new Error(`Tool server descriptor HTTP ${response.status}`);
  const payload = (await response.json()) as { tools?: ToolDescriptor[] };
  // code_exec is an in-benchmark escape hatch for legacy adapters. It is not
  // exposed to Claude Code, whose baseline must remain browser/file-tool only.
  return (payload.tools ?? []).filter((tool) => typeof tool.name === "string" && tool.name !== "code_exec");
}

async function recordBridgeEvent(callId: string, images: JsonObject[]): Promise<void> {
  try {
    await fetch(`${toolServerUrl}/bridge-events`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        case_id: caseId,
        trace_id: traceId,
        call_id: callId,
        image_delivery: images.map(({ data: _data, ...summary }) => summary),
      }),
    });
  } catch {
    // The tool result remains usable if optional compact-report telemetry fails.
  }
}

async function collectImages(value: unknown): Promise<JsonObject[]> {
  const paths = new Set<string>();
  walkImagePaths(value, paths);
  const images: JsonObject[] = [];
  for (const rawPath of paths) {
    const candidate = resolve(rawPath);
    let safeCandidate: string;
    try {
      safeCandidate = await realpath(candidate);
    } catch {
      images.push({ path: rawPath, delivered: false, status: "image_missing" });
      continue;
    }
    if (!isContained(safeCandidate, sandboxDir)) {
      images.push({ path: rawPath, delivered: false, status: "path_outside_case_sandbox" });
      continue;
    }
    try {
      const bytes = await readFile(safeCandidate);
      const mimeType = imageMime(safeCandidate, bytes);
      if (!mimeType) {
        images.push({ path: rawPath, delivered: false, status: "unsupported_image_type" });
        continue;
      }
      if (bytes.byteLength > maxImageBytes) {
        images.push({ path: rawPath, delivered: false, status: "image_too_large", bytes: bytes.byteLength, mime_type: mimeType });
        continue;
      }
      const dimensions = imageDimensions(mimeType, bytes);
      images.push({
        path: rawPath,
        name: basename(safeCandidate),
        delivered: true,
        status: "delivered",
        mime_type: mimeType,
        bytes: bytes.byteLength,
        sha256: createHash("sha256").update(bytes).digest("hex"),
        ...dimensions,
        data: bytes.toString("base64"),
      });
    } catch (error) {
      images.push({ path: rawPath, delivered: false, status: "image_read_failed", error: error instanceof Error ? error.message : String(error) });
    }
  }
  return images;
}

function walkImagePaths(value: unknown, paths: Set<string>): void {
  if (!value || typeof value !== "object") return;
  if (Array.isArray(value)) {
    for (const item of value) walkImagePaths(item, paths);
    return;
  }
  for (const [key, child] of Object.entries(value as JsonObject)) {
    if (["screenshot", "step_screenshot", "image_path"].includes(key) && typeof child === "string") paths.add(child);
    walkImagePaths(child, paths);
  }
}

function stripImageBinary(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(stripImageBinary);
  if (!value || typeof value !== "object") return value;
  const result: JsonObject = {};
  for (const [key, child] of Object.entries(value as JsonObject)) {
    if (["screenshot", "step_screenshot", "image_path"].includes(key) && typeof child === "string") {
      result[key] = child;
    } else {
      result[key] = stripImageBinary(child);
    }
  }
  return result;
}

function requiredEnv(name: string): string {
  const value = process.env[name];
  if (!value) throw new Error(`Missing ${name}`);
  return value;
}
