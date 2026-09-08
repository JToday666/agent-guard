import { restrictedCanonicalJson, restrictedDigest } from "./canonical.js";

export const OPENCLAW_PRODUCT_RUNTIME_VERSION = "2026.7.1-2";
export const OPENCLAW_PRODUCT_MEMORY_PLUGIN_ID =
  "agentguard-product-runtime-fixture";
export const OPENCLAW_PRODUCT_CORE_SOURCE_ID = "openclaw-core";
export const OPENCLAW_PRODUCT_TOOL_IDS = Object.freeze([
  "agentguard_memory_read",
  "agentguard_memory_write",
  "edit",
  "exec",
  "message",
  "process",
  "read",
  "write",
] as const);

export type OpenClawProductToolId = (typeof OPENCLAW_PRODUCT_TOOL_IDS)[number];
export type OpenClawProductToolDescriptor = {
  name: string;
  /** JSON projection of the actual runtime descriptor's parameters. */
  parameters: unknown;
  /** Independently resolved Host owner, never inferred from a tool name. */
  sourcePluginId: string;
};
export type OpenClawFrozenProductTool = Readonly<{
  tool_id: OpenClawProductToolId;
  source_plugin_id: string;
  input_schema_digest: string;
  event_type:
    "tool_call_proposed" | "memory_write_proposed" | "message_send_proposed";
  fixture_id: string;
}>;
export type OpenClawProductInventory = Readonly<{
  tools: readonly OpenClawFrozenProductTool[];
  /** Source-plugin catalog order, not the complete modifying-hook order. */
  pluginOrder: readonly string[];
  inputSchemas: Readonly<Record<string, unknown>>;
  digests: Readonly<{
    schema_version: "1.0";
    host_inventory_digest: string;
    plugin_inventory_digest: string;
    plugin_order_inventory_digest: string;
    tool_inventory_digest: string;
  }>;
}>;
export type ProductInventoryFailure =
  | "invalid_descriptor"
  | "invalid_schema"
  | "unexpected_tool"
  | "duplicate_tool"
  | "missing_tool"
  | "owner_mismatch"
  | "invalid_plugin_order"
  | "unsupported_runtime"
  | "sdk_unavailable"
  | "sdk_collection_failed"
  | "normalization_drift";

/** Body-free failures must not retain schema descriptions or Host exceptions. */
export class ProductInventoryError extends Error {
  readonly failure: ProductInventoryFailure;
  constructor(failure: ProductInventoryFailure) {
    super(`Product inventory rejected: ${failure}`);
    this.name = "ProductInventoryError";
    this.failure = failure;
  }
}

type InventoryInput = {
  tools: readonly OpenClawProductToolDescriptor[];
  pluginOrder: readonly string[];
  memoryToolPluginId?: string;
};

/** Freeze exactly the eight tools of the isolated acceptance profile. */
export function buildOpenClawProductInventory(
  input: InventoryInput,
): OpenClawProductInventory {
  try {
    if (
      input.memoryToolPluginId !== undefined &&
      input.memoryToolPluginId !== OPENCLAW_PRODUCT_MEMORY_PLUGIN_ID
    ) {
      fail("owner_mismatch");
    }
    if (!Array.isArray(input.tools)) fail("invalid_descriptor");
    const descriptors = new Map<string, OpenClawProductToolDescriptor>();
    for (const descriptor of input.tools) {
      const name = ownField(descriptor, "name");
      if (typeof name !== "string") fail("invalid_descriptor");
      if (!(OPENCLAW_PRODUCT_TOOL_IDS as readonly string[]).includes(name)) {
        fail("unexpected_tool");
      }
      if (descriptors.has(name)) fail("duplicate_tool");
      const owner = ownField(descriptor, "sourcePluginId");
      const expectedOwner = name.startsWith("agentguard_memory_")
        ? OPENCLAW_PRODUCT_MEMORY_PLUGIN_ID
        : OPENCLAW_PRODUCT_CORE_SOURCE_ID;
      if (owner !== expectedOwner) fail("owner_mismatch");
      descriptors.set(name, {
        name,
        sourcePluginId: expectedOwner,
        parameters: ownField(descriptor, "parameters"),
      });
    }
    if (descriptors.size !== OPENCLAW_PRODUCT_TOOL_IDS.length) {
      fail("missing_tool");
    }
    const schemas: Record<string, unknown> = Object.create(null);
    const tools = OPENCLAW_PRODUCT_TOOL_IDS.map((toolId) => {
      const descriptor = descriptors.get(toolId)!;
      let schema: unknown;
      let digest: string;
      try {
        schema = snapshotSchema(descriptor.parameters);
        if (
          schema === null ||
          typeof schema !== "object" ||
          Array.isArray(schema)
        ) {
          fail("invalid_schema");
        }
        digest = restrictedDigest(schema);
      } catch {
        fail("invalid_schema");
      }
      schemas[toolId] = schema;
      return Object.freeze({
        tool_id: toolId,
        source_plugin_id: descriptor.sourcePluginId,
        input_schema_digest: digest,
        // This explicit profile mapping is not the legacy memory-name heuristic.
        event_type:
          toolId === "agentguard_memory_write"
            ? ("memory_write_proposed" as const)
            : toolId === "message"
              ? ("message_send_proposed" as const)
              : ("tool_call_proposed" as const),
        fixture_id: `openclaw:${toolId}:restricted-v1`,
      });
    });
    const pluginIds = [
      ...new Set(tools.map((tool) => tool.source_plugin_id)),
    ].sort();
    const order = input.pluginOrder;
    if (
      !Array.isArray(order) ||
      order.length !== pluginIds.length ||
      new Set(order).size !== order.length ||
      order.some((id) => typeof id !== "string" || !pluginIds.includes(id))
    ) {
      fail("invalid_plugin_order");
    }
    const hostDigest = restrictedDigest({
      schema_version: "1.0",
      runtime: "openclaw",
      tools: tools.map(({ tool_id, source_plugin_id }) => ({
        tool_id,
        source_plugin_id,
      })),
    });
    return Object.freeze({
      tools: Object.freeze(tools),
      pluginOrder: Object.freeze([...order]),
      inputSchemas: Object.freeze(schemas),
      digests: Object.freeze({
        schema_version: "1.0" as const,
        host_inventory_digest: hostDigest,
        plugin_inventory_digest: restrictedDigest({
          schema_version: "1.0",
          runtime: "openclaw",
          plugin_ids: pluginIds,
        }),
        plugin_order_inventory_digest: restrictedDigest({
          schema_version: "1.0",
          runtime: "openclaw",
          plugin_order: order,
        }),
        tool_inventory_digest: restrictedDigest({
          schema_version: "1.0",
          runtime: "openclaw",
          host_inventory_digest: hostDigest,
          tools,
        }),
      }),
    });
  } catch (error) {
    if (error instanceof ProductInventoryError) throw error;
    return fail("invalid_descriptor");
  }
}

type HostSdk = typeof import("openclaw/plugin-sdk/agent-harness");
export type OpenClawProductInventorySdk = Pick<
  HostSdk,
  | "createOpenClawCodingTools"
  | "getPluginToolMeta"
  | "normalizeAgentRuntimeTools"
  | "inspectRuntimeToolInputSchemas"
  | "projectRuntimeToolInputSchema"
>;
export type CollectOpenClawProductInventoryInput = {
  /** Must come from the loaded Host, not an expected-version configuration. */
  runtimeVersion: string;
  sdk?: OpenClawProductInventorySdk;
  toolOptions: NonNullable<Parameters<HostSdk["createOpenClawCodingTools"]>[0]>;
  normalizationOptions?: Omit<
    Parameters<HostSdk["normalizeAgentRuntimeTools"]>[0],
    "tools"
  >;
  pluginOrder: readonly string[];
  memoryToolPluginId?: string;
};

/**
 * Instantiate descriptors through the pinned public SDK, without executing any
 * tool. The caller owns isolated Host loading/configuration and independently
 * captures plugin order. This is an inventory prerequisite, not activation.
 */
export async function collectOpenClawProductInventory(
  input: CollectOpenClawProductInventoryInput,
): Promise<OpenClawProductInventory> {
  if (input.runtimeVersion !== OPENCLAW_PRODUCT_RUNTIME_VERSION) {
    fail("unsupported_runtime");
  }
  let sdk: OpenClawProductInventorySdk;
  try {
    sdk = input.sdk ?? (await import("openclaw/plugin-sdk/agent-harness"));
  } catch {
    return fail("sdk_unavailable");
  }
  try {
    const raw = sdk.createOpenClawCodingTools(input.toolOptions);
    if (!Array.isArray(raw)) fail("invalid_descriptor");
    if (sdk.inspectRuntimeToolInputSchemas(raw).length > 0)
      fail("invalid_schema");
    const project = (tools: typeof raw): OpenClawProductToolDescriptor[] =>
      tools.map((tool) => {
        const name = ownField(tool, "name");
        const parameters = ownField(tool, "parameters");
        if (typeof name !== "string") fail("invalid_descriptor");
        const projection = sdk.projectRuntimeToolInputSchema(
          parameters,
          "tool.parameters",
        );
        if (
          projection.violations.length > 0 ||
          projection.schema === undefined
        ) {
          fail("invalid_schema");
        }
        const meta = sdk.getPluginToolMeta(tool);
        return {
          name,
          parameters: projection.schema,
          sourcePluginId:
            meta === undefined
              ? OPENCLAW_PRODUCT_CORE_SOURCE_ID
              : meta.pluginId,
        };
      });
    const before = buildOpenClawProductInventory({
      ...input,
      tools: project(raw),
    });
    const normalized = sdk.normalizeAgentRuntimeTools({
      provider: input.toolOptions.modelProvider ?? "",
      config: input.toolOptions.config,
      workspaceDir: input.toolOptions.workspaceDir,
      modelId: input.toolOptions.modelId,
      modelApi: input.toolOptions.modelApi,
      ...input.normalizationOptions,
      tools: raw,
    });
    if (sdk.inspectRuntimeToolInputSchemas(normalized).length > 0)
      fail("invalid_schema");
    const after = buildOpenClawProductInventory({
      ...input,
      tools: project(normalized),
    });
    // Provider normalization may change schemas but must not drop or reassign a tool.
    if (
      before.digests.host_inventory_digest !==
      after.digests.host_inventory_digest
    ) {
      fail("normalization_drift");
    }
    return after;
  } catch (error) {
    if (error instanceof ProductInventoryError) throw error;
    return fail("sdk_collection_failed");
  }
}

function fail(failure: ProductInventoryFailure): never {
  throw new ProductInventoryError(failure);
}

function ownField(value: unknown, name: string): unknown {
  if (value === null || typeof value !== "object") fail("invalid_descriptor");
  const field = Object.getOwnPropertyDescriptor(value, name);
  if (!field || !("value" in field)) fail("invalid_descriptor");
  return field.value;
}

/** Snapshot JSON data without invoking getters, toJSON, or prototype methods. */
function snapshotSchema(value: unknown): unknown {
  const active = new Set<object>();
  let nodes = 0;
  const copy = (item: unknown, depth: number): unknown => {
    if (++nodes > 100_000 || depth > 128) fail("invalid_schema");
    if (item === null || typeof item !== "object") {
      restrictedCanonicalJson(item);
      return item;
    }
    if (active.has(item)) fail("invalid_schema");
    const prototype = Object.getPrototypeOf(item);
    if (
      !Array.isArray(item) &&
      prototype !== Object.prototype &&
      prototype !== null
    ) {
      fail("invalid_schema");
    }
    if (Object.getOwnPropertySymbols(item).length > 0) fail("invalid_schema");
    active.add(item);
    const result: Record<string, unknown> | unknown[] = Array.isArray(item)
      ? []
      : Object.create(null);
    const keys = Object.getOwnPropertyNames(item);
    if (Array.isArray(item)) {
      if (keys.length !== item.length + 1) fail("invalid_schema");
      for (let index = 0; index < item.length; index += 1) {
        (result as unknown[]).push(
          copy(ownField(item, String(index)), depth + 1),
        );
      }
    } else {
      for (const key of keys) {
        const descriptor = Object.getOwnPropertyDescriptor(item, key)!;
        if (!descriptor.enumerable || !("value" in descriptor))
          fail("invalid_schema");
        restrictedCanonicalJson(key);
        (result as Record<string, unknown>)[key] = copy(
          descriptor.value,
          depth + 1,
        );
      }
    }
    active.delete(item);
    return Object.freeze(result);
  };
  return copy(value, 0);
}
